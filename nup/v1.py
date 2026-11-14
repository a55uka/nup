"""NUP v1 (1.0, meow branch SPEC.md) reader, for conversion to v2.

v1 is its own container: a superblock, a TOC (packages, directory tree,
string pool) and a blob region of per-file extents, raw or one whole-file
zstd frame each.  Only what the 1.0 spec defines is read: reserved fields
and superblock flags must be zero, as it says.  A v1 file from elsewhere is
untrusted like any container (SPEC §6.4): every count, offset and name is
checked before it is used, the tree walk refuses cycles, and file data is
checked against its SHA-256 as it is read.
"""

from dataclasses import dataclass, field
import hashlib
import os
import struct

from .errors import NupError, VerificationError
from .layout import TLV_HEADER as TLV_HEAD   # v2 kept v1's TLV framing (SPEC §3)

MAGIC = b"NUP\x01"
TOC_MAGIC = b"TOC\x01"
SUPERBLOCK = struct.Struct("<4sHHQQ32sQQII16s32s")
TOC_HEAD = struct.Struct("<4sIQQQQQ")
PACKAGE = struct.Struct("<QIIIIBBHIQI20s")
DIR = struct.Struct("<IIIIQ")
FILE = struct.Struct("<IIQQQ32sBBH12s")
NO_DIR = 0xFFFFFFFF
EXTENT_ALIGN = 16
PKG_FLAG_STANDALONE = 0x01
CODEC_RAW, CODEC_ZSTD = 0, 1
MAX_TOC_SIZE = 2 << 30
MAX_META_SIZE = 64 << 20
MAX_DEPTH = 256
READ_CHUNK = 4 << 20

KIND_BASE, KIND_UPDATE, KIND_ADDON, KIND_ADDON_UPDATE, KIND_SYSTEM = range(5)
KIND_NAMES = ("base", "update", "addon", "addon_update", "system")


class V1Tlv:
    NPDM = 0x0001
    NACP = 0x0002
    ICON = 0x0003
    DISPLAY_VERSION = 0x0004
    TITLE_NAME = 0x0005
    PUBLISHER = 0x0006
    BUILD_ID = 0x0007
    SOURCE_DUMP = 0x0008
    LOCALIZED_TITLES = 0x0009
    LOCALIZED_ICONS = 0x000A


@dataclass(slots=True)
class V1File:
    path: str  # package-relative, "/"-separated
    size: int
    extent_offset: int
    extent_size: int
    sha256: bytes
    codec: int


@dataclass(slots=True)
class V1Package:
    index: int
    title_id: int
    version: int
    kind: int
    flags: int
    root_dir: int
    tlvs: dict[int, bytes] = field(default_factory=dict)
    files: list[V1File] = field(default_factory=list)

    @property
    def kind_name(self) -> str:
        return KIND_NAMES[self.kind]

    @property
    def label(self) -> str:
        return f"#{self.index} {self.kind_name} {self.title_id:016x} v{self.version}"


class V1Reader:
    def __init__(self, path: str) -> None:
        self.path = path
        self.handle = open(path, "rb")
        try:
            self._parse()
        except BaseException:
            self.handle.close()
            raise

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> "V1Reader":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _read_at(self, offset: int, size: int) -> bytes:
        self.handle.seek(offset)
        data = self.handle.read(size)
        if len(data) != size:
            raise NupError(f"v1 file ends early at {offset + len(data):#x}")
        return data

    def _parse(self) -> None:
        self.file_size = os.fstat(self.handle.fileno()).st_size
        if self.file_size < SUPERBLOCK.size:
            raise NupError("not a NUP v1 file: shorter than its superblock")
        (magic, header_size, _header_version, toc_offset, toc_size, toc_sha256, blob_offset,
         file_size, package_count, flags, _uuid, _reserved) = SUPERBLOCK.unpack(self._read_at(0, SUPERBLOCK.size))
        if magic != MAGIC:
            raise NupError(f"not a NUP v1 file (magic {magic!r})")
        if header_size < SUPERBLOCK.size or toc_offset != header_size:
            raise NupError(f"v1 superblock: header size {header_size:#x}, TOC at {toc_offset:#x}")
        if file_size != self.file_size:
            raise NupError(f"v1 superblock claims {file_size:,} bytes, the file has {self.file_size:,}")
        if not 0 < toc_size <= MAX_TOC_SIZE or toc_offset + toc_size > self.file_size:
            raise NupError(f"v1 TOC of {toc_size:,} bytes does not fit the file")
        if blob_offset % EXTENT_ALIGN or not toc_offset + toc_size <= blob_offset <= self.file_size:
            raise NupError(f"v1 blob region at {blob_offset:#x} is misplaced")
        if flags:
            raise NupError(f"v1 superblock has unknown flags {flags:#x} (v1.0 defines none)")
        self.blob_offset = blob_offset
        toc = self._read_at(toc_offset, toc_size)
        if hashlib.sha256(toc).digest() != toc_sha256:
            raise VerificationError("v1 TOC hash mismatch")
        self.packages = self._parse_toc(memoryview(toc), package_count)

    def _parse_toc(self, toc: memoryview, package_count: int) -> list[V1Package]:
        if len(toc) < TOC_HEAD.size:
            raise NupError("v1 TOC is shorter than its header")
        magic, toc_packages, dir_count, file_count, pool_off, pool_size, _reserved = TOC_HEAD.unpack_from(toc, 0)
        if magic != TOC_MAGIC or toc_packages != package_count or package_count == 0:
            raise NupError("v1 TOC header does not match the superblock")
        dirs_at = TOC_HEAD.size + package_count * PACKAGE.size
        files_at = dirs_at + dir_count * DIR.size
        children_at = files_at + file_count * FILE.size
        if children_at > len(toc) or pool_off + pool_size > len(toc):
            raise NupError("v1 TOC tables overrun the TOC")
        self._pool = toc[pool_off : pool_off + pool_size]
        self._dirs = [DIR.unpack_from(toc, dirs_at + i * DIR.size) for i in range(dir_count)]
        self._files = [FILE.unpack_from(toc, files_at + i * FILE.size) for i in range(file_count)]
        slots = sum(record[3] for record in self._dirs)  # child_slot_count (v1 SPEC §3.3)
        if children_at + 4 * slots > len(toc):
            raise NupError("v1 children array overruns the TOC")
        self._children = struct.unpack_from(f"<{slots}I", toc, children_at)
        packages = []
        for index in range(package_count):
            (title_id, root, _exefs, _romfs, version, kind, pkg_flags, reserved, reserved2,
             meta_offset, meta_size, reserved3) = PACKAGE.unpack_from(toc, TOC_HEAD.size + index * PACKAGE.size)
            if kind >= len(KIND_NAMES):
                raise NupError(f"v1 package {index} has unknown kind {kind}")
            if reserved or reserved2 or any(reserved3):
                raise NupError(f"v1 package {index} has non-zero reserved fields (not a v1.0 file)")
            package = V1Package(index, title_id, version, kind, pkg_flags, root)
            package.tlvs = self._parse_meta(meta_offset, meta_size)
            package.files = self._walk(root)
            packages.append(package)
        return packages

    def _parse_meta(self, offset: int, size: int) -> dict[int, bytes]:
        if offset == 0 or size == 0:
            return {}
        if size > MAX_META_SIZE or offset + size > self.file_size:
            raise NupError(f"v1 meta block at {offset:#x} ({size:,} bytes) does not fit the file")
        block = self._read_at(offset, size)
        tlvs, pos = {}, 0
        while pos + TLV_HEAD.size <= len(block):
            if not bytes(block[pos:]).strip(b"\0"):
                break   # zeros padding the block out, however many: no TLV of type 0
            tlv_type, _reserved, length = TLV_HEAD.unpack_from(block, pos)
            pos += TLV_HEAD.size
            if pos + length > len(block):
                raise NupError(f"v1 TLV {tlv_type:#x} overruns its meta block")
            tlvs.setdefault(tlv_type, block[pos : pos + length])
            pos += length
        if bytes(block[pos:]).strip(b"\0"):   # zeros may pad the block; a cut-off TLV header may not
            raise NupError(f"v1 meta block at {offset:#x} ends in {len(block) - pos} stray byte(s)")
        return tlvs

    def _name(self, offset: int, length: int) -> str:
        if offset + length > len(self._pool):
            raise NupError("v1 name overruns the string pool")
        try:
            name = bytes(self._pool[offset : offset + length]).decode("utf-8")
        except UnicodeDecodeError:
            raise NupError("v1 name is not UTF-8") from None
        if name in ("", ".", "..") or any(char in name for char in "/\\\0"):
            raise NupError(f"v1 tree holds the unsafe name {name!r}")
        return name

    def _walk(self, root: int) -> list[V1File]:
        """Every file under a package root, refusing cycles and shared dirs."""
        if root >= len(self._dirs):
            raise NupError(f"v1 package root {root} is not a directory")
        files: list[V1File] = []
        seen = {root}
        stack = [(root, "", 0)]
        dir_count = len(self._dirs)
        while stack:
            dir_index, prefix, depth = stack.pop()
            if depth > MAX_DEPTH:
                raise NupError("v1 tree is deeper than any dump")
            _name_off, _name_len, first, count, _r = self._dirs[dir_index]
            if first + count > len(self._children):
                raise NupError("v1 directory children overrun the children array")
            for node in self._children[first : first + count]:
                if node < dir_count:
                    if node in seen:
                        raise NupError("v1 tree has a directory reached twice (a cycle)")
                    seen.add(node)
                    name_off, name_len = self._dirs[node][:2]
                    stack.append((node, prefix + self._name(name_off, name_len) + "/", depth + 1))
                elif node - dir_count < len(self._files):
                    files.append(self._file(self._files[node - dir_count], prefix))
                else:
                    raise NupError(f"v1 node id {node} is out of range")
        files.sort(key=lambda f: f.path.encode("utf-8"))
        for a, b in zip(files, files[1:]):
            if a.path == b.path:
                raise NupError(f"v1 tree names {a.path!r} twice")
        return files

    def _file(self, record, prefix: str) -> V1File:
        name_off, name_len, size, extent_offset, extent_size, sha256, codec, codec_flags, _r, _r2 = record
        path = prefix + self._name(name_off, name_len)
        if codec not in (CODEC_RAW, CODEC_ZSTD) or codec_flags:
            raise NupError(f"v1 file {path!r} uses unknown codec {codec}/{codec_flags}")
        if size and (extent_offset < self.blob_offset or extent_offset + extent_size > self.file_size):
            raise NupError(f"v1 file {path!r} extent lies outside the blob region")
        if codec == CODEC_RAW and extent_size != size:
            raise NupError(f"v1 file {path!r}: raw extent of {extent_size} bytes for {size}")
        return V1File(path, size, extent_offset, extent_size, sha256, codec)

    def copy_file(self, entry: V1File, target: str) -> None:
        """Write a file's bytes to target, decompressed and hash-checked."""
        digest = hashlib.sha256()
        written = 0
        with open(target, "wb") as out:
            for chunk in self._iter_data(entry):
                written += len(chunk)
                if written > entry.size:
                    raise VerificationError(f"v1 file {entry.path!r} holds more than {entry.size} bytes")
                digest.update(chunk)
                out.write(chunk)
        if written != entry.size:
            raise VerificationError(f"v1 file {entry.path!r} holds {written} bytes, not {entry.size}")
        if digest.digest() != entry.sha256:
            raise VerificationError(f"v1 file {entry.path!r} data hash mismatch")

    def _iter_extent(self, entry: V1File):
        self.handle.seek(entry.extent_offset)
        remaining = entry.extent_size
        while remaining:
            chunk = self.handle.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise NupError(f"v1 file {entry.path!r} ends early")
            remaining -= len(chunk)
            yield chunk

    def _iter_data(self, entry: V1File):
        if entry.size == 0:
            return
        if entry.codec == CODEC_RAW:
            yield from self._iter_extent(entry)
            return
        try:
            # at most READ_CHUNK bytes at a time: copy_file stops a frame that expands
            # past the file's size before it is all in memory (SPEC §6.4)
            yield from zstd_chunks(self._iter_extent(entry))
        except NupError:
            raise
        except Exception as error:   # the codec's own error type: the standard library's or zstandard's
            raise VerificationError(f"v1 file {entry.path!r}: zstd data is corrupt ({error})") from None


def zstd_chunks(chunks, out_size: int = READ_CHUNK):
    """The zstd frame that starts the compressed chunks, decompressed at most
    out_size bytes at a time, however far it expands; bytes after the frame
    are left to the size and hash checks (copy_file). The standard library's
    codec on Python 3.14+, else the zstandard package (pip install nup[v1]);
    a missing codec is an error here, before any chunk is read."""
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        pass
    else:
        return stdlib_zstd_chunks(zstd.ZstdDecompressor(), chunks, out_size)
    try:
        import zstandard
    except ImportError:
        raise NupError(
            "this v1 file holds zstd-compressed files: use Python 3.14+ or "
            "install zstandard (pip install nup[v1])"
        ) from None
    return zstandard_chunks(zstandard.ZstdDecompressor(), chunks, out_size)


def stdlib_zstd_chunks(decompressor, chunks, out_size: int):
    for chunk in chunks:
        out = decompressor.decompress(chunk, out_size)
        while True:
            if out:
                yield out
            if decompressor.eof:
                return   # bytes after the frame: the size and hash checks decide (copy_file)
            if decompressor.needs_input:
                break
            out = decompressor.decompress(b"", out_size)


def zstandard_chunks(decompressor, chunks, out_size: int):
    # read_to_iter stops at the end of the frame and leaves what follows unread
    yield from decompressor.read_to_iter(ChunkSource(chunks), write_size=out_size)


class ChunkSource:
    """The file-like read(size) zstandard's read_to_iter pulls from, over an
    iterator of byte chunks."""

    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.pending = b""

    def read(self, size: int = -1) -> bytes:
        if not self.pending:
            self.pending = next(self.chunks, b"")
        if size < 0 or size >= len(self.pending):
            out, self.pending = self.pending, b""
        else:
            out, self.pending = self.pending[:size], self.pending[size:]
        return out
