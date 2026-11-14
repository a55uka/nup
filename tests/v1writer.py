"""A minimal NUP v1 writer (meow branch SPEC.md) for conversion tests."""

from dataclasses import dataclass, field
import hashlib
import struct

SUPERBLOCK = struct.Struct("<4sHHQQ32sQQII16s32s")
TOC_HEAD = struct.Struct("<4sIQQQQQ")
PACKAGE = struct.Struct("<QIIIIBBHIQI20s")
DIR = struct.Struct("<IIIIQ")
FILE = struct.Struct("<IIQQQ32sBBH12s")
NO_DIR = 0xFFFFFFFF


@dataclass
class Pkg:
    kind: int
    title_id: int
    files: dict[str, bytes]
    version: int = 0
    flags: int = 0
    tlvs: dict[int, bytes] = field(default_factory=dict)


def localized(records: dict[str, bytes]) -> bytes:
    out = b""
    for tag, value in records.items():
        out += bytes([len(tag)]) + tag.encode() + struct.pack("<I", len(value)) + value
    return out


def align(value: int, to: int = 16) -> int:
    return (value + to - 1) // to * to


def write_v1(path, packages: list[Pkg], *, zstd: bool = False, tamper=None) -> None:
    compress = None
    if zstd:
        try:
            from compression import zstd as std_zstd
            compress = std_zstd.compress
        except ImportError:
            import zstandard
            compress = zstandard.ZstdCompressor(level=3, write_content_size=True).compress
    # tree: dir = [name, {child_name: dir|file_index}]
    dirs: list[list] = []
    files: list[tuple[str, bytes]] = []
    roots = []
    for pkg in packages:
        root = ["", {}]
        dirs.append(root)
        roots.append(len(dirs) - 1)
        for rel, data in sorted(pkg.files.items()):
            node = root
            *parents, leaf = rel.split("/")
            for part in parents:
                child = node[1].get(part)
                if child is None:
                    child = [part, {}]
                    dirs.append(child)
                    node[1][part] = child
                node = child
            files.append((leaf, data))
            node[1][leaf] = len(files) - 1
    dir_index = {id(d): i for i, d in enumerate(dirs)}
    pool = bytearray()
    names: dict[str, tuple[int, int]] = {}

    def intern(name: str) -> tuple[int, int]:
        if name not in names:
            raw = name.encode()
            names[name] = (len(pool), len(raw))
            pool.extend(raw)
        return names[name]

    children: list[int] = []
    dir_records = []
    for d in dirs:
        first = len(children)
        for name in sorted(d[1], key=lambda n: n.encode()):
            child = d[1][name]
            children.append(dir_index[id(child)] if isinstance(child, list) else len(dirs) + child)
        off, ln = intern(d[0])
        dir_records.append((off, ln, first, len(children) - first))
    toc_core = TOC_HEAD.size + len(packages) * PACKAGE.size + len(dirs) * DIR.size + len(files) * FILE.size
    pool_off = toc_core + 4 * len(children)
    for name, _data in files:
        intern(name)
    toc_size = pool_off + len(pool)
    blob_offset = align(0x80 + toc_size)
    blob = bytearray()
    file_records = []
    for name, data in files:
        stored, codec = data, 0
        if compress and data:
            packed = compress(data)
            if len(packed) < len(data):
                stored, codec = packed, 1
        offset = blob_offset + len(blob) if data else 0
        blob.extend(stored)
        blob.extend(bytes(align(len(blob)) - len(blob)))
        off, ln = intern(name)
        file_records.append((off, ln, len(data), offset, len(stored) if data else 0,
                             hashlib.sha256(data).digest(), codec))
    meta_records = []
    meta_blob = bytearray()
    meta_base = blob_offset + len(blob)
    for pkg in packages:
        block = b"".join(struct.pack("<HHI", t, 0, len(v)) + v for t, v in sorted(pkg.tlvs.items()))
        meta_records.append((meta_base + len(meta_blob), len(block)) if block else (0, 0))
        meta_blob.extend(block)
    toc = bytearray(TOC_HEAD.pack(b"TOC\x01", len(packages), len(dirs), len(files), pool_off, len(pool), 0))
    for pkg, root, (meta_off, meta_size) in zip(packages, roots, meta_records):
        toc += PACKAGE.pack(pkg.title_id, root, NO_DIR, NO_DIR, pkg.version, pkg.kind, pkg.flags,
                            0, 0, meta_off, meta_size, bytes(20))
    for off, ln, first, count in dir_records:
        toc += DIR.pack(off, ln, first, count, 0)
    for off, ln, size, eoff, esz, sha, codec in file_records:
        toc += FILE.pack(off, ln, size, eoff, esz, sha, codec, 0, 0, bytes(12))
    toc += struct.pack(f"<{len(children)}I", *children)
    toc += pool
    if tamper:
        tamper(toc, blob)
    body = bytes(toc) + bytes(blob_offset - 0x80 - len(toc)) + bytes(blob) + bytes(meta_blob)
    superblock = SUPERBLOCK.pack(b"NUP\x01", 0x80, 1, 0x80, len(toc), hashlib.sha256(toc).digest(),
                                 blob_offset, 0x80 + len(body), len(packages), 0, bytes(16), bytes(32))
    with open(path, "wb") as handle:
        handle.write(superblock + body)
