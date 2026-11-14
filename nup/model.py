"""In-memory model of a NUP v2 container: entries, package records, rules.

Meta record serialization lives in metarecord; byte codecs in layout.
"""

from dataclasses import dataclass, field
import hashlib

from .errors import NupError
from .layout import (
    ADDON_OFFSET,
    CONTAINER_ENTRY,
    CONTAINER_HEADER,
    DIFF_KINDS,
    Flags,
    HFS0_MAGIC,
    HEADER_SIZE,
    ENTRY_SIZE,
    Kind,
    PROGRAM_INDEX_MAX,
    scope_prefix,
)
from .layout import FileRow, ZERO_DIGEST, align_up, content_hash


@dataclass(slots=True)
class ContainerEntry:
    name: str
    size: int
    data_offset: int
    hashed_size: int
    prefix_hash: bytes


@dataclass(slots=True)
class PackageRecord:
    kind: Kind
    flags: int
    title_id: int
    application_id: int
    version: int
    first_entry_index: int
    content_hash: bytes = ZERO_DIGEST
    base_content_hash: bytes = ZERO_DIGEST
    tlvs: dict[int, bytes] = field(default_factory=dict)
    files: list[FileRow] = field(default_factory=list)
    program_index: int = 0  # SPEC §4.1

    @property
    def is_diff(self) -> bool:
        return bool(self.flags & Flags.DIFF)

    def content_digest(self) -> bytes:
        return content_hash(self.files)

    def store_content_hash(self) -> None:
        self.content_hash = self.content_digest()


@dataclass(slots=True)
class MetaRecord:
    patch_version: int
    header_hash: bytes
    packages: list[PackageRecord] = field(default_factory=list)
    feature_flags: int = 0

    def package_of_entry(self, index: int) -> PackageRecord:
        for record in self.packages:
            if record.first_entry_index <= index < record.first_entry_index + len(record.files):
                return record
        raise NupError(f"no package scope owns entry index {index}")


def build_string_table(names: list[str]) -> tuple[bytes, list[int]]:
    table = bytearray()
    offsets = []
    for name in names:
        encoded = name.encode("utf-8") + b"\x00"
        offsets.append(len(table))
        table += encoded
    return bytes(table), offsets


def encode_container_prefix(entries: list[ContainerEntry], table: bytes) -> bytes:
    out = bytearray()
    out += CONTAINER_HEADER.pack(HFS0_MAGIC, len(entries), len(table), 0)
    for entry in entries:
        out += encode_container_entry(entry, table)
    out += table
    return bytes(out)


def encode_container_entry(entry: ContainerEntry, table: bytes) -> bytes:
    encoded_name = entry.name.encode("utf-8") + b"\x00"
    name_offset = table.find(encoded_name)
    if name_offset < 0:
        raise NupError(f"entry name {entry.name!r} missing from string table")
    return CONTAINER_ENTRY.pack(
        entry.data_offset,
        entry.size,
        name_offset,
        entry.hashed_size,
        0,
        entry.prefix_hash,
    )


def data_region_start(entry_count: int, string_table_size: int) -> int:
    return align_up(HEADER_SIZE + ENTRY_SIZE * entry_count + string_table_size)


def parse_container_counts(header: bytes) -> tuple[int, int]:
    counts = parse_container_header_fields(header)
    return counts[1], counts[2]


def parse_container_header_fields(header: bytes) -> tuple[bytes, int, int, int]:
    if len(header) < HEADER_SIZE:
        raise NupError("container is shorter than the HFS0 header")
    magic, count, table_size, reserved = CONTAINER_HEADER.unpack_from(header)
    validate_container_magic(magic, reserved)
    return magic, count, table_size, reserved


def validate_container_magic(magic: bytes, reserved: int) -> None:
    if magic != HFS0_MAGIC:
        raise NupError(f"bad container magic {magic!r}")
    if reserved != 0:
        raise NupError("container header reserved field is not zero")


def parse_container_prefix(prefix: memoryview) -> tuple[int, list[ContainerEntry], bytes]:
    if len(prefix) < HEADER_SIZE:
        raise NupError("container is shorter than the HFS0 header")
    magic, count, table_size, reserved = CONTAINER_HEADER.unpack_from(prefix)
    validate_container_magic(magic, reserved)
    entries_end = HEADER_SIZE + ENTRY_SIZE * count
    table_end = entries_end + table_size
    if table_end > len(prefix):
        raise NupError("entry table or string table overruns the container")
    table = bytes(prefix[entries_end:table_end])
    entries = [parse_container_entry(prefix, table, index) for index in range(count)]
    return count, entries, table


def parse_container_entry(prefix: memoryview, table: bytes, index: int) -> ContainerEntry:
    offset = HEADER_SIZE + ENTRY_SIZE * index
    data_offset, size, name_offset, hashed_size, entry_reserved, prefix_hash = (
        CONTAINER_ENTRY.unpack_from(prefix, offset)
    )
    if entry_reserved != 0:
        raise NupError(f"entry {index} reserved field is not zero")
    return ContainerEntry(
        parse_entry_name(table, index, name_offset), size, data_offset, hashed_size, prefix_hash
    )


def parse_entry_name(table: bytes, index: int, name_offset: int) -> str:
    end = table.find(b"\x00", name_offset)
    if end < 0:
        raise NupError(f"entry {index} name is not NUL-terminated")
    try:
        return table[name_offset:end].decode("utf-8")
    except UnicodeDecodeError:
        raise NupError(
            f"entry {index} name is not valid UTF-8 (string table corrupted?)"
        ) from None


def validate_record_flags(record: PackageRecord) -> None:
    if record.kind in DIFF_KINDS and not record.is_diff:
        raise NupError(f"a {record.kind.name.lower()} package must carry the diff flag")
    if record.kind not in DIFF_KINDS and record.is_diff:
        raise NupError(f"only update and add-on update packages may carry the diff flag (kind {record.kind})")
    if not 0 <= record.program_index <= PROGRAM_INDEX_MAX:
        raise NupError(f"program index {record.program_index} does not fit the package record "
                       f"(at most {PROGRAM_INDEX_MAX}, SPEC §4.1)")
    if record.program_index and record.kind not in (Kind.BASE, Kind.UPDATE):
        raise NupError(f"only base and update packages have a program index (kind {record.kind})")
    if record.program_index and not record.application_id:
        raise NupError(f"program {record.program_index} package {record.title_id:#x} has no "
                       "application id (SPEC §4.1)")


def validate_grouping(packages: list[PackageRecord]) -> None:
    """SPEC §1 rule 7 / §3: one package group per file.  A container holds a
    base, a single update (optionally with its base, SPEC §5.3), any number
    of add-ons sharing one application id, or any number of add-on updates
    (SPEC §5.4); every package of a container belongs to one program (§4.1)."""
    if len({record.program_index for record in packages}) > 1:
        raise NupError("a container holds the packages of one program (SPEC §4.1)")
    kinds = sorted(record.kind for record in packages)
    if len(packages) <= 1 or all(kind is Kind.ADDON for kind in kinds):
        return
    if all(kind is Kind.ADDON_UPDATE for kind in kinds):
        return
    if kinds == [Kind.BASE, Kind.UPDATE]:
        return
    raise NupError(
        "a container may hold one base, a base+update pair (SPEC §5.3), "
        "add-ons only (SPEC §1 rule 7), or add-on updates only (SPEC §5.4)"
    )


def validate_scope_contiguity(packages: list[PackageRecord]) -> None:
    expected = 1
    for first, count in sorted(
        (record.first_entry_index, len(record.files)) for record in packages
    ):
        if first != expected:
            raise NupError(
                f"package scopes are not contiguous: expected first entry {expected}, got {first}"
            )
        expected += count


def bind_file_tables(entries: list[ContainerEntry], meta: MetaRecord) -> None:
    for record in meta.packages:
        bind_package_file_table(entries, record)


def bind_package_file_table(entries: list[ContainerEntry], record: PackageRecord) -> None:
    for offset, row in enumerate(record.files):
        index = record.first_entry_index + offset
        entry = entries[index]
        expected_name = entry_scope_name(record, row.path)
        if entry.name != expected_name:
            raise NupError(
                f"entry {index} is {entry.name!r} but the file table says {expected_name!r}"
            )
        if entry.size != row.size:
            raise NupError(
                f"entry {entry.name!r} size {entry.size} disagrees with file table size {row.size}"
            )


def scope_of(record: PackageRecord) -> str:
    """A package's scope label and entry prefix (SPEC §4): base, update/<v>,
    addon/<i>, addonupdate/<i>/<v>. The one place it is worked out."""
    return scope_prefix(record.kind, record.version, addon_index(record))


def entry_scope_name(record: PackageRecord, path: str) -> str:
    return f"{scope_of(record)}/{path}"


def addon_index(record: PackageRecord) -> int:
    return record.title_id - record.application_id - ADDON_OFFSET


def empty_prefix_hash() -> bytes:
    return hashlib.sha256(b"").digest()
