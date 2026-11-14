"""Container reader: parse, bind-verify, and expose hash-checked entry reads."""

import hashlib

from .errors import NupError, VerificationError
from .layout import ALIGN, DIGEST_SIZE, META_NAME, Kind, align_up
from .model import (
    MetaRecord,
    PackageRecord,
    bind_file_tables,
    entry_scope_name,
    parse_container_counts,
    parse_container_prefix,
    validate_grouping,
    validate_scope_contiguity,
)
from .metarecord import parse_meta_record
from .tree import validate_container_path

READ_CHUNK = 4 << 20
MAX_META_RECORD_SIZE = 1 << 31


class NupReader:
    def __init__(self, path: str, *, check_bind: bool = True) -> None:
        self.path = path
        self.handle = open(path, "rb")
        try:
            self._parse()
            if check_bind:
                self.check_bind()
        except BaseException:
            self.handle.close()
            raise

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> "NupReader":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _parse(self) -> None:
        self.handle.seek(0, 2)
        self.file_size = self.handle.tell()
        self.handle.seek(0)
        header = self.handle.read(0x10)
        count, table_size = parse_container_counts(header)
        entries_end = 0x10 + 0x40 * count
        if entries_end + table_size > self.file_size:
            raise NupError(
                f"declared entry table ({count} entries) and string table "
                f"({table_size} bytes) exceed the {self.file_size}-byte container"
            )
        prefix = memoryview(header + self.handle.read(entries_end - 0x10 + table_size))
        _count, self.entries, self.string_table = parse_container_prefix(prefix)
        self.entry_count = count
        self.data_start = entries_end + table_size
        if self.data_start % ALIGN or self.entry_count == 0:
            raise NupError(
                f"data region starts at {self.data_start:#x}: the string table must be "
                "padded so entry data lands on 0x200 boundaries"
            )
        for index, entry in enumerate(self.entries):
            if entry.data_offset % ALIGN:
                raise NupError(f"entry {entry.name!r} data offset is not 0x200-aligned")
            if self.data_start + entry.data_offset + entry.size > self.file_size:
                raise NupError(f"entry {entry.name!r} lies outside the container (SPEC §6.4)")
            expected = 0 if index == 0 else min(entry.size, ALIGN)
            if entry.hashed_size != expected:
                raise NupError(
                    f"entry {entry.name!r} hashed size {entry.hashed_size:#x} is not {expected:#x} (SPEC §2)"
                )
        self._index_by_name = {entry.name: i for i, entry in enumerate(self.entries)}
        if len(self._index_by_name) != len(self.entries):
            seen: set[str] = set()
            for entry in self.entries:
                if entry.name in seen:
                    raise NupError(f"entry name {entry.name!r} appears twice (SPEC §6.4)")
                seen.add(entry.name)
        if self.entries[0].name != META_NAME:
            raise NupError("the first container entry is not meta.nup")
        for entry in self.entries[1:]:
            validate_container_path(entry.name)
        meta_entry = self.entries[0]
        if meta_entry.size > MAX_META_RECORD_SIZE:
            raise NupError(
                f"meta record claims {meta_entry.size:,} bytes; nothing "
                "legitimate comes near the sanity cap"
            )
        self.meta_raw = self.read_entry_bytes(meta_entry)
        self.meta: MetaRecord = parse_meta_record(memoryview(self.meta_raw))
        validate_scope_contiguity(self.meta.packages)
        validate_grouping(self.meta.packages)
        declared = sum(len(record.files) for record in self.meta.packages)
        if declared != self.entry_count - 1:
            raise NupError(
                f"meta declares {declared} scoped files but the container holds "
                f"{self.entry_count - 1}"
            )
        bind_file_tables(self.entries, self.meta)
        for record in self.meta.packages:
            if record.application_id == 0 and record.kind is not Kind.BASE:
                raise NupError(
                    f"{record.kind.name} package {record.title_id:#x} has no application id"
                )
            for row in record.files:
                validate_container_path(row.path)
        self._rows_by_path = {
            self.entry_name_of(record, offset): row
            for record in self.meta.packages
            for offset, row in enumerate(record.files)
        }
        self._package_ranges = sorted(
            (record.first_entry_index, len(record.files), record)
            for record in self.meta.packages
        )

    def check_bind(self) -> None:
        self.check_meta_digest()
        self.check_header_hash()

    def check_meta_digest(self) -> None:
        body = self.meta_raw[:-DIGEST_SIZE]
        stored = self.meta_raw[-DIGEST_SIZE:]
        if hashlib.sha256(body).digest() != stored:
            raise VerificationError("meta record digest mismatch")

    def check_header_hash(self) -> None:
        self.handle.seek(0)
        region = self.handle.read(self.data_start)
        if hashlib.sha256(region).digest() != self.meta.header_hash:
            raise VerificationError("container header hash mismatch")

    def entry_index(self, name: str) -> int:
        try:
            return self._index_by_name[name]
        except KeyError:
            raise NupError(f"no entry named {name!r}") from None

    def entry(self, name: str):
        return self.entries[self.entry_index(name)]

    def read_entry_bytes(self, entry) -> bytes:
        self.handle.seek(self.data_start + entry.data_offset)
        return self.handle.read(entry.size)

    def iter_entry_chunks(self, entry):
        self.handle.seek(self.data_start + entry.data_offset)
        remaining = entry.size
        while remaining:
            chunk = self.handle.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise NupError(f"entry {entry.name!r} ended early")
            remaining -= len(chunk)
            yield chunk

    def read_file(self, container_path: str, *, verify: bool = True) -> bytes:
        """Lazy verification level (SPEC §6.3): the data is hashed on read."""
        data = self.read_entry_bytes(self.entry(container_path))
        if verify:
            row = self._rows_by_path.get(container_path)
            if row is None:
                raise NupError(f"no file-table row for {container_path!r}")
            if hashlib.sha256(data).digest() != row.sha256:
                raise VerificationError(f"entry {container_path!r} data hash mismatch")
        return data

    def package_of_entry(self, index: int) -> PackageRecord:
        for first, count, record in self._package_ranges:
            if first <= index < first + count:
                return record
        raise NupError(f"no package scope owns entry index {index}")

    def entry_name_of(self, record: PackageRecord, offset: int) -> str:
        return entry_scope_name(record, record.files[offset].path)

    def verify_entry_table_hashes(self) -> None:
        for entry in self.entries[1:]:
            if not entry.hashed_size:
                continue
            data = self.read_entry_bytes(entry)
            if hashlib.sha256(data[: entry.hashed_size]).digest() != entry.prefix_hash:
                raise VerificationError(f"entry {entry.name!r} prefix hash mismatch")

    def verify_data_coverage(self) -> None:
        expected = self.data_start + sum(align_up(e.size) for e in self.entries)
        if self.file_size != expected:
            raise VerificationError(
                f"container size {self.file_size} != covered data end {expected}"
            )
        cursor = align_up(self.entries[0].size)
        for entry in self.entries[1:]:
            if entry.data_offset != cursor:
                raise VerificationError(
                    f"entry {entry.name!r} data offset {entry.data_offset} != {cursor}"
                )
            cursor += align_up(entry.size)


def read_container(path: str, *, check_bind: bool = True) -> NupReader:
    return NupReader(path, check_bind=check_bind)
