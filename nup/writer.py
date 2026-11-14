"""Container writer: entry layout, padding, and the two hash layers.

The writer fixes the string table padding so the data region starts on a
0x200 file boundary (see SPEC_ISSUES['string-table-alignment']) and stores
meta.nup with hashed size 0 (see SPEC_ISSUES['meta-prefix-hash-cycle']).
"""

from dataclasses import dataclass
import hashlib
import os

from .errors import NupError
from .layout import ALIGN, META_NAME, align_up
from .metarecord import encode_meta_record, meta_length
from .model import (
    ContainerEntry,
    MetaRecord,
    build_string_table,
    data_region_start,
    empty_prefix_hash,
    encode_container_prefix,
)

READ_CHUNK = 4 << 20
META_ENTRY_DATA_OFFSET = 0


@dataclass(slots=True)
class Blob:
    """Entry payload: inline bytes, a file stream, or a container byte range."""

    name: str
    size: int
    prefix_hash: bytes
    fs_path: str | None = None
    offset: int = 0
    data: bytes | None = None


def write_container(out_path: str, packed_packages, patch_version: int = 0) -> None:
    records = [packed.record for packed in packed_packages]
    total_files = sum(len(record.files) for record in records)
    meta_len = meta_length(records)
    blobs = [blob for packed in packed_packages for blob in packed.blobs]
    refuse_own_source(out_path, blobs)
    entries, data_start = layout_entries(meta_len, blobs)
    prefix_padded, meta_bytes = build_prefix_and_meta(entries, records, total_files, patch_version)
    write_regions(out_path, prefix_padded, meta_bytes, blobs)
    check_written_size(out_path, data_start, meta_len, blobs)


def refuse_own_source(out_path: str, blobs: list[Blob]) -> None:
    """Writing out_path empties it first: a container whose bytes come from that
    same file (`nup edit x.nup -o x.nup`) would lose them before they are copied."""
    if not os.path.exists(out_path):
        return
    for source in {blob.fs_path for blob in blobs if blob.fs_path}:
        if os.path.exists(source) and os.path.samefile(source, out_path):
            raise NupError(f"{out_path!r} is also where this container's data is read from; "
                           "write to another path (or leave out -o to edit in place)")


def layout_entries(meta_len: int, blobs: list[Blob]) -> tuple[list[ContainerEntry], int]:
    entries = [
        ContainerEntry(META_NAME, meta_len, META_ENTRY_DATA_OFFSET, 0, empty_prefix_hash())
    ]
    cursor = align_up(meta_len)
    for blob in blobs:
        entries.append(
            ContainerEntry(blob.name, blob.size, cursor, min(blob.size, ALIGN), blob.prefix_hash)
        )
        cursor += align_up(blob.size)
    table, _offsets = build_string_table([entry.name for entry in entries])
    return entries, data_region_start(len(entries), len(table))


def build_prefix_and_meta(entries, records, total_files: int, patch_version: int) -> tuple[bytes, bytes]:
    table, _offsets = build_string_table([entry.name for entry in entries])
    data_start = data_region_start(len(entries), len(table))
    prefix_bytes = 0x10 + 0x40 * len(entries)
    padded_table = table + b"\x00" * (data_start - prefix_bytes - len(table))
    prefix_padded = encode_container_prefix(entries, padded_table)
    header_hash = hashlib.sha256(prefix_padded).digest()
    meta_bytes = encode_meta_record(MetaRecord(patch_version, header_hash, records), total_files)
    return prefix_padded, meta_bytes


def write_regions(out_path: str, prefix_padded: bytes, meta_bytes: bytes, blobs: list[Blob]) -> None:
    with open(out_path, "wb") as out:
        out.write(prefix_padded)
        out.write(meta_bytes)
        out.write(b"\x00" * (align_up(len(meta_bytes)) - len(meta_bytes)))
        for blob in blobs:
            copy_blob_data(out, blob)
            padding = align_up(blob.size) - blob.size
            if padding:
                out.write(b"\x00" * padding)


def copy_blob_data(out, blob: Blob) -> None:
    if blob.data is not None:
        out.write(blob.data)
        return
    if blob.fs_path is None:
        raise NupError(f"blob {blob.name!r} has no data source")
    with open(blob.fs_path, "rb") as source:
        source.seek(blob.offset)
        remaining = blob.size
        while remaining:
            chunk = source.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise NupError(f"{blob.fs_path!r} ended early while packing")
            out.write(chunk)
            remaining -= len(chunk)


def check_written_size(out_path: str, data_start: int, meta_len: int, blobs: list[Blob]) -> None:
    written = os.path.getsize(out_path)
    expected = data_start + align_up(meta_len) + sum(align_up(b.size) for b in blobs)
    if written != expected:
        raise NupError(f"container size {written} != expected {expected}")
