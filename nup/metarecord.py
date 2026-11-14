"""Meta record serialization and parsing (the "NUP\\x02" record)."""

import hashlib

from .errors import NupError
from .layout import (
    DIGEST_SIZE,
    Kind,
    META_HEADER,
    META_HEADER_SIZE,
    META_MAGIC,
    PACKAGE_FIXED_SIZE,
    PACKAGE_RECORD,
    encode_tlv,
    parse_file_rows,
    parse_tlvs,
    tlv_block_size,
)
from .model import MetaRecord, PackageRecord, validate_record_flags, validate_scope_contiguity


def meta_length(packages: list[PackageRecord]) -> int:
    length = META_HEADER_SIZE + DIGEST_SIZE
    for record in packages:
        length += PACKAGE_FIXED_SIZE
        length += tlv_block_size(record.tlvs)
        length += sum(len(row.encode()) for row in record.files)
    return length


def encode_meta_record(meta: MetaRecord, total_file_count: int) -> bytes:
    for record in meta.packages:
        validate_record_flags(record)
        validate_tlv_block_size(record)
    out = bytearray()
    out += META_HEADER.pack(
        META_MAGIC,
        META_HEADER_SIZE,
        meta.patch_version,
        len(meta.packages),
        0,
        total_file_count,
        meta.header_hash,
        0,
        meta.feature_flags,
    )
    for record in meta.packages:
        out += encode_package_record(record)
    digest = hashlib.sha256(out).digest()
    out += digest
    return bytes(out)


def encode_package_record(record: PackageRecord) -> bytes:
    for field_name, digest in (("content hash", record.content_hash),
                               ("base content hash", record.base_content_hash)):
        if len(digest) != DIGEST_SIZE:
            raise NupError(
                f"{field_name} must be a {DIGEST_SIZE}-byte digest, got {len(digest)} bytes"
            )
    out = bytearray()
    out += PACKAGE_RECORD.pack(
        record.kind.value,
        record.flags,
        record.program_index,
        0,
        tlv_block_size(record.tlvs),
        record.title_id,
        record.application_id,
        record.version,
        len(record.files),
        record.content_hash,
        record.base_content_hash,
        record.first_entry_index,
    )
    for tlv_type, value in sorted(record.tlvs.items()):
        out += encode_tlv(tlv_type, value)
    for row in record.files:
        out += row.encode()
    return bytes(out)


def validate_tlv_block_size(record: PackageRecord) -> None:
    """Each value within the per-TLV cap (encode_tlv says which one is over); the u32 block size then always holds them"""
    total = tlv_block_size(record.tlvs)
    if total > 0xFFFFFFFF:
        raise NupError(f"TLV block of {total:,} bytes exceeds the u32 tlv size field (SPEC §3)")


def parse_meta_record(record: memoryview) -> MetaRecord:
    body, digest = split_digest(record)
    header = parse_meta_header(body)
    packages = []
    pos = header["header_size"]
    for _ in range(header["package_count"]):
        record_parsed, pos = parse_package_record(body, pos)
        packages.append(record_parsed)
    if pos != len(body):
        raise NupError(f"{len(body) - pos} trailing bytes after the last package record")
    declared = sum(len(pkg.files) for pkg in packages)
    if declared != header["file_count"]:
        raise NupError(
            f"meta file count {header['file_count']} disagrees with package tables ({declared})"
        )
    validate_scope_contiguity(packages)
    return MetaRecord(header["patch_version"], header["header_hash"], packages,
                      header["feature_flags"])


def split_digest(record: memoryview) -> tuple[memoryview, bytes]:
    if len(record) < META_HEADER_SIZE + DIGEST_SIZE:
        raise NupError("meta record is too short")
    body = record[:-DIGEST_SIZE]
    digest = bytes(record[-DIGEST_SIZE:])
    if hashlib.sha256(body).digest() != digest:
        raise NupError("meta record digest mismatch")
    return body, digest


def parse_meta_header(body: memoryview) -> dict:
    magic, header_size, patch_version, package_count, reserved, file_count, header_hash, meta_reserved, feature_flags = (
        META_HEADER.unpack_from(body)
    )
    if magic != META_MAGIC:
        raise NupError(f"bad meta magic {magic!r}")
    if header_size < META_HEADER_SIZE or header_size > len(body):
        raise NupError(f"implausible meta header size {header_size:#x}")
    if reserved != 0 or meta_reserved != 0:
        raise NupError("meta header reserved field is not zero")
    if feature_flags:
        raise NupError(
            f"unknown feature flags {feature_flags:#x} set; this build reads "
            "v2.0 containers only (flags field, SPEC §3)"
        )
    return {
        "header_size": header_size,
        "patch_version": patch_version,
        "package_count": package_count,
        "file_count": file_count,
        "header_hash": header_hash,
        "feature_flags": feature_flags,
    }


def parse_package_record(body: memoryview, pos: int) -> tuple[PackageRecord, int]:
    if pos + PACKAGE_FIXED_SIZE > len(body):
        raise NupError("package record overruns the meta record")
    kind_value, flags, program_index, pkg_reserved, tlv_size, title_id, application_id, version, row_count, content, base_content, first_index = (
        PACKAGE_RECORD.unpack_from(body, pos)
    )
    pos += PACKAGE_FIXED_SIZE
    if pkg_reserved:
        raise NupError("package record reserved field is not zero")
    kind = parse_kind(kind_value)
    validate_record_flags(
        PackageRecord(kind=kind, flags=flags, title_id=title_id,
                      application_id=application_id, version=version,
                      first_entry_index=first_index, program_index=program_index)
    )
    tlv_end = pos + tlv_size
    if tlv_end > len(body):
        raise NupError("TLV block overruns the meta record")
    tlvs = parse_tlvs(body[pos:tlv_end])
    pos = tlv_end
    files = parse_file_rows(body, row_count, pos)
    pos += sum(len(row.encode()) for row in files)
    record = PackageRecord(
        kind=kind,
        flags=flags,
        title_id=title_id,
        application_id=application_id,
        version=version,
        first_entry_index=first_index,
        content_hash=content,
        base_content_hash=base_content,
        tlvs=tlvs,
        files=files,
        program_index=program_index,
    )
    return record, pos


def parse_kind(kind_value: int) -> Kind:
    try:
        return Kind(kind_value)
    except ValueError:
        raise NupError(f"unknown package kind {kind_value}") from None
