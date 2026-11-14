"""Wire-format tests: structs, TLVs, content hashing, and layout decisions."""

import hashlib

import pytest

from nup.errors import NupError
from nup.layout import (
    ALIGN,
    CONTAINER_ENTRY,
    CONTAINER_HEADER,
    ENTRY_SIZE,
    HEADER_SIZE,
    META_HEADER,
    META_HEADER_SIZE,
    PACKAGE_FIXED_SIZE,
    PACKAGE_RECORD,
    ZERO_DIGEST,
    FileRow,
    SPEC_ISSUES,
    TlvType,
    align_up,
    content_hash,
    encode_localized,
    encode_tlv,
    parse_file_rows,
    parse_localized,
    parse_tlvs,
    scope_prefix,
)
from nup.layout import Kind


def test_struct_widths_match_the_documented_layout():
    assert CONTAINER_HEADER.size == HEADER_SIZE
    assert CONTAINER_ENTRY.size == ENTRY_SIZE
    assert META_HEADER.size == META_HEADER_SIZE
    assert PACKAGE_RECORD.size == PACKAGE_FIXED_SIZE


def test_package_record_fixed_part_is_0x68_bytes_ending_before_tlvs():
    layout = "<BBBBIQQII32s32sQ"  # 0x02: program index (SPEC §4.1), 0x04: u32 tlv size (§3, §10.3)
    assert PACKAGE_RECORD.format == layout
    assert PACKAGE_FIXED_SIZE == 0x68


def test_malformed_localized_record_is_a_nup_error():
    """Issue #36: a damaged localized record fails as NupError, never a raw decode error."""
    from nup.layout import parse_localized
    for bad in (b"\x02\xff\xfe\x01\x00x", b"\x05ab", b"\x02ja\x05\x00ab"):
        with pytest.raises(NupError):
            parse_localized(memoryview(bad))


def test_tlv_roundtrip():
    encoded = encode_tlv(int(TlvType.TITLE_NAME), b"Donkey Kong Bananza")
    assert parse_tlvs(memoryview(encoded)) == {int(TlvType.TITLE_NAME): b"Donkey Kong Bananza"}


def test_tlv_length_is_capped_at_1_mib(spec_issue):
    """u16 type + u16 reserved + u32 length; one value at most 1 MiB (SPEC §3, §10.3)"""
    import struct
    assert spec_issue("tlv-size") is not None
    with pytest.raises(NupError):
        encode_tlv(int(TlvType.ICON), b"\0" * 0x100001)
    console_icon = b"\xff\xd8\xff" + b"\0" * 204_000   # a console icon: 150-250 KB, past the old 64 KiB
    encoded = encode_tlv(int(TlvType.ICON), console_icon)
    assert encoded[:8] == struct.pack("<HHI", TlvType.ICON, 0, len(console_icon))
    assert parse_tlvs(memoryview(encoded)) == {int(TlvType.ICON): console_icon}
    assert encode_tlv(int(TlvType.ICON), b"\0" * 0x100000)


def test_tlv_reader_refuses_a_reserved_field_and_an_oversized_length():
    import struct
    with pytest.raises(NupError, match="reserved"):
        parse_tlvs(memoryview(struct.pack("<HHI", 5, 1, 1) + b"x"))
    with pytest.raises(NupError, match="cap"):
        parse_tlvs(memoryview(struct.pack("<HHI", 3, 0, 0x100001)))


@pytest.fixture
def spec_issue():
    def lookup(name: str) -> str:
        return SPEC_ISSUES.get(name)

    return lookup


def test_content_hash_is_sorted_by_raw_path_bytes():
    rows_a = [
        FileRow("b.txt", 1, b"\x01" * 32),
        FileRow("a.txt", 2, b"\x02" * 32),
    ]
    rows_b = [
        FileRow("a.txt", 2, b"\x02" * 32),
        FileRow("b.txt", 1, b"\x01" * 32),
    ]
    assert content_hash(rows_a) == content_hash(rows_b)


def test_content_hash_digest_binds_path_size_and_data():
    row = FileRow("romfs/a", 5, hashlib.sha256(b"data").digest())
    expected = hashlib.sha256(
        b"romfs/a\x00" + (5).to_bytes(8, "little") + hashlib.sha256(b"data").digest()
    ).digest()
    assert content_hash([row]) == expected


def test_records_store_the_full_digest(spec_issue):
    digest = content_hash([FileRow("a", 0, b"\x00" * 32)])
    assert len(digest) == 32
    assert ZERO_DIGEST == bytes(32)
    assert spec_issue("content-hash-width") is not None


def test_localized_records_roundtrip_with_v1_framing():
    encoded = encode_localized({"en-US": b"Title", "ja-JP": "タイトル".encode("utf-8")})
    decoded = parse_localized(memoryview(encoded))
    assert decoded["en-us"] == b"Title"
    assert len(decoded) == 2


def test_localized_record_framing_is_u8_lang_u32_value():
    encoded = encode_localized({"fr": b"value"})
    assert encoded == bytes([2]) + b"fr" + (5).to_bytes(4, "little") + b"value"


def test_file_rows_roundtrip():
    rows = [FileRow("exefs/main", 100, b"\x03" * 32), FileRow("romfs/a", 0, b"\x04" * 32)]
    blob = b"".join(row.encode() for row in rows)
    assert parse_file_rows(memoryview(blob), 2, 0) == rows


def test_scope_prefixes_follow_spec_section_4():
    assert scope_prefix(Kind.BASE) == "base"
    assert scope_prefix(Kind.UPDATE, 458752) == "update/458752"
    assert scope_prefix(Kind.ADDON, index=2) == "addon/2"


def test_align_up_is_0x200():
    assert align_up(0) == 0
    assert align_up(1) == ALIGN
    assert align_up(ALIGN) == ALIGN


def test_spec_issues_registry_is_loaded():
    expected = {
        "string-table-alignment",
        "meta-header-size",
        "content-hash-width",
        "update-content-hash",
        "deleted-manifest-identity",
        "localized-tlv-framing",
        "worked-example-counts",
        "switch2-title-id-namespace",
    }
    assert expected <= set(SPEC_ISSUES)


@pytest.mark.parametrize("tag", ["é", "x" * 256])
def test_localized_tag_must_fit_the_record(tag: str) -> None:
    with pytest.raises(NupError, match="language tag"):
        encode_localized({tag: b"name"})
