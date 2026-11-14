"""Packing and extraction: container structure, determinism, and roundtrips."""

import hashlib
import struct

import pytest

from nup.layout import ENTRY_SIZE

from conftest import BASE_TITLE_ID, make_dump, pack_base, tree_of
from nup.errors import NupError
from nup.layout import META_HEADER_SIZE, TlvType
from nup.reader import read_container


def test_first_entry_is_meta_nup(base_nup):
    with read_container(str(base_nup)) as reader:
        assert reader.entries[0].name == "meta.nup"
        assert reader.entry_count == len(reader.meta.packages[0].files) + 1


def test_entry_data_is_0x200_aligned_in_absolute_terms(base_nup):
    """SPEC §1 rule 4: entries are 0x200-aligned so the file mmaps cleanly.

    This holds only because the writer pads the string table so the data
    region itself starts on a 0x200 boundary (see SPEC_ISSUES).
    """
    with read_container(str(base_nup)) as reader:
        assert reader.data_start % 0x200 == 0
        for entry in reader.entries:
            assert (reader.data_start + entry.data_offset) % 0x200 == 0
            assert entry.data_offset % 0x200 == 0


def test_string_table_size_field_is_padded(base_nup):
    """The header's string table size must include the alignment padding so
    generic HFS0 readers land on the data region."""
    with open(base_nup, "rb") as handle:
        _magic, count, table_size, _reserved = struct.unpack("<4sIII", handle.read(0x10))
    assert (0x10 + ENTRY_SIZE * count + table_size) % 0x200 == 0


def test_meta_record_header_size_is_0x40_with_zero_pad(base_nup):
    with read_container(str(base_nup)) as reader:
        meta = reader.meta_raw
        magic, header_size = struct.unpack_from("<4sH", meta)
        assert magic == b"NUP\x02"
        assert header_size == META_HEADER_SIZE
        assert meta[0x3C:0x40] == b"\x00" * 4


def test_dump_artifacts_are_not_packed(base_dump, tmp_path):
    out = pack_base(base_dump, tmp_path / "base.nup", title_id=f"{BASE_TITLE_ID:x}")
    with read_container(str(out)) as reader:
        names = [entry.name for entry in reader.entries]
    assert not any(name.endswith(".listing") for name in names)
    assert "base/romfs/junk.listing" not in names


def test_pack_extract_roundtrip_is_byte_exact(base_dump, tmp_path):
    out = pack_base(base_dump, tmp_path / "base.nup", title_id=f"{BASE_TITLE_ID:x}")
    extracted = tmp_path / "out"
    from nup.cli import main as nup_main

    assert nup_main(["extract", str(out), "-o", str(extracted)]) == 0
    expected = {name: data for name, data in tree_of(base_dump).items() if not name.endswith(".listing")}
    extracted_files = tree_of(extracted / "base")
    assert extracted_files == expected
    for relative, content in extracted_files.items():
        assert content == (base_dump / relative).read_bytes()


def test_zero_size_files_and_prefix_hash_convention(base_dump, tmp_path):
    out = pack_base(base_dump, tmp_path / "base.nup", title_id=f"{BASE_TITLE_ID:x}")
    with read_container(str(out)) as reader:
        empty = reader.entry("base/romfs/empty.bin")
        assert empty.size == 0
        assert empty.hashed_size == 0
        assert empty.prefix_hash == hashlib.sha256(b"").digest()
        big = reader.entry("base/romfs/big.bin")
        assert big.hashed_size == 0x200
        assert big.prefix_hash == hashlib.sha256(
            (base_dump / "romfs" / "big.bin").read_bytes()[:0x200]
        ).digest()


def test_packing_is_deterministic(base_dump, tmp_path):
    first = pack_base(base_dump, tmp_path / "a.nup", title_id=f"{BASE_TITLE_ID:x}")
    second = pack_base(base_dump, tmp_path / "b.nup", title_id=f"{BASE_TITLE_ID:x}")
    assert first.read_bytes() == second.read_bytes()


def test_case_sensitive_names_survive(base_dump, tmp_path):
    from nup.tree import case_insensitive

    if case_insensitive(str(base_dump / "romfs")):
        pytest.skip("this folder folds case: it cannot hold the two dump files (default Windows and macOS)")
    target = base_dump / "romfs" / "Case.bin"
    target.write_bytes(b"upper")
    (base_dump / "romfs" / "case.bin").write_bytes(b"lower")
    out = pack_base(base_dump, tmp_path / "base.nup", title_id=f"{BASE_TITLE_ID:x}")
    with read_container(str(out)) as reader:
        assert reader.read_file("base/romfs/Case.bin") == b"upper"
        assert reader.read_file("base/romfs/case.bin") == b"lower"


def test_unicode_and_deep_paths_survive(base_dump, tmp_path):
    deep = base_dump / "romfs" / "群" / "pack" / "テスト.pack.zs"
    deep.parent.mkdir(parents=True, exist_ok=True)
    deep.write_bytes(b"unicode payload")
    out = pack_base(base_dump, tmp_path / "base.nup", title_id=f"{BASE_TITLE_ID:x}")
    with read_container(str(out)) as reader:
        assert reader.read_file("base/romfs/群/pack/テスト.pack.zs") == b"unicode payload"


def test_extract_repack_is_identical(base_dump, tmp_path):
    from nup.pack import pack_base_container

    first = pack_base(base_dump, tmp_path / "a.nup", title_id=f"{BASE_TITLE_ID:x}")
    extracted = tmp_path / "out"
    from nup.cli import main as nup_main

    nup_main(["extract", str(first), "-o", str(extracted)])
    second = tmp_path / "b.nup"
    pack_base_container(
        str(second), str(extracted / "base"), title_id=BASE_TITLE_ID
    )
    assert first.read_bytes() == second.read_bytes()


def test_identity_tlvs_and_build_id_are_recorded(base_nup):
    with read_container(str(base_nup)) as reader:
        record = reader.meta.packages[0]
        assert record.tlvs[TlvType.TITLE_NAME] == b"Test Title"
        assert record.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.0"
        build_id = bytes.fromhex(record.tlvs[TlvType.BUILD_ID].decode())
        assert build_id[:9] == b"base-main"


def test_addon_container_groups_all_addons(base_dump, addon_dump, tmp_path):
    from nup.pack import pack_addon_container

    second = make_dump(tmp_path / "dkc1", title_id=BASE_TITLE_ID + 0x1001, seed=b"b")
    (second / "romfs" / "two.bin").write_bytes(b"two")
    out = tmp_path / "test.dlc.nup"
    records = pack_addon_container(
        str(out), [str(addon_dump), str(second)], application_id=BASE_TITLE_ID
    )
    assert [record.title_id for record in records] == [
        BASE_TITLE_ID + 0x1001,
        BASE_TITLE_ID + 0x1002,
    ]
    with read_container(str(out)) as reader:
        record = reader.meta.packages[0]
        assert record.kind.name == "ADDON"
        assert record.application_id == BASE_TITLE_ID
        assert reader.entry("addon/1/romfs/level.pack.zs")
        assert reader.entry("addon/2/romfs/two.bin")
        from nup.verify import verify_container

        verify_container(reader, "full")


def test_container_rejects_unsafe_paths_on_extract(base_dump, tmp_path):
    """Entry paths containing '..' must fail closed instead of escaping."""
    from nup.tree import validate_container_path

    for bad in ("../escape", "a/../../b", "/abs", "a//b", "back\\slash"):
        with pytest.raises(NupError):
            validate_container_path(bad)


def test_reused_base_entries_in_standalone_share_bytes(standalone_nup):
    """Per-entry bytes are identical across layouts (SPEC §8)."""
    with read_container(str(standalone_nup)) as reader:
        base_entry = reader.entry("base/exefs/main")
        assert base_entry.size > 0
        data = reader.read_file("base/exefs/main")
        assert hashlib.sha256(data[:0x200]).digest() == base_entry.prefix_hash


def test_generic_hfs0_parser_reads_the_container(base_nup):
    """An HFS0-era reader must enumerate entries without knowing NUP (SPEC §2)."""
    with open(base_nup, "rb") as handle:
        magic, count, table_size, reserved = struct.unpack("<4sIII", handle.read(0x10))
        assert magic == b"HFS0"
        assert reserved == 0
        entries = []
        for _ in range(count):
            entries.append(struct.unpack("<QQIIQ32s", handle.read(0x40)))
        table = handle.read(table_size)
    names = []
    for index, (data_offset, size, name_offset, hashed_size, _res, prefix_hash) in enumerate(entries):
        end = table.index(b"\x00", name_offset)
        names.append(table[name_offset:end].decode())
        if names[-1] == "meta.nup":
            assert hashed_size == 0, "meta.nup opts out of the prefix-hash cycle (SPEC_ISSUES)"
        else:
            assert hashed_size == min(size, 0x200)
        assert len(prefix_hash) == 32
    assert names[0] == "meta.nup"
