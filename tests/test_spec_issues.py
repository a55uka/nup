"""Where SPEC.md contradicts itself, and what the tool does about it.

Each test pins one documented interpretation from nup.layout.SPEC_ISSUES.
If a test here fails, either the tool drifted from its resolution or the
spec was updated — either way the pair must be revisited together.
"""

import struct

import pytest

from conftest import BASE_TITLE_ID, make_dump, pack_base, pack_update
from nup.layout import SPEC_ISSUES
from nup.reader import read_container


def test_issue_string_table_alignment(base_nup):
    """SPEC §2 says the string table is padded 'out to a 0x200 boundary', but
    that alone cannot place entry data on 0x200 file offsets, because
    0x10 + 0x40*N is not generically 0x200-aligned (N=6 -> 0x190).

    Resolution: pad the string table until the data region STARTS on a
    0x200 boundary and store the padded size.
    """
    with open(base_nup, "rb") as handle:
        _magic, count, table_size, _reserved = struct.unpack("<4sIII", handle.read(0x10))
    literal_table_end = 0x10 + 0x40 * count + (table_size & ~0x1FF)
    assert literal_table_end % 0x200 != 0, "the test fixture lost its discriminating N"
    assert (0x10 + 0x40 * count + table_size) % 0x200 == 0
    with read_container(str(base_nup)) as reader:
        assert reader.data_start % 0x200 == 0


def test_issue_meta_header_size_vs_field_list(base_nup):
    """SPEC §3 lists meta fields ending at 0x3C yet declares the fixed part
    '0x40 in v2.0'.  Resolution: write 0x40 and zero bytes [0x3C, 0x40);
    accept header_size >= 0x3C when reading."""
    with read_container(str(base_nup)) as reader:
        header_size, = struct.unpack_from("<H", reader.meta_raw, 4)
        assert header_size == 0x40
        assert reader.meta_raw[0x3C:0x40] == b"\x00" * 4
        first_record_at_header_size = struct.unpack_from(
            "<BBH", reader.meta_raw, header_size
        )
        assert first_record_at_header_size[0] == 0  # kind base


def test_issue_content_hash_width(base_nup):
    """RATIFIED: the record fields carry the full 0x20-byte digest; the
    draft's u64 truncation is gone (fixed record part 0x38 -> 0x68)."""
    from nup.layout import content_hash

    with read_container(str(base_nup)) as reader:
        record = reader.meta.packages[0]
        assert len(record.content_hash) == 32
        assert record.content_hash == content_hash(record.files)
        assert record.base_content_hash == bytes(32)


def test_issue_meta_prefix_hash_cycle(base_nup):
    """SPEC §2/§3 cannot be packed as written: the 0x18 header hash covers the
    entry table, whose entry 0 carries meta.nup's prefix hash over the first
    0x200 bytes of a record that itself contains the header hash — a cycle.

    Resolution: meta.nup is stored with hashed size 0 (hash of empty input),
    which keeps 'hash covers the first hashed-size bytes' literally true and
    makes generic HFS0 readers treat meta as an unhashed entry instead of a
    corrupt one."""
    with read_container(str(base_nup)) as reader:
        meta_entry = reader.entries[0]
        assert meta_entry.hashed_size == 0
        assert meta_entry.prefix_hash == __import__("hashlib").sha256(b"").digest()
        assert meta_entry.size >= 0x200


def test_issue_update_content_hash_semantics(update_nup, base_nup):
    """SPEC §5.1 wants a diff's base content hash to equal the content hash of
    the tree it lands on, and §6.2 calls that what an emulator compares after
    materializing.  A hash over the diff's own rows cannot satisfy either.
    Resolution: update identity = merged (materialized) state; @deleted is
    consumed and excluded."""
    from tests.test_updates import test_update_content_hash_is_materialized_identity_not_table_hash

    test_update_content_hash_is_materialized_identity_not_table_hash(update_nup, base_nup)


def test_issue_deleted_manifest_identity(update_nup):
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        assert "@deleted" in {row.path for row in record.files}
        assert "@deleted" not in {
            reader.entry_name_of(record, offset).rsplit("/", 1)[-1]
            for offset in range(len(record.files))
        } - {"@deleted"}


def test_issue_worked_example_arithmetic():
    """SPEC §8 says the update container has 3,452 entries while listing meta
    + 2,145 added + 1,306 changed + @deleted (3,453), and the prose counts
    1,310 changed.  The spec's own numbers disagree; real-dump tests record
    the actual counts (tests/test_real_dumps.py)."""
    assert "worked-example-counts" in SPEC_ISSUES


def test_issue_switch2_title_ids(base_dump, tmp_path):
    """Switch 2 programs have 0400… ids, which their signed ACID requires, and
    update dumps repeat the base id.  Resolution (revised 2026-11-13): ids stay
    as the console has them, in their range; patch ids are application + 0x800."""
    from nup.identity import parse_npdm_program_id, title_number

    assert parse_npdm_program_id((base_dump / "exefs" / "main.npdm").read_bytes()) == BASE_TITLE_ID
    switch2 = BASE_TITLE_ID & 0x00FF_FFFF_FFFF_FFFF | 0x0400_0000_0000_0000
    s2_base = make_dump(tmp_path / "s2-base", title_id=switch2, seed=b"s2 base")
    (s2_base / "romfs" / "a.bin").write_bytes(b"base")
    s2_update = make_dump(tmp_path / "s2-update", title_id=switch2, seed=b"s2 update")   # the base id again
    (s2_update / "romfs" / "a.bin").write_bytes(b"update")
    base_out = pack_base(s2_base, tmp_path / "s2.nup")
    update_out = pack_update(s2_update, base_out, tmp_path / "s2.update.65536.nup", 65536)
    with read_container(str(base_out)) as reader:
        assert reader.meta.packages[0].title_id == switch2
    with read_container(str(update_out)) as reader:
        record = reader.meta.packages[0]
        assert (record.title_id, record.application_id) == (switch2 + 0x800, switch2)
    assert title_number(0x040015100B514001) == title_number(0x010015100B514000) + 1   # a Switch 2 Edition's program 1


def test_two_package_containers_must_be_base_plus_update(base_dump, tmp_path):
    """SPEC §5.3: P = 2 with kind 0 + kind 1 is the only two-package shape."""
    from nup.layout import Flags, Kind
    from nup.model import PackageRecord, validate_grouping

    validate_grouping(
        [
            PackageRecord(kind=Kind.BASE, flags=0, title_id=1, application_id=0,
                          version=0, first_entry_index=1),
            PackageRecord(kind=Kind.UPDATE, flags=Flags.DIFF, title_id=0x801,
                          application_id=1, version=1, first_entry_index=2),
        ]
    )
    with pytest.raises(Exception):
        validate_grouping(
            [
                PackageRecord(kind=Kind.BASE, flags=0, title_id=1, application_id=0,
                              version=0, first_entry_index=1),
                PackageRecord(kind=Kind.BASE, flags=0, title_id=2, application_id=0,
                              version=0, first_entry_index=2),
            ]
        )


def test_addon_containers_hold_any_number_of_addons():
    """SPEC §3: a dlc.nup holds every add-on for the title (P >= 1)."""
    from nup.model import validate_grouping

    validate_grouping(addon_records(2))
    validate_grouping(addon_records(5))


def addon_records(count):
    from nup.layout import Kind
    from nup.model import PackageRecord

    first_index = 1
    records = []
    for position in range(count):
        record = PackageRecord(kind=Kind.ADDON, flags=0, title_id=0x1001 + position,
                               application_id=1, version=0, first_entry_index=first_index)
        first_index += 1
        records.append(record)
    return records


def test_mixed_groups_are_rejected():
    from nup.layout import Kind
    from nup.model import PackageRecord, validate_grouping

    with pytest.raises(Exception):
        validate_grouping(
            [
                PackageRecord(kind=Kind.BASE, flags=0, title_id=1, application_id=0,
                              version=0, first_entry_index=1),
                PackageRecord(kind=Kind.ADDON, flags=0, title_id=0x1001, application_id=1,
                              version=0, first_entry_index=2),
            ]
        )
