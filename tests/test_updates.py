"""Update model: diffs, @deleted manifests, chains, standalone containers."""

from conftest import BASE_TITLE_ID, pack_base, pack_update, tree_of
from nup.layout import Kind, content_hash
from nup.reader import read_container
from nup.tree import parse_deleted_manifest


def test_diff_stores_only_changed_and_added_files(update_nup):
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        names = {row.path for row in record.files}
    assert names == {
        "exefs/main",
        "exefs/main.npdm",
        "romfs/big.bin",
        "romfs/extra.bin",
        "romfs/small.bin",
        "@deleted",
    }


def test_deleted_manifest_lists_base_only_paths(update_dump, base_nup, update_nup):
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        offset = next(
            index
            for index, candidate in enumerate(record.files)
            if candidate.path == "@deleted"
        )
        entry = reader.entries[record.first_entry_index + offset]
        removed = parse_deleted_manifest(reader.read_entry_bytes(entry))
    assert removed == ["romfs/data/table.bin", "romfs/empty.bin", "romfs/todelete.bin"]


def test_update_record_identity_and_binding(update_nup, base_nup):
    with read_container(str(base_nup)) as base_reader:
        base_record = base_reader.meta.packages[0]
        base_identity = base_record.content_hash
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
    assert record.kind is Kind.UPDATE
    assert record.is_diff
    assert record.base_content_hash == base_identity
    assert record.title_id == BASE_TITLE_ID + 0x800
    assert record.application_id == BASE_TITLE_ID


def test_apply_materializes_the_update_tree(update_nup, base_nup, update_dump, tmp_path):
    from nup.cli import main as nup_main

    out = tmp_path / "tree"
    assert nup_main(["extract", str(update_nup), "--base", str(base_nup), "--apply", "-o", str(out)]) == 0
    materialized = tree_of(out)
    expected = tree_of(update_dump)
    for relative, content in expected.items():
        assert materialized[relative] == content
    assert "romfs/todelete.bin" not in materialized
    assert materialized["exefs/main"] == (update_dump / "exefs" / "main").read_bytes()
    assert materialized["romfs/small.bin"] == b"HELLO"


def test_update_container_without_base_requires_base_flag(update_nup, tmp_path):
    from nup.cli import main as nup_main

    assert nup_main(["extract", str(update_nup), "--apply", "-o", str(tmp_path / "t")]) == 1
    assert not (tmp_path / "t").exists()


def test_chain_of_two_diffs(tmp_path):
    """1.0.0 -> 2.0.0 -> 3.2.0 (SPEC §5.1): each diff binds to the tree it lands on."""
    v1 = tmp_path / "v1"
    (v1 / "romfs").mkdir(parents=True)
    (v1 / "romfs" / "common.bin").write_bytes(b"v1 content")
    (v1 / "romfs" / "gone.bin").write_bytes(b"delete me")
    base_nup = pack_base(v1, tmp_path / "v1.nup", title_id=f"{BASE_TITLE_ID:x}")

    v2 = tmp_path / "v2"
    (v2 / "romfs").mkdir(parents=True)
    (v2 / "romfs" / "common.bin").write_bytes(b"v2 content")
    (v2 / "romfs" / "gone.bin").write_bytes(b"delete me")
    (v2 / "romfs" / "added.bin").write_bytes(b"added in v2")
    update_2 = pack_update(v2, base_nup, tmp_path / "v2.nup", 131072)

    v3 = tmp_path / "v3"
    (v3 / "romfs").mkdir(parents=True)
    (v3 / "romfs" / "common.bin").write_bytes(b"v3 content")
    (v3 / "romfs" / "added.bin").write_bytes(b"changed in v3")
    update_3 = pack_update(
        v3, base_nup, tmp_path / "v3.nup", 196608, chain=str(update_2)
    )

    with read_container(str(update_2)) as reader:
        v2_record = reader.meta.packages[0]
    with read_container(str(update_3)) as reader:
        v3_record = reader.meta.packages[0]
    assert v3_record.base_content_hash == v2_record.content_hash

    from nup.cli import main as nup_main

    out = tmp_path / "tree"
    assert nup_main([
        "extract", str(update_3), "--base", str(base_nup), "--chain", str(update_2),
        "--apply", "-o", str(out),
    ]) == 0
    assert (out / "romfs" / "common.bin").read_bytes() == b"v3 content"
    assert (out / "romfs" / "added.bin").read_bytes() == b"changed in v3"
    assert not (out / "romfs" / "gone.bin").exists()


def test_wrong_base_binding_is_rejected(update_nup, base_dump, tmp_path):
    """A diff applied to a tree other than its named base must fail."""
    (base_dump / "romfs" / "mutant.bin").write_bytes(b"this base differs")
    other_base = pack_base(base_dump, tmp_path / "other.nup", title_id=f"{BASE_TITLE_ID:x}")
    with read_container(str(other_base)) as reader:
        other_identity = reader.meta.packages[0].content_hash
    with read_container(str(update_nup)) as reader:
        bound = reader.meta.packages[0].base_content_hash
    assert other_identity != bound

    from nup.cli import main as nup_main

    assert (
        nup_main(["extract", str(update_nup), "--base", str(other_base), "--apply", "-o", str(tmp_path / "t")])
        == 1
    )


def test_update_dump_without_base_packs_as_base(update_dump, tmp_path):
    """SPEC §5.2: a lone update dump becomes a base carrying its revision."""
    from nup.cli import main as nup_main

    out = tmp_path / "mkw-as-base.nup"
    assert (
        nup_main(["pack", str(update_dump), "-o", str(out), "--version=458752", "--display-version=3.2.0"])
        == 0
    )
    with read_container(str(out)) as reader:
        record = reader.meta.packages[0]
        assert len(reader.meta.packages) == 1
        assert record.kind is Kind.BASE
        assert not record.is_diff
        assert record.version == 458752
        assert record.tlvs[TlvType.DISPLAY_VERSION] == b"3.2.0"
        names = {row.path for row in record.files}
    assert "romfs/extra.bin" in names


def test_standalone_holds_base_plus_one_diff(standalone_nup):
    with read_container(str(standalone_nup)) as reader:
        kinds = [record.kind for record in reader.meta.packages]
        base_record, update_record = reader.meta.packages
    assert kinds == [Kind.BASE, Kind.UPDATE]
    assert update_record.base_content_hash == base_record.content_hash
    assert update_record.first_entry_index == 1 + len(base_record.files)


def test_standalone_materializes_like_separate_files(
    standalone_nup, update_dump, tmp_path
):
    from nup.cli import main as nup_main

    out = tmp_path / "tree"
    assert nup_main(["extract", str(standalone_nup), "--apply", "-o", str(out)]) == 0
    materialized = tree_of(out)
    expected = tree_of(update_dump)
    for relative, content in expected.items():
        assert materialized[relative] == content


def test_update_content_hash_is_materialized_identity_not_table_hash(
    update_nup, base_nup
):
    """SPEC_ISSUES['update-content-hash']: a diff's stored identity covers the
    merged tree, not its own diff rows; the file-table hash differs."""
    with read_container(str(base_nup)) as base_reader:
        base_rows = {
            row.path: row for row in base_reader.meta.packages[0].files
        }
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        table_digest = content_hash(record.files)
        merged = dict(base_rows)
        for row in record.files:
            if row.path != "@deleted":
                merged[row.path] = row
        for path in parse_deleted_manifest_data(reader, record):
            merged.pop(path, None)
        materialized_digest = content_hash(sorted(merged.values(), key=lambda r: r.path_bytes))
    assert materialized_digest == record.content_hash
    assert table_digest != record.content_hash


def test_editing_a_standalone_update_keeps_its_materialized_identity(standalone_nup, tmp_path):
    """An update file edited in a standalone container: its identity is the state it
    produces on the container's own base, its @deleted read where the source stores
    it, also when a base edit moves the update's entries; an edited base takes the
    update along (it binds to the edited base), whether or not its files changed."""
    from nup.cli import main as nup_main
    from nup.edit import EditOps, edit_container

    new = tmp_path / "new.bin"
    new.write_bytes(b"edited in place")
    added = tmp_path / "added.bin"
    added.write_bytes(b"one more base file")
    cases = {
        "update.nup": EditOps(replace_files={"update/458752/romfs/extra.bin": str(new)}),
        "both.nup": EditOps(replace_files={"update/458752/romfs/extra.bin": str(new)},
                            add_files={"base/romfs/added.bin": str(added)}),
        "base.nup": EditOps(add_files={"base/romfs/added.bin": str(added)}),
    }
    for name, ops in cases.items():
        out = tmp_path / name
        report = edit_container(str(standalone_nup), str(out), ops)
        # the update beside the base follows it; only updates in other files are warned about
        assert all("in other files" in line for line in report.warnings)
        assert bool(report.warnings) == ("base/romfs/added.bin" in ops.add_files)
        with read_container(str(out)) as reader:
            base, record = reader.meta.packages
            assert record.base_content_hash == base.content_hash
            merged = {row.path: row for row in base.files}
            merged.update({row.path: row for row in record.files if row.path != "@deleted"})
            for path in parse_deleted_manifest_data(reader, record):
                merged.pop(path, None)
            assert record.content_hash == content_hash(sorted(merged.values(), key=lambda r: r.path_bytes))
        tree = tmp_path / f"tree-{name}"
        assert nup_main(["extract", str(out), "--apply", "-o", str(tree)]) == 0
        assert (tree / "romfs/added.bin").exists() == ("base/romfs/added.bin" in ops.add_files)


def parse_deleted_manifest_data(reader, record):
    offset = next(
        index for index, row in enumerate(record.files) if row.path == "@deleted"
    )
    entry = reader.entries[record.first_entry_index + offset]
    return parse_deleted_manifest(reader.read_entry_bytes(entry))


from nup.layout import TlvType  # noqa: E402
