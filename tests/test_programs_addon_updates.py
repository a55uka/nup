"""Multi-program titles (SPEC §4.1), add-on updates (§5.4), and the dump
layouts of the extractors (discover)."""

import struct
from pathlib import Path

import pytest

from conftest import make_dump, nup_main
from nup.discover import discover_dumps
from nup.errors import NupError
from nup.layout import Kind
from nup.reader import read_container

APP = 0x010015100B514000
S2_PROGRAM = 0x040015100B514001
ADDON = APP + 0x1001
PATCH = ADDON + 0x800


def cnmt(record_id: int, version: int, kind: int, extended: bytes) -> bytes:
    """A content meta record in switchbrew's layout, without contents."""
    return (struct.pack("<QIBBHHHB3xI4x", record_id, version, kind, 1, len(extended), 0, 0, 0, 0)
            + extended + bytes(0x20))


def put(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture
def console_bundle(tmp_path: Path) -> Path:
    """OunceCake's layout: program/<index>/, dlc/<id>/<v>/base and updates/<v>/."""
    root = tmp_path / "Wonder"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    put(root / "base/program/0/romfs/shared.bin", b"shared" * 50)
    make_dump(root / "updates/327680/program/0", title_id=APP, seed=b"upd")
    put(root / "updates/327680/program/0/romfs/shared.bin", b"changed" * 50)
    make_dump(root / "updates/327680/program/1", title_id=S2_PROGRAM, seed=b"s2")
    put(root / "updates/327680/program/1/romfs/s2.bin", b"switch 2" * 50)
    addon = root / "dlc" / f"{ADDON:016x}" / "0"
    put(addon / "base/program/0/romfs/a.bin", b"addon" * 100)
    put(addon / "base/program/0/romfs/gone.bin", b"removed by the patch")
    put(addon / "base/program/0/meta/AddOnContent.cnmt",
        cnmt(ADDON, 0, 0x82, struct.pack("<QIB3xQ", APP, 196608, 0, PATCH)))
    put(addon / "updates/131072/program/0/romfs/a.bin", b"addon" * 100)
    put(addon / "updates/131072/program/0/romfs/new.bin", b"patched")
    put(addon / "updates/131072/program/0/meta/DataPatch.cnmt",
        cnmt(PATCH, 131072, 0x84, struct.pack("<QQII8x", ADDON, APP, 327680, 0)))
    return root


def packages(path: Path) -> list[tuple]:
    with read_container(str(path)) as reader:
        return [(r.kind, r.title_id, r.version, r.program_index, r.application_id)
                for r in reader.meta.packages], reader.meta.feature_flags


def test_discovery_of_the_console_layout(console_bundle: Path) -> None:
    found = discover_dumps(str(console_bundle))
    assert Path(found.base_dir) == console_bundle / "base" / "program" / "0"
    assert sorted(found.updates) == [327680]
    assert sorted(found.programs) == [1] and found.programs[1].base_dir is None
    assert [p.title_id for p in found.addon_patches] == [PATCH]
    assert found.addon_patches[0].addon_title_id == ADDON
    assert list(found.addon_title_ids.values()) == [ADDON]


def test_every_program_is_packed(console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle)]) == 0
    assert sorted(p.name for p in tmp_path.glob("*.nup")) == [
        "Wonder.nup", "Wonder.program1.standalone.update.327680.nup", "Wonder.update.327680.nup"]
    program1 = tmp_path / "Wonder.program1.standalone.update.327680.nup"
    records, flags = packages(program1)
    # program 1 arrived with the update: packed as its base (SPEC §5.2), bound to the application
    assert records == [(Kind.BASE, S2_PROGRAM, 327680, 1, APP)]
    assert flags == 0
    assert packages(tmp_path / "Wonder.nup") == ([(Kind.BASE, APP, 0, 0, 0)], 0)
    assert nup_main(["verify", str(program1), "--level", "full"]) == 0


def test_every_container_goes_beside_the_out_file(console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    """-o names the base: the updates and the other programs go beside it, named after it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dist").mkdir()
    assert nup_main(["pack", str(console_bundle), "-o", "dist/Game.nup"]) == 0
    assert list(tmp_path.glob("*.nup")) == []
    assert sorted(p.name for p in (tmp_path / "dist").glob("*.nup")) == [
        "Game.nup", "Game.program1.standalone.update.327680.nup", "Game.update.327680.nup"]


def test_standalone_and_update_packs_name_the_console_layout_after_the_bundle(
        console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    """updates/<v>/program/0/ names nothing: program 0's containers take the bundle's name
    in every flow, as the other programs' do."""
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle), "--kind", "standalone"]) == 0
    assert sorted(p.name for p in tmp_path.glob("*.nup")) == [
        "Wonder.program1.standalone.update.327680.nup", "Wonder.standalone.update.327680.nup"]
    assert nup_main(["pack", str(console_bundle), "-o", "Wonder.nup"]) == 0
    (tmp_path / "Wonder.update.327680.nup").unlink()
    assert nup_main(["pack", str(console_bundle), "--base", "Wonder.nup"]) == 0
    assert (tmp_path / "Wonder.update.327680.nup").is_file()


def test_a_standalone_pack_packs_every_program_standalone(tmp_path: Path, monkeypatch) -> None:
    """--kind standalone: program 1's base and its update of that version travel together
    as program 0's do, not as an update that needs a base from elsewhere."""
    root = tmp_path / "Kirby"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    make_dump(root / "base/program/1", title_id=APP + 1, seed=b"s2")
    make_dump(root / "updates/65536/program/0", title_id=APP, seed=b"upd")
    make_dump(root / "updates/65536/program/1", title_id=APP + 1, seed=b"s2 upd")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--kind", "standalone"]) == 0
    assert sorted(p.name for p in tmp_path.glob("*.nup")) == [
        "Kirby.program1.standalone.update.65536.nup", "Kirby.standalone.update.65536.nup"]
    assert packages(tmp_path / "Kirby.program1.standalone.update.65536.nup")[0] == [
        (Kind.BASE, APP + 1, 0, 1, APP), (Kind.UPDATE, APP + 1 + 0x800, 65536, 1, APP)]


def test_addon_update(console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle), "--kind", "dlc"]) == 0
    dlc, dlc_update = tmp_path / "Wonder.dlc.nup", tmp_path / "Wonder.dlc.update.nup"
    assert packages(dlc) == ([(Kind.ADDON, ADDON, 0, 0, APP)], 0)
    assert packages(dlc_update) == ([(Kind.ADDON_UPDATE, PATCH, 131072, 0, APP)], 0)
    with read_container(str(dlc)) as base, read_container(str(dlc_update)) as patch:
        assert patch.meta.packages[0].base_content_hash == base.meta.packages[0].content_hash
    out = tmp_path / "materialized"
    assert nup_main(["extract", str(dlc_update), "-o", str(out), "--apply", "--base", str(dlc)]) == 0
    tree = out / "addon" / "1" / "romfs"
    patched = console_bundle / "dlc" / f"{ADDON:016x}" / "0" / "updates/131072/program/0/romfs"
    assert sorted(p.name for p in tree.iterdir()) == sorted(p.name for p in patched.iterdir())
    assert (tree / "new.bin").read_bytes() == b"patched"


def test_yoink_layout(tmp_path: Path) -> None:
    """Yoink: switch2/updates/<v>/ is program 1, dlc/<data patch id>/<v>/ a data patch,
    and a romfs.img beside romfs/ is not packed."""
    root = tmp_path / "Game"
    make_dump(root / "base", title_id=APP, seed=b"base")
    make_dump(root / "updates/327680", title_id=APP, seed=b"upd")
    put(root / "updates/327680/romfs.img", b"image")
    make_dump(root / "switch2/updates/327680", title_id=S2_PROGRAM, seed=b"s2")
    put(root / "dlc" / f"{ADDON:016x}" / "0/romfs/a.bin", b"addon")
    put(root / "dlc" / f"{PATCH:016x}" / "131072/romfs/a.bin", b"patched")
    found = discover_dumps(str(root))
    assert sorted(found.programs[1].updates) == [327680]
    assert [(p.title_id, p.addon_title_id, p.version) for p in found.addon_patches] == [(PATCH, ADDON, 131072)]
    out = tmp_path / "u.nup"
    assert nup_main(["pack", str(root / "updates/327680"), "-o", str(out), "--version", "327680",
                     "--title-id", f"{APP:x}"]) == 0
    with read_container(str(out)) as reader:
        assert not any(row.path == "romfs.img" for row in reader.meta.packages[0].files)


def test_flattened_program_folder(tmp_path: Path, monkeypatch) -> None:
    """updates/<v>/program1/ beside exefs/ and romfs/ (a flattened dump that keeps a Switch 2
    Edition's program 1 with its version): program 1, and not in program 0's files."""
    root = tmp_path / "Kirby"
    make_dump(root / "base", title_id=APP, seed=b"base")
    make_dump(root / "updates/65536", title_id=APP, seed=b"upd")
    make_dump(root / "updates/65536/program1", title_id=S2_PROGRAM, seed=b"s2")
    put(root / "updates/65536/program1/romfs/s2.bin", b"switch 2" * 50)
    put(root / "updates/65536/programX/romfs/x.bin", b"not a program")   # no index: program 0's
    found = discover_dumps(str(root))
    assert sorted(found.updates) == [65536] and sorted(found.programs) == [1]
    assert Path(found.programs[1].updates[65536]) == root / "updates/65536/program1"
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--name", "Kirby"]) == 0
    with read_container(str(tmp_path / "Kirby.update.65536.nup")) as reader:
        paths = {row.path for row in reader.meta.packages[0].files}
    assert not any(p.startswith("program1/") for p in paths) and "programX/romfs/x.bin" in paths
    records, _flags = packages(tmp_path / "Kirby.program1.standalone.update.65536.nup")
    assert records == [(Kind.BASE, S2_PROGRAM, 65536, 1, APP)]


def test_a_zero_padded_program_folder_is_a_program(tmp_path: Path) -> None:
    root = tmp_path / "Pad"
    make_dump(root / "base", title_id=APP, seed=b"base")
    make_dump(root / "base/program01", title_id=APP + 1, seed=b"one")
    found = discover_dumps(str(root))
    assert sorted(found.programs) == [1] and Path(found.programs[1].base_dir) == root / "base/program01"


def test_flattened_programs_share_the_bundles_name(tmp_path: Path, monkeypatch) -> None:
    """Without --name, program 0 of a title with several programs is named after the
    bundle as program 1 is, not after its base/ folder."""
    root = tmp_path / "Kirby"
    make_dump(root / "base", title_id=APP, seed=b"base")
    make_dump(root / "base/program1", title_id=APP + 1, seed=b"s2")
    make_dump(root / "updates/65536", title_id=APP, seed=b"upd")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root)]) == 0
    assert sorted(p.name for p in tmp_path.glob("*.nup")) == [
        "Kirby.nup", "Kirby.program1.nup", "Kirby.update.65536.nup"]


def test_content_folder_with_a_program_folder(tmp_path: Path, monkeypatch, capsys) -> None:
    """A single content folder (exefs/ and romfs/ at the top) with program1/ beside them:
    program 1 packs into its own container, not into program 0's and not dropped."""
    root = tmp_path / "Kirby"
    make_dump(root, title_id=APP, seed=b"base")
    make_dump(root / "program1", title_id=S2_PROGRAM, seed=b"s2")
    found = discover_dumps(str(root))
    assert found.mode == "content" and Path(found.programs[1].base_dir) == root / "program1"
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root)]) == 0
    with read_container(str(tmp_path / "Kirby.nup")) as reader:
        assert not any(row.path.startswith("program1/") for row in reader.meta.packages[0].files)
    assert packages(tmp_path / "Kirby.program1.nup")[0] == [(Kind.BASE, S2_PROGRAM, 0, 1, APP)]
    # --base diffs program 0 only: the other program is named, not silently skipped
    capsys.readouterr()
    assert nup_main(["pack", str(root), "--base", str(tmp_path / "Kirby.nup"), "--version", "65536",
                     "-o", str(tmp_path / "u.nup")]) == 0
    assert "program 1, not packed" in capsys.readouterr().err


def test_version_folder_with_only_another_program(tmp_path: Path) -> None:
    """updates/<v>/ holding only program1/ is program 1's update, not an empty one of program 0;
    base/ holding only program1/ is no base of program 0."""
    root = tmp_path / "Kirby"
    make_dump(root / "base/program1", title_id=S2_PROGRAM, seed=b"s2")
    make_dump(root / "updates/65536", title_id=APP, seed=b"upd")
    make_dump(root / "updates/131072/program1", title_id=S2_PROGRAM, seed=b"s2 upd")
    found = discover_dumps(str(root))
    assert found.base_dir is None and sorted(found.updates) == [65536]
    assert Path(found.programs[1].base_dir) == root / "base/program1"
    assert sorted(found.programs[1].updates) == [131072]


def test_program_only_bundle_needs_the_application_id(tmp_path: Path, monkeypatch, capsys) -> None:
    """A bundle with only Yoink's switch2/ program cannot name its application by itself."""
    root = tmp_path / "Only2"
    make_dump(root / "switch2/updates/327680", title_id=S2_PROGRAM, seed=b"s2")
    (root / "updates").mkdir()
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root)]) == 1
    assert "--title-id" in capsys.readouterr().err
    assert nup_main(["pack", str(root), "--title-id", f"{APP:x}"]) == 0
    records, _flags = packages(tmp_path / "Only2.program1.standalone.update.327680.nup")
    assert records == [(Kind.BASE, S2_PROGRAM, 327680, 1, APP)]


def test_tar_mode_refused(tmp_path: Path) -> None:
    root = tmp_path / "Game"
    put(root / "base/program/0/exefs/main.npdm", b"META")
    put(root / "base/program/0/romfs.tar", b"tar")
    with pytest.raises(NupError, match="tar -xf romfs.tar -C romfs"):
        discover_dumps(str(root))


def test_program_index_rules() -> None:
    """Only bases and updates have a program; another program's base names its application."""
    from nup.model import PackageRecord, validate_record_flags
    with pytest.raises(NupError, match="only base and update"):
        validate_record_flags(PackageRecord(kind=Kind.ADDON, flags=0, title_id=ADDON, application_id=APP,
                                            version=0, first_entry_index=1, program_index=1))
    with pytest.raises(NupError, match="no application id"):
        validate_record_flags(PackageRecord(kind=Kind.BASE, flags=0, title_id=APP + 1, application_id=0,
                                            version=0, first_entry_index=1, program_index=1))


def add_second_patch(console_bundle: Path) -> Path:
    """A v196608 data patch of ADDON, chained on v131072."""
    patch = console_bundle / "dlc" / f"{ADDON:016x}" / "0" / "updates/196608/program/0"
    put(patch / "romfs/a.bin", b"ADDON" * 100)
    put(patch / "romfs/new.bin", b"patched")
    put(patch / "meta/DataPatch.cnmt", cnmt(PATCH, 196608, 0x84, struct.pack("<QQII8x", ADDON, APP, 327680, 0)))
    return patch


def test_editing_an_addon_update_keeps_its_chain(console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    """A TLV edit leaves every add-on update's materialized identity as it was, so the
    second patch still chains on the first; a file edit is refused."""
    add_second_patch(console_bundle)
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle), "--kind", "dlc"]) == 0
    dlc, dlc_update = tmp_path / "Wonder.dlc.nup", tmp_path / "Wonder.dlc.update.nup"
    with read_container(str(dlc_update)) as reader:
        before = [r.content_hash for r in reader.meta.packages]
    assert nup_main(["edit", str(dlc_update), "--package", "0", "--set-tlv", "name=Wonder DLC"]) == 0
    with read_container(str(dlc_update)) as reader:
        assert [r.content_hash for r in reader.meta.packages] == before
    out = tmp_path / "materialized"
    assert nup_main(["extract", str(dlc_update), "-o", str(out), "--apply", "--base", str(dlc)]) == 0
    assert (out / "addon/1/romfs/a.bin").read_bytes() == b"ADDON" * 100
    extra = tmp_path / "extra.bin"
    extra.write_bytes(b"extra")
    assert nup_main(["edit", str(dlc_update), "--package", "0",
                     "--add-file", f"addonupdate/2049/131072/romfs/x.bin={extra}"]) == 1


def test_data_patch_without_data_id(console_bundle: Path) -> None:
    """A CNMT whose DataId is 0 names no add-on: the folder's id stands."""
    meta = console_bundle / "dlc" / f"{ADDON:016x}" / "0" / "updates/131072/program/0/meta/DataPatch.cnmt"
    meta.write_bytes(cnmt(PATCH, 131072, 0x84, struct.pack("<QQII8x", 0, APP, 327680, 0)))
    found = discover_dumps(str(console_bundle))
    assert [(p.title_id, p.addon_title_id) for p in found.addon_patches] == [(PATCH, ADDON)]


def test_patches_land_on_their_own_addon(tmp_path: Path, monkeypatch) -> None:
    """Two add-ons with the same files share a content hash: each data patch lands
    on the add-on its id names."""
    root = tmp_path / "Twins"
    make_dump(root / "base", title_id=APP, seed=b"base")
    for addon in (ADDON, ADDON + 1):
        put(root / "dlc" / f"{addon:016x}" / "0/romfs/a.bin", b"same")
    put(root / "dlc" / f"{ADDON + 1 + 0x800:016x}" / "65536/romfs/a.bin", b"second patched")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--kind", "dlc"]) == 0
    out = tmp_path / "materialized"
    assert nup_main(["extract", "Twins.dlc.update.nup", "-o", str(out), "--apply",
                     "--base", "Twins.dlc.nup"]) == 0
    assert (out / "addon/1/romfs/a.bin").read_bytes() == b"same"
    assert (out / "addon/2/romfs/a.bin").read_bytes() == b"second patched"


def test_several_versions_of_a_lone_patch(tmp_path: Path, monkeypatch) -> None:
    """Without its add-on, the oldest data patch packs as the add-on and the newer
    ones chain on it as add-on updates."""
    root = tmp_path / "Lone"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{PATCH:016x}" / "65536/romfs/a.bin", b"v1")
    put(root / "dlc" / f"{PATCH:016x}" / "131072/romfs/a.bin", b"v2")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--kind", "dlc", "-o", str(out_dir / "Lone.dlc.nup")]) == 0
    assert packages(out_dir / "Lone.dlc.nup")[0] == [(Kind.ADDON, ADDON, 65536, 0, APP)]
    # the add-on update container goes beside the -o file
    assert packages(out_dir / "Lone.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, PATCH, 131072, 0, APP)]
    tree = tmp_path / "tree"
    assert nup_main(["extract", str(out_dir / "Lone.dlc.update.nup"), "-o", str(tree), "--apply",
                     "--base", str(out_dir / "Lone.dlc.nup")]) == 0
    assert (tree / "addon/1/romfs/a.bin").read_bytes() == b"v2"


def test_title_id_flag_moves_a_lone_patchs_chain_along(tmp_path: Path, monkeypatch) -> None:
    """--title-id renames the add-on a lone data patch stands in for: the newer
    versions chained on it follow it to the new id."""
    root = tmp_path / "Lone"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{PATCH:016x}" / "65536/romfs/a.bin", b"v1")
    put(root / "dlc" / f"{PATCH:016x}" / "131072/romfs/a.bin", b"v2")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--kind", "dlc", "--title-id", f"{ADDON + 5:x}"]) == 0
    assert packages(tmp_path / "Lone.dlc.nup")[0] == [(Kind.ADDON, ADDON + 5, 65536, 0, APP)]
    # the newer version's id follows too: still its add-on's + 0x800 (SPEC §5.4)
    assert packages(tmp_path / "Lone.dlc.update.nup")[0] == [
        (Kind.ADDON_UPDATE, ADDON + 5 + 0x800, 131072, 0, APP)]
    tree = tmp_path / "tree"
    assert nup_main(["extract", "Lone.dlc.update.nup", "-o", str(tree), "--apply",
                     "--base", "Lone.dlc.nup"]) == 0
    assert (tree / "addon/6/romfs/a.bin").read_bytes() == b"v2"


def test_unnamed_addons_skip_the_named_indexes(tmp_path: Path) -> None:
    from nup.pack import pack_addon_container

    named, unnamed = tmp_path / "b-named", tmp_path / "a-unnamed"
    put(named / "romfs/n.bin", b"named")
    put(unnamed / "romfs/u.bin", b"unnamed")
    records = pack_addon_container(str(tmp_path / "x.dlc.nup"), [str(named), str(unnamed)],
                                   application_id=APP, title_ids=[ADDON, None])
    assert sorted(r.title_id for r in records) == [ADDON, ADDON + 1]
    with pytest.raises(NupError, match="given twice"):
        pack_addon_container(str(tmp_path / "y.dlc.nup"), [str(named), str(unnamed)],
                             application_id=APP, title_ids=[ADDON, ADDON])


def test_console_layout_with_a_data_content_names_by_the_bundle(tmp_path: Path, monkeypatch) -> None:
    """base/program/0/program/ (a data content shares index 0) is named after the bundle."""
    root = tmp_path / "Wonder"
    make_dump(root / "base/program/0/program", title_id=APP, seed=b"base")
    put(root / "base/program/0/data/romfs/d.bin", b"data")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root)]) == 0
    assert (tmp_path / "Wonder.nup").is_file()


def test_addon_versions_are_kept(tmp_path: Path, monkeypatch) -> None:
    """An add-on keeps the version its folder names; a data patch packed as its add-on
    (its add-on was not dumped) keeps its own version, as a lone update does (SPEC §5.2)."""
    root = tmp_path / "Game"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{ADDON:016x}" / "65536/base/program/0/romfs/a.bin", b"addon")
    lone_patch = ADDON + 1 + 0x800   # the data patch of add-on ADDON + 1, which was not dumped
    put(root / "dlc" / f"{lone_patch:016x}" / "131072/romfs/b.bin", b"patched")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--kind", "dlc"]) == 0
    records, _flags = packages(tmp_path / "Game.dlc.nup")
    assert sorted((title, version) for _kind, title, version, _p, _a in records) == \
        [(ADDON, 65536), (ADDON + 1, 131072)]


def test_yoink_data_patch_without_an_addon_id(tmp_path: Path) -> None:
    """A data patch whose CNMT DataId is 0, filed under an id without the 0x800 bit,
    names no add-on: an error, not id - 0x800."""
    root = tmp_path / "Game"
    make_dump(root / "base", title_id=APP, seed=b"base")
    odd = ADDON + 5
    put(root / "dlc" / f"{odd:016x}" / "65536/romfs/a.bin", b"patched")
    put(root / "dlc" / f"{odd:016x}" / "65536/meta/DataPatch.cnmt",
        cnmt(odd, 65536, 0x84, struct.pack("<QQII8x", 0, APP, 0, 0)))
    with pytest.raises(NupError, match="names no add-on"):
        discover_dumps(str(root))


def test_addon_with_the_patch_bit_is_an_addon(tmp_path: Path) -> None:
    """An add-on of index 0x800 or more has the 0x800 bit; its CNMT says it is an add-on."""
    root = tmp_path / "Game"
    make_dump(root / "base", title_id=APP, seed=b"base")
    big = APP + 0x1000 + 0x801
    put(root / "dlc" / f"{big:016x}" / "0/romfs/a.bin", b"addon")
    put(root / "dlc" / f"{big:016x}" / "0/meta/AddOnContent.cnmt",
        cnmt(big, 0, 0x82, struct.pack("<QIB3xQ", APP, 0, 0, 0)))
    found = discover_dumps(str(root))
    assert found.addon_patches == [] and list(found.addon_title_ids.values()) == [big]


def test_program_index_out_of_range(tmp_path: Path) -> None:
    root = tmp_path / "Game"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    make_dump(root / "base/program/300", title_id=APP + 300, seed=b"far")
    with pytest.raises(NupError, match="program index 300"):
        discover_dumps(str(root))


def test_patch_on_identical_addons_without_its_id_is_ambiguous(tmp_path: Path) -> None:
    """Two add-ons in one state and a data patch whose id names neither: the record
    keeps no add-on id, so no reader could place it; the packer refuses it (a CNMT
    DataId named the add-on), and the extractor refuses such a file from elsewhere."""
    from nup.extract import materialize
    from nup.pack import AddonPatchInput, pack_addon_container, pack_addon_update_container

    for name in ("a", "b"):
        put(tmp_path / name / "romfs/a.bin", b"same")
    put(tmp_path / "p/romfs/a.bin", b"patched")
    dlc, update = tmp_path / "x.dlc.nup", tmp_path / "x.dlc.update.nup"
    pack_addon_container(str(dlc), [str(tmp_path / "a"), str(tmp_path / "b")],
                         application_id=APP, title_ids=[ADDON, ADDON + 1])
    with pytest.raises(NupError, match="no reader could tell"):
        pack_addon_update_container(
            str(update), [AddonPatchInput(str(tmp_path / "p"), 65536, ADDON + 0x900, ADDON)], str(dlc))
    # an earlier patch of another add-on that brings it to the same state counts too:
    # a reader applies every patch in version order
    put(tmp_path / "c/romfs/a.bin", b"other")
    put(tmp_path / "q/romfs/a.bin", b"same")
    pack_addon_container(str(dlc), [str(tmp_path / "a"), str(tmp_path / "c")],
                         application_id=APP, title_ids=[ADDON, ADDON + 1])
    with pytest.raises(NupError, match="no reader could tell"):
        pack_addon_update_container(str(update), [
            AddonPatchInput(str(tmp_path / "p"), 131072, ADDON + 0x900, ADDON),
            AddonPatchInput(str(tmp_path / "q"), 65536, ADDON + 1 + 0x800, ADDON + 1),
        ], str(dlc))
    pack_addon_container(str(dlc), [str(tmp_path / "a"), str(tmp_path / "b")],
                         application_id=APP, title_ids=[ADDON, ADDON + 1])
    # its id the add-on's + 0x800: it names its add-on, and lands on it
    pack_addon_update_container(
        str(update), [AddonPatchInput(str(tmp_path / "p"), 65536, ADDON + 0x800, ADDON)], str(dlc))
    with read_container(str(update)) as reader, read_container(str(dlc)) as base:
        materialize(reader, str(tmp_path / "out"), base_reader=base)
    assert (tmp_path / "out/addon/1/romfs/a.bin").read_bytes() == b"patched"
    assert (tmp_path / "out/addon/2/romfs/a.bin").read_bytes() == b"same"


def test_program_update_title_id_is_conformant(tmp_path: Path, monkeypatch) -> None:
    """An update of program 1 is application + 1 + 0x800: no conformance note."""
    from nup.info import container_info

    root = tmp_path / "Kirby"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    make_dump(root / "base/program/1", title_id=S2_PROGRAM, seed=b"s2")
    make_dump(root / "updates/65536/program/1", title_id=S2_PROGRAM, seed=b"s2 upd")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--name", "Kirby"]) == 0
    with read_container(str(tmp_path / "Kirby.program1.update.65536.nup")) as reader:
        info = container_info(reader)
    assert info["packages"][0]["title_id"] == f"{S2_PROGRAM + 0x800:016x}"   # its own Switch 2 range (SPEC §4.1)
    assert info["packages"][0]["conformance"] == []


def test_program_base_title_id_is_conformant(tmp_path: Path, monkeypatch) -> None:
    """Program 1's base is application + 1: the base's 000 rule is program 0's only."""
    from nup.info import container_info

    root = tmp_path / "Kirby"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    make_dump(root / "base/program/1", title_id=APP + 1, seed=b"s2")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--name", "Kirby"]) == 0
    with read_container(str(tmp_path / "Kirby.program1.nup")) as reader:
        info = container_info(reader)
    assert info["packages"][0]["title_id"] == f"{APP + 1:016x}"
    assert info["packages"][0]["conformance"] == []


def test_two_versions_of_one_addon_pack_the_newest(tmp_path: Path, capsys) -> None:
    """dlc/<id>/<v>/ for two versions of one add-on: the container holds it once."""
    root = tmp_path / "Versions"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{ADDON:016x}" / "1/romfs/a.bin", b"old")
    put(root / "dlc" / f"{ADDON:016x}" / "2/romfs/a.bin", b"new")
    out = tmp_path / "v.dlc.nup"
    assert nup_main(["pack", str(root), "--kind", "dlc", "-o", str(out)]) == 0
    assert packages(out)[0] == [(Kind.ADDON, ADDON, 2, 0, APP)]
    assert "another version folder of add-on" in capsys.readouterr().err


def test_one_patch_under_two_version_folders_is_packed_once(tmp_path: Path, capsys) -> None:
    """The console layout files a data patch under each version folder of its add-on:
    the same patch twice is one record, not a second, empty one in the same scope."""
    root = tmp_path / "Twice"
    make_dump(root / "base", title_id=APP, seed=b"base")
    for folder in ("65536", "131072"):
        addon = root / "dlc" / f"{ADDON:016x}" / folder
        put(addon / "base/program/0/romfs/a.bin", b"addon")
        put(addon / "updates/196608/program/0/romfs/a.bin", b"patched")
    out = tmp_path / "t.dlc.nup"
    assert nup_main(["pack", str(root), "--kind", "dlc", "-o", str(out)]) == 0
    assert "again; packed once" in capsys.readouterr().err
    assert packages(tmp_path / "t.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, PATCH, 196608, 0, APP)]


def test_addon_update_container_is_named_after_the_out_file(tmp_path: Path) -> None:
    root = tmp_path / "Lone"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{PATCH:016x}" / "65536/romfs/a.bin", b"v1")
    put(root / "dlc" / f"{PATCH:016x}" / "131072/romfs/a.bin", b"v2")
    (tmp_path / "dist").mkdir()
    assert nup_main(["pack", str(root), "--kind", "dlc", "-o", str(tmp_path / "dist/Game.dlc.nup")]) == 0
    assert sorted(p.name for p in (tmp_path / "dist").iterdir()) == ["Game.dlc.nup", "Game.dlc.update.nup"]


def test_discovery_edge_cases(tmp_path: Path) -> None:
    """A program folder spelled with leading zeros is found; program 1 dumped both
    in switch2/ and base/program/1/ is refused, not one copy silently kept; a
    flattened data patch takes its own id from its content meta record."""
    root = tmp_path / "Zeros"
    make_dump(root / "base/program/00", title_id=APP, seed=b"base")
    make_dump(root / "base/program/01", title_id=APP + 1, seed=b"one")
    found = discover_dumps(str(root))
    assert Path(found.base_dir) == root / "base/program/00" and sorted(found.programs) == [1]
    make_dump(root / "switch2/base", title_id=APP + 1, seed=b"two")
    with pytest.raises(NupError, match="program 1's base is both"):
        discover_dumps(str(root))
    yoink = tmp_path / "Yoink"
    make_dump(yoink / "base", title_id=APP, seed=b"base")
    put(yoink / "dlc" / f"{ADDON:016x}" / "65536/romfs/a.bin", b"patched")
    put(yoink / "dlc" / f"{ADDON:016x}" / "65536/meta/DataPatch.cnmt",
        cnmt(PATCH, 65536, 0x84, struct.pack("<QQII8x", ADDON, APP, 0, 0)))
    (patch,) = discover_dumps(str(yoink)).addon_patches
    assert (patch.title_id, patch.addon_title_id) == (PATCH, ADDON)


def test_a_data_patch_is_known_by_its_content_meta_record_wherever_it_sits(tmp_path: Path) -> None:
    """A folder not named by an id, and dlc/<id>/ itself, holding a 0x84 record: a data patch."""
    root = tmp_path / "Named"
    make_dump(root / "base", title_id=APP, seed=b"base")
    record = cnmt(PATCH, 65536, 0x84, struct.pack("<QQII8x", ADDON, APP, 0, 0))
    put(root / "dlc/MyDLC/1/romfs/a.bin", b"patched")
    put(root / "dlc/MyDLC/1/meta/DataPatch.cnmt", record)
    put(root / "dlc" / f"{ADDON + 1:016x}" / "romfs/b.bin", b"patched too")
    put(root / "dlc" / f"{ADDON + 1:016x}" / "meta/DataPatch.cnmt",
        cnmt(PATCH + 1, 0, 0x84, struct.pack("<QQII8x", ADDON + 1, APP, 0, 0)))
    found = discover_dumps(str(root))
    assert found.addons == []
    assert sorted((p.title_id, p.addon_title_id) for p in found.addon_patches) == [
        (PATCH, ADDON), (PATCH + 1, ADDON + 1)]


def test_an_edit_cannot_remove_an_updates_deleted_manifest(update_nup: Path, base_nup: Path,
                                                           tmp_path: Path) -> None:
    """Without @deleted the recomputed state would keep every file the update removes."""
    from nup.edit import EditOps, edit_container

    for base in (str(base_nup), None):   # refused with --base and without
        with pytest.raises(NupError, match="cannot add, replace or remove @deleted"):
            edit_container(str(update_nup), str(tmp_path / "x.nup"),
                           EditOps(package_selector="0", remove_files={"update/458752/@deleted"},
                                   base_path=base))


def test_an_edit_cannot_leave_a_deleted_path_its_base_lacks(standalone_nup: Path, tmp_path: Path) -> None:
    """Removing from the base a file the update deletes: no reader could build that state."""
    from nup.edit import EditOps, edit_container

    with pytest.raises(NupError, match="which its base no longer holds"):
        edit_container(str(standalone_nup), str(tmp_path / "x.nup"),
                       EditOps(package_selector="0", remove_files={"base/romfs/todelete.bin"}))


def test_an_edit_refuses_a_base_its_update_does_not_land_on(update_nup: Path, tmp_path: Path,
                                                            base_dump: Path) -> None:
    """--base must be the state the update lands on, or its identity would be a state no reader builds."""
    from conftest import pack_base
    from nup.edit import EditOps, edit_container

    (base_dump / "romfs/other.bin").write_bytes(b"another base")
    other = pack_base(base_dump, tmp_path / "other.nup", title_id=f"{APP:x}")
    put(tmp_path / "x.bin", b"x")
    with pytest.raises(NupError, match="is not the state update"):
        edit_container(str(update_nup), str(tmp_path / "y.nup"),
                       EditOps(package_selector="0", add_files={"update/458752/romfs/x.bin": str(tmp_path / "x.bin")},
                               base_path=str(other)))


def test_editing_an_addons_files_warns_about_its_patches(tmp_path: Path) -> None:
    from nup.edit import EditOps, edit_container
    from nup.pack import pack_addon_container

    put(tmp_path / "a/romfs/a.bin", b"a")
    dlc = tmp_path / "x.dlc.nup"
    pack_addon_container(str(dlc), [str(tmp_path / "a")], application_id=APP, title_ids=[ADDON])
    put(tmp_path / "new.bin", b"new")
    report = edit_container(str(dlc), str(tmp_path / "y.dlc.nup"),
                            EditOps(package_selector="0",
                                    add_files={"addon/1/romfs/new.bin": str(tmp_path / "new.bin")}))
    assert any("no longer land on it" in line for line in report.warnings)


def test_editing_a_bases_files_warns_about_its_updates(base_nup: Path, tmp_path: Path) -> None:
    from nup.edit import EditOps, edit_container

    put(tmp_path / "new.bin", b"new")
    report = edit_container(str(base_nup), str(tmp_path / "y.nup"),
                            EditOps(package_selector="0",
                                    add_files={"base/romfs/new.bin": str(tmp_path / "new.bin")}))
    assert any("updates packed against it" in line for line in report.warnings)


def test_a_data_patch_id_below_the_addon_range_is_refused(tmp_path: Path) -> None:
    from nup.pack import AddonPatchInput, pack_addon_container, pack_addon_update_container

    put(tmp_path / "a/romfs/a.bin", b"a")
    put(tmp_path / "p/romfs/a.bin", b"p")
    dlc = tmp_path / "x.dlc.nup"
    pack_addon_container(str(dlc), [str(tmp_path / "a")], application_id=APP, title_ids=[ADDON])
    with pytest.raises(NupError, match="smaller than application id"):
        pack_addon_update_container(str(tmp_path / "u.nup"),
                                    [AddonPatchInput(str(tmp_path / "p"), 65536, APP + 0x800, ADDON)], str(dlc))


def test_a_title_name_makes_a_safe_file_name() -> None:
    from nup.packcli import name_stem

    assert name_stem("Zelda: Tears of the Kingdom") == "Zelda - Tears of the Kingdom"
    assert name_stem("AC/DC Live?") == "AC - DC Live"
    assert name_stem("Plain") == "Plain" and name_stem(None) is None
    assert name_stem("CON") == "CON_" and name_stem("aux") == "aux_"


def test_a_bundle_of_addons_alone_needs_the_dlc_kind(tmp_path: Path, capsys) -> None:
    """An empty base/ beside dlc/: not a silent success that writes nothing."""
    root = tmp_path / "OnlyDlc"
    (root / "base").mkdir(parents=True)
    put(root / "dlc" / f"{PATCH:016x}" / "65536/romfs/a.bin", b"patch")
    assert nup_main(["pack", str(root), "-o", str(tmp_path / "x.nup")]) == 1
    assert "--kind dlc" in capsys.readouterr().err


def test_a_tarred_switch2_base_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "Tar"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "switch2/base/romfs.tar", b"tar")
    with pytest.raises(NupError, match="romfs.tar"):
        discover_dumps(str(root))


def test_title_id_flag_names_one_addon(tmp_path: Path, capsys) -> None:
    """--title-id cannot name several add-ons: refused, not silently dropped."""
    root = tmp_path / "Two"
    make_dump(root / "base", title_id=APP, seed=b"base")
    put(root / "dlc" / f"{ADDON:016x}" / "romfs/a.bin", b"a")
    put(root / "dlc" / f"{ADDON + 1:016x}" / "romfs/b.bin", b"b")
    assert nup_main(["pack", str(root), "--kind", "dlc", "--title-id", f"{ADDON + 5:x}",
                     "-o", str(tmp_path / "x.dlc.nup")]) == 1
    assert "names one add-on" in capsys.readouterr().err
    assert not (tmp_path / "x.dlc.nup").exists()