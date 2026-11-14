"""nup convert: NUP v1 files into v2 containers (best effort)."""

import os
import struct
from pathlib import Path

import pytest

from conftest import make_dump, npdm_bytes, nso_bytes, nup_main
from nup.convert import convert_v1
from nup.errors import NupError, VerificationError
from nup.layout import Kind, TlvType, parse_localized
from nup.reader import read_container
from test_control_metadata import nacp
from v1writer import Pkg, localized, write_v1

APP = 0x010074A01BF12000
S2 = 0x040074A01BF12001
ADDON = APP + 0x1001
JPEG = b"\xff\xd8\xff\xe0" + b"icon" * 200


def exefs(program_id: int, seed: bytes) -> dict[str, bytes]:
    return {"exefs/main": nso_bytes(3000, seed), "exefs/main.npdm": npdm_bytes(program_id)}


def title(tmp_path: Path, **kwargs) -> Path:
    """A Yoink-style v1 title: base, update, add-on, data patch."""
    base_files = {**exefs(APP, b"base"), "romfs/a.bin": b"a" * 3000, "romfs/gone.bin": b"old",
                  "romfs/dir/b.bin": os.urandom(500), "romfs/empty.bin": b""}
    update_files = {**exefs(APP, b"upd"), "romfs/a.bin": b"A" * 3000, "romfs/dir/b.bin": base_files["romfs/dir/b.bin"],
                    "romfs/empty.bin": b"", "romfs/new.bin": b"new"}
    packages = [
        Pkg(0, APP, base_files, tlvs={
            0x0002: nacp({"AmericanEnglish": ("Wonder", "Pub"), "Japanese": ("ワンダー", "社")}, "1.0.0"),
            0x0003: JPEG, 0x0005: b"Wonder", 0x0006: b"Pub", 0x0008: b"Yoink",
            0x0009: localized({"ja": "ワンダー".encode()}), 0x0001: npdm_bytes(APP), 0x0007: bytes(32),
        }),
        Pkg(1, APP, update_files, version=131072, tlvs={0x0004: b"1.2.0"}),
        Pkg(2, ADDON, {"romfs/dlc.bin": b"dlc" * 100, "romfs/old.bin": b"x"}),
        # Yoink: the data patch under the add-on's id
        Pkg(3, ADDON, {"romfs/dlc.bin": b"DLC" * 100}, version=65536),
    ]
    out = tmp_path / "Wonder [010074A01BF12000].nup"
    write_v1(out, packages, **kwargs)
    return out


def records(path: Path):
    with read_container(str(path)) as reader:
        return [(r.kind, r.title_id, r.version, r.program_index) for r in reader.meta.packages], \
            reader.meta.packages


def test_title_converts_to_the_containers_pack_writes(tmp_path: Path) -> None:
    src = title(tmp_path)
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="Wonder")
    assert sorted(Path(p).name for p in report.written) == [
        "Wonder.dlc.nup", "Wonder.dlc.update.nup", "Wonder.nup", "Wonder.update.131072.nup"]
    for path in report.written:
        assert nup_main(["verify", path, "--level", "full"]) == 0
    base_records, (base,) = records(out / "Wonder.nup")
    assert base_records == [(Kind.BASE, APP, 0, 0)]
    assert base.tlvs[TlvType.TITLE_NAME] == b"Wonder"
    assert base.tlvs[TlvType.PUBLISHER] == b"Pub"
    assert base.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.0"  # from the base's NACP
    assert base.tlvs[TlvType.ICON] == JPEG
    assert parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_TITLE])) == {"ja": "ワンダー".encode()}
    assert base.tlvs[TlvType.SOURCE_DUMP] == b"Yoink; converted from NUP v1"
    update_records, (update,) = records(out / "Wonder.update.131072.nup")
    assert update_records == [(Kind.UPDATE, APP + 0x800, 131072, 0)]
    assert update.tlvs[TlvType.DISPLAY_VERSION] == b"1.2.0"
    assert TlvType.TITLE_NAME not in update.tlvs
    assert {row.path for row in update.files} >= {"romfs/a.bin", "romfs/new.bin", "@deleted"}
    assert records(out / "Wonder.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, ADDON + 0x800, 65536, 0)]
    assert any("data patch id taken as" in line for line in report.warnings)
    # the materialized v2 tree is the v1 update's tree
    tree = tmp_path / "tree"
    assert nup_main(["extract", str(out / "Wonder.update.131072.nup"), "--base", str(out / "Wonder.nup"),
                     "--apply", "-o", str(tree)]) == 0
    assert (tree / "romfs/a.bin").read_bytes() == b"A" * 3000
    assert (tree / "romfs/new.bin").read_bytes() == b"new"
    assert not (tree / "romfs/gone.bin").exists()


def test_cli_default_output_folder(tmp_path: Path, capsys) -> None:
    src = title(tmp_path)
    assert nup_main(["convert", str(src)]) == 0
    folder = tmp_path / "Wonder [010074A01BF12000].v2"
    assert (folder / "Wonder [010074A01BF12000].nup").is_file()
    assert "converted" in capsys.readouterr().out
    assert not any(p.name.startswith(".nup-convert-") for p in folder.iterdir())  # work dir removed


def test_zstd_extents(tmp_path: Path) -> None:
    try:
        from compression import zstd  # noqa: F401
    except ImportError:
        pytest.importorskip("zstandard")
    src = title(tmp_path, zstd=True)
    report = convert_v1(str(src), str(tmp_path / "out"), stem="Wonder")
    assert len(report.written) == 4


def test_update_only_file_packs_updates_as_bases(tmp_path: Path) -> None:
    src = tmp_path / "upd.nup"
    write_v1(src, [Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/x": b"x"}, version=65536, flags=1,
                       tlvs={0x0005: b"Wonder", 0x0004: b"1.0.1"})])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="W")
    (path,) = report.written
    assert Path(path).name == "W.standalone.update.65536.nup"
    found, (record,) = records(Path(path))
    assert found == [(Kind.BASE, APP, 65536, 0)]  # SPEC §5.2, with the program's id
    assert record.tlvs[TlvType.TITLE_NAME] == b"Wonder"
    assert record.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.1"


def test_yoink_switch2_update_twin_becomes_program_1(tmp_path: Path) -> None:
    src = tmp_path / "ed.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={0x0005: b"Ed"}),
        Pkg(1, APP, {**exefs(APP, b"u"), "romfs/a": b"b"}, version=65536),
        Pkg(1, S2, {**exefs(S2, b"s2"), "romfs/s2": b"s2"}, version=65536),
    ])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="Ed")
    names = sorted(Path(p).name for p in report.written)
    assert names == ["Ed.nup", "Ed.program1.standalone.update.65536.nup", "Ed.update.65536.nup"]
    found, _ = records(tmp_path / "out" / "Ed.program1.standalone.update.65536.nup")
    assert found == [(Kind.BASE, S2, 65536, 1)]   # its own Switch 2 id (SPEC §4.1)


def test_fields_v1_0_does_not_define_are_refused(tmp_path: Path) -> None:
    """Only the v1.0 spec is read: superblock flags and the package record's
    reserved fields are zero there."""
    src = tmp_path / "flags.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"})])
    data = bytearray(src.read_bytes())
    struct.pack_into("<I", data, 0x4C, 1)
    src.write_bytes(data)
    with pytest.raises(NupError, match="unknown flags"):
        convert_v1(str(src), str(tmp_path / "out"))
    for offset in (0x1A, 0x1C, 0x2C, 0x3F):   # reserved, reserved2, reserved3 (both ends)
        src = tmp_path / f"reserved{offset:x}.nup"
        write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"})],
                 tamper=lambda toc, _blob, offset=offset: toc.__setitem__(0x30 + offset, 1))
        with pytest.raises(NupError, match="reserved fields"):
            convert_v1(str(src), str(tmp_path / "out"))


def test_unusable_icon_is_dropped_with_a_warning(tmp_path: Path) -> None:
    # not a JPEG and no image at all: refused with or without Pillow
    src = tmp_path / "icon.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b")}, tlvs={0x0003: b"not an image" * 0x1800})])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="I")
    assert any("icon dropped" in line for line in report.warnings)
    assert TlvType.ICON not in records(tmp_path / "out" / "I.nup")[1][0].tlvs


def test_console_size_icons_carry_over_as_stored(tmp_path: Path) -> None:
    big = b"\xff\xd8\xff\xe0" + os.urandom(200_000)  # a console icon is 150-250 KB
    other = b"\xff\xd8\xff\xe0" + os.urandom(1000)
    src = tmp_path / "icons.nup"
    write_v1(src, [Pkg(0, APP, exefs(APP, b"b"), tlvs={
        0x0003: big, 0x000A: localized({"en-gb": big, "ja": other})})])
    convert_v1(str(src), str(tmp_path / "out"), stem="I")
    tlvs = records(tmp_path / "out" / "I.nup")[1][0].tlvs
    assert tlvs[TlvType.ICON] == big
    # en-gb repeats the default: only the icon that differs is localized
    assert parse_localized(memoryview(tlvs[TlvType.LOCALIZED_ICON])) == {"ja": other}


def test_v1_hint_on_v2_commands(tmp_path: Path, capsys) -> None:
    src = title(tmp_path)
    assert nup_main(["info", str(src)]) == 1
    assert "nup convert" in capsys.readouterr().err


def test_refuses_to_overwrite_its_input(tmp_path: Path) -> None:
    src = title(tmp_path)
    with pytest.raises(NupError, match="overwrite"):
        convert_v1(str(src), str(tmp_path), stem="Wonder [010074A01BF12000]")
    assert src.is_file()


# ---- hostile v1 files (SPEC §6.4)

def corrupt_data(tmp_path: Path) -> Path:
    src = title(tmp_path)
    data = bytearray(src.read_bytes())
    data[data.index(b"a" * 3000) + 10] ^= 0xFF
    src.write_bytes(data)
    return src


def test_data_corruption_fails_and_leaves_nothing(tmp_path: Path) -> None:
    src = corrupt_data(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(VerificationError, match="hash mismatch"):
        convert_v1(str(src), str(out), stem="Wonder")
    assert not out.exists()   # the folder it made goes with the rest


def test_toc_tampering_is_caught(tmp_path: Path) -> None:
    src = title(tmp_path)
    data = bytearray(src.read_bytes())
    data[0x80 + 0x40] ^= 0xFF  # inside the TOC, under its hash
    src.write_bytes(data)
    with pytest.raises(VerificationError, match="TOC hash"):
        convert_v1(str(src), str(tmp_path / "out"))


@pytest.mark.parametrize("name", ["..", ".", "a/b", "a\\b"])
def test_unsafe_names_are_refused(tmp_path: Path, name: str) -> None:
    src = tmp_path / "evil.nup"
    write_v1(src, [Pkg(0, APP, {"romfs/" + "x" * len(name): b"1"})],
             tamper=lambda toc, blob: patch_name(toc, "x" * len(name), name))
    with pytest.raises(NupError, match="unsafe name"):
        convert_v1(str(src), str(tmp_path / "out"))


def patch_name(toc: bytearray, old: str, new: str) -> None:
    index = toc.rindex(old.encode())
    toc[index : index + len(old)] = new.encode()


def test_directory_cycle_is_refused(tmp_path: Path) -> None:
    def loop(toc, _blob):
        # make the romfs dir's first child point back at the package root (dir 0)
        children_at = len(toc) - toc_pool_size(toc) - 4 * child_slots(toc)
        struct.pack_into("<I", toc, children_at + 4, 0)

    src = tmp_path / "cycle.nup"
    write_v1(src, [Pkg(0, APP, {"romfs/a": b"1"})], tamper=loop)
    with pytest.raises(NupError, match="cycle|reached twice"):
        convert_v1(str(src), str(tmp_path / "out"))


def toc_pool_size(toc) -> int:
    return struct.unpack_from("<Q", toc, 0x20)[0]


def child_slots(toc) -> int:
    dirs = struct.unpack_from("<Q", toc, 0x08)[0]
    packages = struct.unpack_from("<I", toc, 0x04)[0]
    dirs_at = 0x30 + packages * 0x40
    return sum(struct.unpack_from("<I", toc, dirs_at + i * 0x18 + 0x0C)[0] for i in range(dirs))


def test_extent_outside_the_file_is_refused(tmp_path: Path) -> None:
    def far(toc, _blob):
        dirs = struct.unpack_from("<Q", toc, 0x08)[0]
        files_at = 0x30 + 0x40 + dirs * 0x18
        struct.pack_into("<Q", toc, files_at + 0x10, 1 << 40)

    src = tmp_path / "far.nup"
    write_v1(src, [Pkg(0, APP, {"romfs/a": b"1"})], tamper=far)
    with pytest.raises(NupError, match="outside the blob region"):
        convert_v1(str(src), str(tmp_path / "out"))


# ---- outputs, ids and data patches

def test_non_ascii_localized_tag_is_dropped_with_a_warning(tmp_path: Path) -> None:
    tag = "é".encode()
    raw = bytes([len(tag)]) + tag + struct.pack("<I", 1) + b"x" + localized({"ja": "ワンダー".encode()})
    src = tmp_path / "tags.nup"
    write_v1(src, [Pkg(0, APP, exefs(APP, b"b"), tlvs={0x0005: b"W", 0x0009: raw})])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="T")
    assert any("not ASCII" in line for line in report.warnings)
    tlvs = records(tmp_path / "out" / "T.nup")[1][0].tlvs
    assert parse_localized(memoryview(tlvs[TlvType.LOCALIZED_TITLE])) == {"ja": "ワンダー".encode()}


@pytest.mark.parametrize("value", ["0x0100zz", "1" * 17, "-1"])
def test_bad_application_id_is_a_one_line_error(tmp_path: Path, capsys, value: str) -> None:
    src = title(tmp_path)
    assert nup_main(["convert", str(src), "--application-id", value]) == 1
    assert "--application-id" in capsys.readouterr().err


def test_a_failed_pack_leaves_no_partial_container(tmp_path: Path, monkeypatch) -> None:
    import nup.convert

    def failing(out, *args, **kwargs):
        Path(out).write_bytes(b"half a container")
        raise NupError("disk full")

    monkeypatch.setattr(nup.convert, "pack_update_container", failing)
    out = tmp_path / "out"
    out.mkdir()
    (out / "Wonder.update.131072.nup").write_bytes(b"from an earlier run")
    with pytest.raises(NupError, match="disk full"):
        convert_v1(str(title(tmp_path)), str(out), stem="Wonder")
    assert sorted(p.name for p in out.iterdir()) == ["Wonder.update.131072.nup"]
    assert (out / "Wonder.update.131072.nup").read_bytes() == b"from an earlier run"


def test_replacing_an_earlier_conversion_warns(tmp_path: Path) -> None:
    src, out = title(tmp_path), tmp_path / "out"
    assert not any("replaced" in line for line in convert_v1(str(src), str(out), stem="Wonder").warnings)
    report = convert_v1(str(src), str(out), stem="Wonder")
    assert sum("replaced" in line for line in report.warnings) == len(report.written)


def test_several_versions_of_a_lone_data_patch(tmp_path: Path) -> None:
    """Without its add-on, the oldest data patch converts as the add-on and the newer
    ones as add-on updates chained on it, as `nup pack` does."""
    src = tmp_path / "lone.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(3, ADDON, {"romfs/d": b"v1"}, version=65536),
        Pkg(3, ADDON, {"romfs/d": b"v2"}, version=131072),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="L")
    assert records(out / "L.dlc.nup")[0] == [(Kind.ADDON, ADDON, 65536, 0)]
    assert records(out / "L.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, ADDON + 0x800, 131072, 0)]
    tree = tmp_path / "tree"
    assert nup_main(["extract", str(out / "L.dlc.update.nup"), "--base", str(out / "L.dlc.nup"),
                     "--apply", "-o", str(tree)]) == 0
    assert (tree / "addon/1/romfs/d").read_bytes() == b"v2"


def test_addon_metadata_carries_over(tmp_path: Path) -> None:
    """An add-on's and a data patch's own name and display version carry over; an add-on
    without one does not take the game's."""
    src = tmp_path / "dlc.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={0x0005: b"Game"}),
        Pkg(2, ADDON, {"romfs/d": b"d"}, tlvs={0x0005: b"Expansion", 0x0004: b"1.0.0"}),
        Pkg(2, ADDON + 1, {"romfs/e": b"e"}),
        Pkg(3, ADDON, {"romfs/d": b"D"}, version=65536,
            tlvs={0x0005: b"Expansion", 0x0004: b"1.0.1"}),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="D")
    _found, (named, unnamed) = records(out / "D.dlc.nup")
    assert named.tlvs[TlvType.TITLE_NAME] == b"Expansion" and named.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.0"
    assert TlvType.TITLE_NAME not in unnamed.tlvs
    _found, (patch,) = records(out / "D.dlc.update.nup")
    assert patch.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.1"


def test_a_program_never_takes_an_addons_name(tmp_path: Path) -> None:
    """A lone update without a name of its own does not inherit an add-on's."""
    src = tmp_path / "upd.nup"
    write_v1(src, [
        Pkg(2, ADDON, {"romfs/d": b"d"}, tlvs={0x0005: b"Expansion Pass", 0x0006: b"DLC Pub"}),
        Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/x": b"x"}, version=65536),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="U")
    _found, (base,) = records(out / "U.standalone.update.65536.nup")
    assert TlvType.TITLE_NAME not in base.tlvs and TlvType.PUBLISHER not in base.tlvs


def test_two_versions_of_one_addon_keep_the_newest(tmp_path: Path) -> None:
    src = tmp_path / "dup.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(2, ADDON, {"romfs/d": b"old"}),
        Pkg(2, ADDON, {"romfs/d": b"new"}, version=65536),
    ])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="D")
    assert records(out / "D.dlc.nup")[0] == [(Kind.ADDON, ADDON, 65536, 0)]
    assert any("a second add-on" in line for line in report.warnings)


def test_a_packages_own_nacp_names_its_display_version(tmp_path: Path) -> None:
    """v1 put the title's one display version on the base: the base's NACP says its own."""
    src = tmp_path / "dv.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={
        0x0002: nacp({"AmericanEnglish": ("Wonder", "Pub")}, "1.0.0"), 0x0004: b"3.2.0"})])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="V")
    _found, (base,) = records(out / "V.nup")
    assert base.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.0"
    assert any("differs from its NACP's" in line for line in report.warnings)


def test_the_inherited_title_metadata_is_made_once(tmp_path: Path) -> None:
    """Every package that takes the title's metadata shares one conversion of it:
    a problem with it is said once, not once per package."""
    src = tmp_path / "many.nup"
    bad = b"\x02ja" + b"\x99\x99\x99\x99"   # a localized record that overruns its TLV
    write_v1(src, [Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/x": bytes([v])}, version=v << 16,
                       tlvs={0x0005: b"Game", 0x0009: bad} if v == 1 else {}) for v in (1, 2, 3)])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="M")
    lines = [line for line in report.warnings if "localized TLV" in line]
    assert len(lines) == 2   # its own, and the title's once
    assert all(line.startswith("#0") for line in lines)   # both name the package the title's metadata is on


def test_warnings_before_a_failure_are_shown(tmp_path: Path, capsys) -> None:
    """What convert noticed before it failed can be why: it is printed, not lost."""
    src = tmp_path / "bad.nup"
    write_v1(src, [Pkg(4, APP, {"romfs/s": b"system"}),   # skipped, with a warning
                   Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a.bin": b"a" * 3000})])
    data = bytearray(src.read_bytes())
    data[data.index(b"a" * 3000) + 10] ^= 0xFF   # then the base's data fails its hash
    src.write_bytes(data)
    assert nup_main(["convert", str(src), "-o", str(tmp_path / "out")]) == 1
    err = capsys.readouterr().err
    assert "system packages have no v2 equivalent" in err and "hash mismatch" in err


def test_the_trees_own_nacp_names_the_display_version(tmp_path: Path) -> None:
    """v1's version TLV on a base whose tree carries control/control.nacp: the tree's wins."""
    src = tmp_path / "tree.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a",
                                "control/control.nacp": nacp({"AmericanEnglish": ("W", "P")}, "1.0.0")},
                       tlvs={0x0004: b"1.2.1"})])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="T")
    _found, (base,) = records(tmp_path / "out/T.nup")
    assert base.tlvs[TlvType.DISPLAY_VERSION] == b"1.0.0"
    assert any("tree's NACP" in line for line in report.warnings)


def test_a_programs_own_control_names_it_not_the_titles_v1_name(tmp_path: Path) -> None:
    """Program 1's tree carries its own Control content: it names program 1, not program 0's v1 name;
    an update's tree NACP names its display version as a base's does."""
    s2_control = {"control/control.nacp": nacp({"AmericanEnglish": ("Wonder S2", "Pub")}, "1.0.0")}
    src = tmp_path / "s2.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={0x0005: b"Wonder"}),
        Pkg(0, APP + 1, {**exefs(APP + 1, b"s"), "romfs/s": b"s", **s2_control}),
        Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/a": b"A", "control/control.nacp": nacp(
            {"AmericanEnglish": ("Wonder", "Pub")}, "1.2.1")}, version=65536, tlvs={0x0004: b"1.0.0"}),
    ])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="W")
    _found, (program1,) = records(tmp_path / "out/W.program1.nup")
    assert program1.tlvs[TlvType.TITLE_NAME] == b"Wonder S2"
    _found, (update,) = records(tmp_path / "out/W.update.65536.nup")
    assert update.tlvs[TlvType.DISPLAY_VERSION] == b"1.2.1"
    assert any("tree's NACP" in line for line in report.warnings)


def test_a_localized_title_that_is_not_utf8_is_dropped(tmp_path: Path) -> None:
    src = tmp_path / "sjis.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={
        0x0005: b"Game", 0x0009: localized({"ja": "ゲーム".encode("shift_jis"), "fr": b"Jeu"})})])
    report = convert_v1(str(src), str(tmp_path / "out"), stem="S")
    _found, (base,) = records(tmp_path / "out/S.nup")
    assert parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_TITLE])) == {"fr": b"Jeu"}
    assert any("not UTF-8" in line for line in report.warnings)


def test_a_v1_meta_block_cut_off_inside_a_tlv_header_is_refused() -> None:
    from types import SimpleNamespace
    from nup.v1 import V1Reader

    tlv = struct.pack("<HHI", 0x0005, 0, 4) + b"Game"
    for tail, refused in ((b"\0\0\0", False), (bytes(12), False), (b"\x05\0\x01", True)):
        block = tlv + tail
        fake = SimpleNamespace(file_size=1 << 20, _read_at=lambda _offset, _size, block=block: block)
        if refused:
            with pytest.raises(NupError, match="stray byte"):
                V1Reader._parse_meta(fake, 0x100, len(block))
        else:
            assert V1Reader._parse_meta(fake, 0x100, len(block)) == {0x0005: b"Game"}


def test_equal_versions_of_one_addon_keep_the_first() -> None:
    from nup.pack import newest_per_title

    items = [("a", 1, 0), ("b", 1, 0), ("c", 1, 5), ("d", None, 9)]
    kept, passed_over = newest_per_title(items, lambda i: i[1], lambda i: i[2])
    assert [i[0] for i in kept] == ["c", "d"]
    assert [(left[0], kept_one[0]) for left, kept_one in passed_over] == [("b", "a"), ("a", "c")]


def test_localized_titles_merge_with_the_nacps(tmp_path: Path) -> None:
    """A v1 localized title sets its own language: the NACP's other languages stay."""
    src = tmp_path / "names.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}, tlvs={
        0x0002: nacp({"AmericanEnglish": ("Wonder", "Pub"), "Japanese": ("ワンダー", "社"),
                      "French": ("Merveille", "Pub")}, "1.0.0"),
        0x0009: localized({"ja": "ワンダー2".encode()}),
    })])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="N")
    _found, (base,) = records(out / "N.nup")
    assert parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_TITLE])) == {
        "ja": "ワンダー2".encode(), "fr": b"Merveille"}


def test_a_title_name_given_as_stem_makes_safe_file_names(tmp_path: Path) -> None:
    report = convert_v1(str(title(tmp_path)), str(tmp_path / "out"), stem="Wonder: Deluxe")
    assert "Wonder - Deluxe.nup" in {Path(p).name for p in report.written}


def test_a_repeated_data_patch_converts_once(tmp_path: Path) -> None:
    src = tmp_path / "rep.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(2, ADDON, {"romfs/d": b"d"}),
        Pkg(3, ADDON, {"romfs/d": b"D"}, version=65536),
        Pkg(3, ADDON, {"romfs/d": b"D"}, version=65536),
    ])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="R")
    assert records(out / "R.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, ADDON + 0x800, 65536, 0)]
    assert any("again; skipped" in line for line in report.warnings)


def test_a_base_without_control_takes_its_updates(tmp_path: Path) -> None:
    """As `nup pack` does: the newest update's Control content names and pictures the base."""
    src = tmp_path / "ctl.nup"
    control = {"control/control.nacp": nacp({"AmericanEnglish": ("Wonder", "Pub"),
                                             "Japanese": ("ワンダー", "社")}, "1.2.0"),
               "control/icon_AmericanEnglish.dat": JPEG, "control/icon_Japanese.dat": JPEG + b"ja"}
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/a": b"A", **control}, version=65536),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="C")
    _found, (base,) = records(out / "C.nup")
    assert base.tlvs[TlvType.TITLE_NAME] == b"Wonder" and base.tlvs[TlvType.ICON] == JPEG
    assert parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_ICON])) == {"ja": JPEG + b"ja"}
    assert TlvType.DISPLAY_VERSION not in base.tlvs   # the update's version, not the base's


def test_a_base_takes_an_updates_control_at_its_tree_root(tmp_path: Path) -> None:
    """control.nacp at the update's root, where `nup pack` also finds it (nacp.find_control_dir)."""
    src = tmp_path / "root.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/a": b"A", "control.nacp": nacp(
            {"AmericanEnglish": ("Wonder", "Pub")}, "1.2.0")}, version=65536),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="R")
    _found, (base,) = records(out / "R.nup")
    assert base.tlvs[TlvType.TITLE_NAME] == b"Wonder"


def test_program_zeros_update_names_the_title_before_another_programs_base(tmp_path: Path) -> None:
    """An unnamed lone update of program 0 inherits the title from program 0's
    named update, not from program 1's base."""
    src = tmp_path / "p.nup"
    write_v1(src, [
        Pkg(1, APP + 0x800, {**exefs(APP, b"u"), "romfs/x": b"x"}, version=65536, tlvs={0x0005: b"Game"}),
        Pkg(1, APP + 0x800, {**exefs(APP, b"v"), "romfs/x": b"y"}, version=131072),
        Pkg(0, APP + 1, {**exefs(APP + 1, b"s"), "romfs/s": b"s"},
            tlvs={0x0005: b"Game: Switch 2 Edition"}),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="P")
    _found, (base,) = records(out / "P.standalone.update.131072.nup")
    assert base.tlvs[TlvType.TITLE_NAME] == b"Game"


def test_a_lone_switch_2_update_is_its_own_program(tmp_path: Path) -> None:
    """Yoink filed a Switch 2 Edition's update among program 0's with its program's id:
    the id alone says which program it is, with or without a program 0 update beside it."""
    src = tmp_path / "s2.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(1, APP + 1 + 0x800, {**exefs(APP + 1, b"s"), "romfs/s": b"s"}, version=65536),
    ])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="S")
    assert records(out / "S.program1.standalone.update.65536.nup")[0] == [(Kind.BASE, APP + 1, 65536, 1)]
    assert sum("named after program 1" in line for line in report.warnings) == 1


def test_a_failed_conversion_leaves_no_output_folder(base_nup: Path, tmp_path: Path) -> None:
    """A v2 file (not v1) fails before anything converts: the <name>.v2/ folder it made goes."""
    with pytest.raises(NupError):
        convert_v1(str(base_nup))
    assert not (base_nup.parent / f"{base_nup.stem}.v2").exists()
    kept = tmp_path / "kept"
    kept.mkdir()
    with pytest.raises(NupError):
        convert_v1(str(base_nup), str(kept))
    assert kept.is_dir()   # a folder it did not make stays


def test_a_v1_0_base_named_after_program_1_is_program_1(tmp_path: Path) -> None:
    """v1 has no program index: a base with program 1's id is program 1's."""
    src = tmp_path / "s2b.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(0, APP + 1, {**exefs(APP + 1, b"s"), "romfs/s": b"s"}),
    ])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="B")
    assert records(out / "B.program1.nup")[0] == [(Kind.BASE, APP + 1, 0, 1)]
    assert not any("second base" in line for line in report.warnings)


def test_a_v1_icon_from_the_trees_control_keeps_the_other_languages(tmp_path: Path) -> None:
    """v1 stored the tree's default icon and no localized ones: the v2 base has both,
    as packing the tree does, not just the one v1 kept."""
    src = tmp_path / "icons.nup"
    control = {"control/control.nacp": nacp({"AmericanEnglish": ("Wonder", "Pub"),
                                             "Japanese": ("ワンダー", "社")}, "1.0.0"),
               "control/icon_AmericanEnglish.dat": JPEG, "control/icon_Japanese.dat": JPEG + b"ja"}
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a", **control}, tlvs={0x0003: JPEG})])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="I")
    _found, (base,) = records(out / "I.nup")
    assert base.tlvs[TlvType.ICON] == JPEG
    assert parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_ICON])) == {"ja": JPEG + b"ja"}


def test_a_v1_0_package_of_a_high_program_index(tmp_path: Path) -> None:
    src = tmp_path / "p16.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(0, APP + 0x10, {**exefs(APP + 0x10, b"s"), "romfs/s": b"s"}),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="H")
    assert records(out / "H.program16.nup")[0] == [(Kind.BASE, APP + 0x10, 0, 16)]


def test_a_high_addon_index_patch_is_the_same_application(tmp_path: Path) -> None:
    """Add-on index 0x900: its data patch's id (+ 0x800) crosses into the next 0x2000 block."""
    addon = APP + 0x1000 + 0x900
    src = tmp_path / "hi.nup"
    write_v1(src, [
        Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a"}),
        Pkg(2, addon, {"romfs/d": b"d"}),
        Pkg(3, addon, {"romfs/d": b"D"}, version=65536),
    ])
    out = tmp_path / "out"
    convert_v1(str(src), str(out), stem="H")
    assert records(out / "H.dlc.update.nup")[0] == [(Kind.ADDON_UPDATE, addon + 0x800, 65536, 0)]


def test_refuses_to_overwrite_its_input_spelled_in_another_case(tmp_path: Path) -> None:
    from nup.tree import case_insensitive

    if not case_insensitive(str(tmp_path)):
        pytest.skip("the folder tells names apart by case")
    src = title(tmp_path)
    with pytest.raises(NupError, match="overwrite"):
        convert_v1(str(src), str(tmp_path), stem="WONDER [010074A01BF12000]")
    assert src.read_bytes()[:4] == b"NUP\x01"


def test_a_failed_rename_leaves_no_partial_conversion(tmp_path: Path, monkeypatch) -> None:
    real_replace, calls = os.replace, []

    def flaky(source, target):
        calls.append(target)
        if len(calls) == 2:
            raise OSError("target is locked")
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", flaky)
    out = tmp_path / "out"
    with pytest.raises(OSError, match="locked"):
        convert_v1(str(title(tmp_path)), str(out), stem="Wonder")
    assert not out.exists()   # the folder it made goes with the rest


def test_bytes_after_a_zstd_frame_and_a_corrupt_frame(tmp_path: Path) -> None:
    import hashlib
    from nup.v1 import READ_CHUNK, V1File, V1Reader, zstd_chunks

    try:
        from compression import zstd
        compress = zstd.compress
    except ImportError:
        compress = pytest.importorskip("zstandard").ZstdCompressor().compress
    zstd_chunks(())   # the codec is there
    data = b"payload" * 100
    frame = compress(data)

    class Extent:   # V1Reader._iter_data reads the stored bytes through _iter_extent
        def __init__(self, *chunks):
            self.chunks = chunks

        def _iter_extent(self, _entry):
            yield from self.chunks

    entry = V1File("romfs/x", len(data), 0, len(frame) + 8, hashlib.sha256(data).digest(), 1)
    assert b"".join(V1Reader._iter_data(Extent(frame, bytes(8)), entry)) == data
    with pytest.raises(VerificationError, match="zstd data is corrupt"):
        list(V1Reader._iter_data(Extent(b"not a zstd frame at all"), entry))
    # a frame that expands far past its file's size comes out a chunk at a time,
    # so copy_file stops it before it is all in memory (SPEC §6.4)
    bomb = compress(bytes(4 * READ_CHUNK))
    tiny = V1File("romfs/y", 1, 0, len(bomb), bytes(32), 1)
    chunks = V1Reader._iter_data(Extent(bomb), tiny)
    assert len(next(chunks)) <= READ_CHUNK
    chunks.close()


def test_program_folder_inside_a_v1_package(tmp_path: Path) -> None:
    """v1 packed a flattened dump with program1/ beside exefs/ and romfs/ as one package:
    program 1 converts as a program, as `nup pack` would pack it, not dropped."""
    src = tmp_path / "flat.nup"
    write_v1(src, [Pkg(0, APP, {**exefs(APP, b"b"), "romfs/a": b"a", **{
        "program1/" + path: data for path, data in {**exefs(S2, b"s2"), "romfs/s": b"s"}.items()}})])
    out = tmp_path / "out"
    report = convert_v1(str(src), str(out), stem="F")
    assert sorted(Path(p).name for p in report.written) == ["F.nup", "F.program1.nup"]
    assert records(out / "F.program1.nup")[0] == [(Kind.BASE, S2, 0, 1)]
    _found, (base,) = records(out / "F.nup")
    assert not any(row.path.startswith("program1/") for row in base.files)