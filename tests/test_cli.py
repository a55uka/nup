"""CLI surface: exit codes, info output, and argument handling."""

import json

import pytest

from conftest import BASE_TITLE_ID
from nup.cli import main as nup_main
from nup.reader import read_container


def test_folder_and_missing_file_are_one_line_errors(tmp_path, capsys):
    """PR #22: no traceback for a folder or a missing file."""
    assert nup_main(["info", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "is a folder" in err and "nup pack" in err and "Traceback" not in err
    assert nup_main(["verify", str(tmp_path / "missing.nup")]) == 1
    assert capsys.readouterr().err.startswith("nup: error:")


def test_a_folder_given_as_any_container_is_one_line(base_nup, tmp_path, capsys):
    """Not only the main file: --base, --chain and the like name containers too."""
    capsys.readouterr()
    assert nup_main(["extract", str(base_nup), "-o", str(tmp_path / "out"), "--base", str(tmp_path)]) == 1
    assert "is a folder, expected a .nup file" in capsys.readouterr().err


def test_a_version_the_dump_lacks_is_a_one_line_error(base_dump, tmp_path, capsys):
    """--version naming no updates/<v>/ folder: no KeyError traceback."""
    bundle = tmp_path / "Bundle"
    bundle.mkdir()
    base_dump.rename(bundle / "base")
    assert nup_main(["pack", str(bundle), "--kind", "standalone", "--version", "65536",
                     f"--title-id={BASE_TITLE_ID:x}"]) == 1
    err = capsys.readouterr().err
    assert "has no updates/65536/" in err and "Traceback" not in err


def test_info_json_matches_human_fields(base_nup, capsys):
    assert nup_main(["info", str(base_nup), "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["entry_count"] == 8
    assert info["meta"]["package_count"] == 1
    package = info["packages"][0]
    assert package["kind"] == "base"
    assert package["title_id"] == f"{BASE_TITLE_ID:016x}"
    assert package["name"] == "Test Title"
    assert package["display_version"] == "1.0.0"
    assert nup_main(["info", str(base_nup)]) == 0
    human = capsys.readouterr().out
    assert "Test Title" in human


def test_info_entry_listing(base_nup, capsys):
    assert nup_main(["info", str(base_nup), "--json", "--entries"]) == 0
    info = json.loads(capsys.readouterr().out)
    names = [entry["name"] for entry in info["entries"]]
    assert names[0] == "meta.nup"
    assert "base/exefs/main" in names


def test_verify_levels_exit_zero(base_nup, capsys):
    for level in ("bind", "package", "full"):
        assert nup_main(["verify", str(base_nup), f"--level={level}"]) == 0
        assert f"{level} verification passed" in capsys.readouterr().out


def test_bad_container_exits_nonzero_with_message(tmp_path, capsys):
    garbage = tmp_path / "garbage.nup"
    garbage.write_bytes(b"not a nup file at all")
    assert nup_main(["info", str(garbage)]) == 1
    assert "container magic" in capsys.readouterr().err


def test_pack_requires_recognizable_layout(tmp_path, capsys):
    empty = tmp_path / "nowhere"
    empty.mkdir()
    assert nup_main(["pack", str(empty)]) == 1
    assert "neither a content directory" in capsys.readouterr().err


def test_version_and_help_do_not_crash(capsys):
    with pytest.raises(SystemExit) as version:
        nup_main(["--version"])
    assert version.value.code == 0
    with pytest.raises(SystemExit) as usage:
        nup_main([])
    assert usage.value.code == 2


def test_tlv_length_cap_error_message(base_dump, tmp_path, capsys):
    from nup.layout import TLV_MAX_LENGTH

    # an icon is converted to fit (image.prepare_icon); text is not
    assert nup_main(["pack", str(base_dump), "-o", str(tmp_path / "x.nup"),
                     f"--title-id={BASE_TITLE_ID:x}", "--provenance=" + "x" * (TLV_MAX_LENGTH + 1)]) == 1
    captured = capsys.readouterr().err
    assert "1,048,576" in captured or "TLV" in captured   # over one TLV's cap: said, not truncated (SPEC §10.3)


def test_s52_default_naming_uses_standalone_update():
    """§5.2 packs (a lone update stored as a base) carry the
    standalone.update convention, per the v1 lineage."""
    from nup.packcli import default_name

    assert default_name("x/updates/917504", "standalone", 917504, "MarioKartWorld") == (
        "MarioKartWorld.standalone.update.917504.nup"
    )


def test_one_package_selector_semantics_for_every_command(base_nup, tmp_path):
    """issue #26: --package means the same thing in verify and extract."""
    from nup.verify import select_packages

    with read_container(str(base_nup)) as reader:
        assert select_packages(reader, "base")[0] is reader.meta.packages[0]
        assert select_packages(reader, 0) == select_packages(reader, "base")
        assert select_packages(reader, "all") == reader.meta.packages
