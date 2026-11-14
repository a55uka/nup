"""nup edit's metadata flags: name, display version, publisher, icons."""

import io
from pathlib import Path

import pytest

from conftest import nup_main
from nup.layout import TlvType, parse_localized
from nup.reader import read_container

JPEG = b"\xff\xd8\xff\xe0" + b"jpeg body" * 100


def tlvs_of(path: Path, index: int = 0) -> dict[int, bytes]:
    with read_container(str(path)) as reader:
        return reader.meta.packages[index].tlvs


def test_name_version_publisher_and_jpeg_icon(base_nup: Path, tmp_path: Path) -> None:
    icon = tmp_path / "cover.jpg"
    icon.write_bytes(JPEG)
    assert nup_main(["edit", str(base_nup), "--name", "Renamed", "--display-version", "1.2.0",
                     "--publisher", "New Pub", "--icon", str(icon)]) == 0
    tlvs = tlvs_of(base_nup)
    assert tlvs[TlvType.TITLE_NAME] == b"Renamed"
    assert tlvs[TlvType.DISPLAY_VERSION] == b"1.2.0"
    assert tlvs[TlvType.PUBLISHER] == b"New Pub"
    assert tlvs[TlvType.ICON] == JPEG  # a JPEG that fits is kept byte for byte
    assert nup_main(["verify", str(base_nup), "--level", "full"]) == 0


def test_an_empty_value_clears_the_field(base_nup: Path, capsys) -> None:
    assert nup_main(["edit", str(base_nup), "--publisher", ""]) == 0
    assert TlvType.PUBLISHER not in tlvs_of(base_nup)
    capsys.readouterr()
    assert nup_main(["verify", str(base_nup), "--level", "package", "--package", "²"]) == 1
    assert "no package matches" in capsys.readouterr().err   # a Unicode digit is no record index


def test_edit_defaults_to_the_containers_package(update_nup: Path) -> None:
    # an update container has no base record; its only package is the update
    assert nup_main(["edit", str(update_nup), "--display-version", "3.2.1"]) == 0
    assert tlvs_of(update_nup)[TlvType.DISPLAY_VERSION] == b"3.2.1"


def test_edit_asks_which_of_several_packages_without_a_base(tmp_path: Path, capsys) -> None:
    """Several add-ons and no base: no package is picked for the user, and a kind
    two packages share names neither; a scope label or index names one."""
    from conftest import BASE_TITLE_ID
    from nup.pack import pack_addon_container

    for name in ("a", "b"):
        (tmp_path / name / "romfs").mkdir(parents=True)
        (tmp_path / name / "romfs/x.bin").write_bytes(name.encode())
    dlc = tmp_path / "x.dlc.nup"
    pack_addon_container(str(dlc), [str(tmp_path / "a"), str(tmp_path / "b")], application_id=BASE_TITLE_ID)
    assert nup_main(["edit", str(dlc), "--name", "Two"]) == 1
    assert "pass --package" in capsys.readouterr().err
    assert nup_main(["edit", str(dlc), "--package", "addon", "--name", "Two"]) == 1
    assert "matches 2 packages" in capsys.readouterr().err
    assert nup_main(["edit", str(dlc), "--package", "addon/2", "--name", "Two"]) == 0
    assert TlvType.TITLE_NAME not in tlvs_of(dlc, 0) and tlvs_of(dlc, 1)[TlvType.TITLE_NAME] == b"Two"
    assert nup_main(["edit", str(dlc), "--package", "0", "--name", "One"]) == 0
    assert tlvs_of(dlc, 0)[TlvType.TITLE_NAME] == b"One"
    # an index past the last package is a one-line error in edit and verify alike
    capsys.readouterr()
    assert nup_main(["edit", str(dlc), "--package", "9", "--name", "Nine"]) == 1
    assert nup_main(["verify", str(dlc), "--level", "package", "--package", "9"]) == 1
    assert capsys.readouterr().err.count("no package matches '9'") == 2


def test_edit_defaults_to_the_base_of_a_standalone_container(standalone_nup: Path) -> None:
    """The title's metadata goes to the base; the display version to the update, as
    `nup pack --display-version` gives it (the version that was dumped)."""
    assert nup_main(["edit", str(standalone_nup), "--name", "Renamed", "--display-version", "1.2.1"]) == 0
    base, update = tlvs_of(standalone_nup, 0), tlvs_of(standalone_nup, 1)
    assert base[TlvType.TITLE_NAME] == b"Renamed" and update[TlvType.DISPLAY_VERSION] == b"1.2.1"
    assert base.get(TlvType.DISPLAY_VERSION) != b"1.2.1"
    assert nup_main(["edit", str(standalone_nup), "--package", "base", "--display-version", "1.0.0"]) == 0
    assert tlvs_of(standalone_nup, 0)[TlvType.DISPLAY_VERSION] == b"1.0.0"


def test_localized_names_and_icons(base_nup: Path, tmp_path: Path) -> None:
    icon = tmp_path / "ja.jpg"
    icon.write_bytes(JPEG)
    assert nup_main(["edit", str(base_nup), "--lang-name", "ja=ワンダー",
                     "--lang-icon", f"ja={icon}"]) == 0
    tlvs = tlvs_of(base_nup)
    assert parse_localized(memoryview(tlvs[TlvType.LOCALIZED_TITLE])) == {"ja": "ワンダー".encode()}
    assert parse_localized(memoryview(tlvs[TlvType.LOCALIZED_ICON])) == {"ja": JPEG}


def test_icon_flag_replaces_every_languages_icon(base_nup: Path, tmp_path: Path) -> None:
    """--icon is the image for every language, as `nup pack --icon` gives it: the
    localized icons go, unless --lang-icon gives one anew."""
    icon = tmp_path / "ja.jpg"
    icon.write_bytes(JPEG)
    assert nup_main(["edit", str(base_nup), "--lang-icon", f"ja={icon}"]) == 0
    cover = tmp_path / "cover.jpg"
    cover.write_bytes(JPEG + b"cover")
    assert nup_main(["edit", str(base_nup), "--icon", str(cover)]) == 0
    tlvs = tlvs_of(base_nup)
    assert tlvs[TlvType.ICON] == JPEG + b"cover" and TlvType.LOCALIZED_ICON not in tlvs
    assert nup_main(["edit", str(base_nup), "--icon", str(cover), "--lang-icon", f"ja={icon}"]) == 0
    assert parse_localized(memoryview(tlvs_of(base_nup)[TlvType.LOCALIZED_ICON])) == {"ja": JPEG}


def test_non_jpeg_without_pillow_is_refused(base_nup: Path, tmp_path: Path, monkeypatch, capsys) -> None:
    import builtins

    real_import = builtins.__import__

    def no_pil(name, *args, **kwargs):
        if name == "PIL" or name.startswith("PIL."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_pil)
    png = tmp_path / "cover.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(64))
    assert nup_main(["edit", str(base_nup), "--icon", str(png)]) != 0
    assert "Pillow" in capsys.readouterr().err
    assert TlvType.ICON not in tlvs_of(base_nup)  # nothing written


def test_png_and_oversized_images_become_a_256_jpeg(base_nup: Path, tmp_path: Path) -> None:
    Image = pytest.importorskip("PIL.Image")
    import os

    png = tmp_path / "cover.png"
    Image.frombytes("RGBA", (640, 360), os.urandom(640 * 360 * 4)).save(png)  # noise: hard to compress
    assert nup_main(["edit", str(base_nup), "--icon", str(png)]) == 0
    icon = tlvs_of(base_nup)[TlvType.ICON]
    assert icon.startswith(b"\xff\xd8\xff")
    assert len(icon) <= 0x100000   # within one TLV's cap (SPEC §3)
    assert Image.open(io.BytesIO(icon)).size == (256, 256)


def test_an_image_pillow_cannot_make_a_jpeg_of_is_a_one_line_error(base_nup: Path, tmp_path: Path,
                                                                   monkeypatch, capsys) -> None:
    Image = pytest.importorskip("PIL.Image")
    png = tmp_path / "cover.png"
    Image.new("RGB", (8, 8)).save(png)
    monkeypatch.setattr("nup.image.to_square", lambda image, _Image: 1 / 0)
    assert nup_main(["edit", str(base_nup), "--icon", str(png)]) == 1
    assert "cannot be converted to a JPEG" in capsys.readouterr().err


def test_pack_takes_images_and_tags_as_edit_does(base_dump: Path, tmp_path: Path) -> None:
    """`nup pack --icon` converts a PNG like `nup edit --icon`, and a language tag is
    stored lowercased by both."""
    from conftest import BASE_TITLE_ID

    Image = pytest.importorskip("PIL.Image")
    png = tmp_path / "cover.png"
    Image.new("RGB", (64, 64), (200, 30, 30)).save(png)
    jpeg = tmp_path / "ja.jpg"
    jpeg.write_bytes(JPEG)
    out = tmp_path / "x.nup"
    assert nup_main(["pack", str(base_dump), "-o", str(out), f"--title-id={BASE_TITLE_ID:x}",
                     "--icon", str(png), "--lang-name", "EN-GB=Wonder", "--lang-icon", f"JA={jpeg}"]) == 0
    tlvs = tlvs_of(out)
    assert Image.open(io.BytesIO(tlvs[TlvType.ICON])).size == (256, 256)
    assert parse_localized(memoryview(tlvs[TlvType.LOCALIZED_ICON])) == {"ja": JPEG}
    assert nup_main(["edit", str(out), "--lang-name", "en-gb=Wonder 2"]) == 0
    assert parse_localized(memoryview(tlvs_of(out)[TlvType.LOCALIZED_TITLE])) == {"en-gb": b"Wonder 2"}