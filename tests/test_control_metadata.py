"""Title metadata from the dump's Control content (SPEC §3.1)."""

from pathlib import Path

import pytest

from conftest import BASE_TITLE_ID, make_dump, nup_main
from nup.layout import TlvType, parse_localized
from nup.nacp import LANGUAGES, parse_nacp
from nup.reader import read_container

APP = BASE_TITLE_ID


def nacp(names: dict[str, tuple[str, str]], display_version: str) -> bytes:
    """A 0x4000-byte NACP; ``names`` maps a NACP language to (name, publisher)."""
    data = bytearray(0x4000)
    slots = [language for language, _tag in LANGUAGES]
    for language, (name, publisher) in names.items():
        entry = slots.index(language) * 0x300
        data[entry : entry + len(name.encode())] = name.encode()
        data[entry + 0x200 : entry + 0x200 + len(publisher.encode())] = publisher.encode()
    data[0x3060 : 0x3060 + len(display_version)] = display_version.encode()
    return bytes(data)


def add_control(content: Path, display_version: str, icon_size: int = 0x800, **names) -> None:
    control = content / "control"
    control.mkdir(parents=True, exist_ok=True)
    titles = names or {"AmericanEnglish": ("Wonder Title", "Wonder Pub"),
                       "Japanese": ("ワンダー", "ワンダー社"),
                       "BritishEnglish": ("Wonder Title", "Wonder Pub")}
    (control / "control.nacp").write_bytes(nacp(titles, display_version))
    for language in titles:
        (control / f"icon_{language}.dat").write_bytes(b"\xff\xd8" + language.encode() * (icon_size // 16))


@pytest.fixture
def console_bundle(tmp_path: Path) -> Path:
    root = tmp_path / "Wonder"
    make_dump(root / "base/program/0", title_id=APP, seed=b"base")
    (root / "base/program/0/romfs/a.bin").write_bytes(b"a" * 100)
    add_control(root / "base/program/0", "1.0.0")
    for version, display in ((65536, "1.0.1"), (131072, "1.1.0")):
        content = root / f"updates/{version}/program/0"
        make_dump(content, title_id=APP, seed=str(version).encode())
        (content / "romfs/a.bin").write_bytes(str(version).encode() * 50)
        add_control(content, display)
    return root


def record_of(path: Path, index: int = 0):
    with read_container(str(path)) as reader:
        return reader.meta.packages[index]


def text(record, tlv: TlvType) -> str | None:
    value = record.tlvs.get(tlv)
    return None if value is None else value.decode("utf-8")


def test_parse_nacp_reads_names_publisher_and_display_version() -> None:
    control = parse_nacp(nacp({"Japanese": ("ワンダー", "社"), "French": ("Merveille", "Éd")}, "2.0.1"))
    assert control.names == {"ja": "ワンダー", "fr": "Merveille"}
    assert control.default_language == "ja"  # first named slot in NACP order
    assert control.publishers["fr"] == "Éd"
    assert control.display_version == "2.0.1"


def test_bundle_takes_each_package_metadata_from_its_own_nacp(
        console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle)]) == 0
    base = record_of(tmp_path / "Wonder.nup")
    assert text(base, TlvType.TITLE_NAME) == "Wonder Title"
    assert text(base, TlvType.PUBLISHER) == "Wonder Pub"
    assert text(base, TlvType.DISPLAY_VERSION) == "1.0.0"
    # en-GB repeats the default name, so only Japanese is localized
    localized = parse_localized(memoryview(base.tlvs[TlvType.LOCALIZED_TITLE]))
    assert localized == {"ja": "ワンダー".encode()}
    icon = console_bundle / "base/program/0/control/icon_AmericanEnglish.dat"
    assert base.tlvs[TlvType.ICON] == icon.read_bytes()
    for version, display in ((65536, "1.0.1"), (131072, "1.1.0")):
        update = record_of(tmp_path / f"Wonder.update.{version}.nup")
        assert text(update, TlvType.DISPLAY_VERSION) == display
        # identity TLVs live on the base record (SPEC §3)
        assert {TlvType.TITLE_NAME, TlvType.ICON, TlvType.LOCALIZED_TITLE}.isdisjoint(update.tlvs)


def test_flags_override_the_nacp(console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle), "--name", "Renamed",
                     "--display-version", "9.9.9"]) == 0
    base = record_of(tmp_path / "Renamed.nup")
    assert text(base, TlvType.TITLE_NAME) == "Renamed"
    assert text(base, TlvType.PUBLISHER) == "Wonder Pub"
    # the display version names the newest package, the version dumped; the others keep their own
    assert text(base, TlvType.DISPLAY_VERSION) == "1.0.0"
    assert text(record_of(tmp_path / "Renamed.update.65536.nup"), TlvType.DISPLAY_VERSION) == "1.0.1"
    assert text(record_of(tmp_path / "Renamed.update.131072.nup"), TlvType.DISPLAY_VERSION) == "9.9.9"


def test_display_version_flag_names_the_update_of_a_dump_without_control(
        tmp_path: Path, monkeypatch) -> None:
    """A Yoink bundle has no control/: the flag goes on the update, not the base, in a
    bundle pack and in a standalone one."""
    root = tmp_path / "Yoink"
    make_dump(root / "base", title_id=APP, seed=b"b")
    make_dump(root / "updates/65536", title_id=APP, seed=b"u")
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(root), "--display-version", "1.2.0"]) == 0
    assert TlvType.DISPLAY_VERSION not in record_of(tmp_path / "base.nup").tlvs
    assert text(record_of(tmp_path / "65536.update.65536.nup"), TlvType.DISPLAY_VERSION) == "1.2.0"
    out = tmp_path / "standalone.nup"
    assert nup_main(["pack", str(root), "--kind", "standalone", "--display-version", "1.2.0",
                     "-o", str(out), "--title-id", f"{APP:x}"]) == 0
    with read_container(str(out)) as reader:
        base, update = reader.meta.packages
    assert TlvType.DISPLAY_VERSION not in base.tlvs
    assert text(update, TlvType.DISPLAY_VERSION) == "1.2.0"


def test_lang_name_flag_merges_with_the_nacp_names(tmp_path: Path) -> None:
    """--lang-name sets its own language: the Control content's other names stay."""
    content = make_dump(tmp_path / "named", title_id=APP, seed=b"n")
    add_control(content, "1.0.0")
    out = tmp_path / "named.nup"
    assert nup_main(["pack", str(content), "-o", str(out), "--lang-name", "ko=원더"]) == 0
    localized = parse_localized(memoryview(record_of(out).tlvs[TlvType.LOCALIZED_TITLE]))
    assert localized == {"ja": "ワンダー".encode(), "ko": "원더".encode()}


def test_update_dump_alone_takes_the_full_set(tmp_path: Path) -> None:
    content = make_dump(tmp_path / "upd", title_id=APP, seed=b"u")
    (content / "romfs/a.bin").write_bytes(b"a")
    add_control(content, "3.2.0")
    out = tmp_path / "out.nup"
    assert nup_main(["pack", str(content), "-o", str(out)]) == 0
    record = record_of(out)
    assert text(record, TlvType.TITLE_NAME) == "Wonder Title"
    assert text(record, TlvType.DISPLAY_VERSION) == "3.2.0"


def test_one_display_version_flag_cannot_name_several_updates(tmp_path: Path, capsys) -> None:
    root = tmp_path / "OnlyUpdates"
    for version in (65536, 131072):
        make_dump(root / f"updates/{version}", title_id=APP, seed=str(version).encode())
        (root / f"updates/{version}/romfs/a.bin").write_bytes(b"a")
    assert nup_main(["pack", str(root), "--display-version", "1.0.0"]) != 0
    assert "--display-version names one package" in capsys.readouterr().err
    # nor can one -o file hold them: each would overwrite the one before
    assert nup_main(["pack", str(root), "-o", str(tmp_path / "one.nup")]) != 0
    assert "-o names one file" in capsys.readouterr().err
    assert not (tmp_path / "one.nup").exists()


def test_parse_nacp_reads_a_compressed_title_area() -> None:
    """Newer SDKs deflate the title entries (Super Mario Bros. Wonder 1.2.1): u16 size + raw deflate."""
    import struct, zlib
    plain = nacp({"AmericanEnglish": ("Wonder Title", "Wonder Pub")}, "1.2.1")
    titles = plain[: 16 * 0x300] + bytes(16 * 0x300)   # 32 entries when inflated
    packer = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = packer.compress(titles) + packer.flush()
    data = bytearray(plain)
    data[: 16 * 0x300] = bytes(16 * 0x300)   # in place of the 16 plain entries
    data[: 2 + len(packed)] = struct.pack("<H", len(packed)) + packed
    control = parse_nacp(bytes(data))
    assert control.names == {"en-US": "Wonder Title"} and control.publishers["en-US"] == "Wonder Pub"
    assert control.display_version == "1.2.1"


def test_console_sized_icons_are_stored_as_distributed(tmp_path: Path) -> None:
    """Console icons are 150-250 KB, past the old 64 KiB block: the default one byte for byte, the other languages'
    in the localized icon TLV where they differ from it (SPEC §3, §3.1, §10.3)."""
    content = make_dump(tmp_path / "big", title_id=APP, seed=b"b")
    add_control(content, "1.0.0", icon_size=200_000)   # each language's bytes differ (add_control repeats its name)
    out = tmp_path / "big.nup"
    assert nup_main(["pack", str(content), "-o", str(out)]) == 0
    record = record_of(out)
    control = content / "control"
    assert record.tlvs[TlvType.ICON] == (control / "icon_AmericanEnglish.dat").read_bytes()
    localized = parse_localized(memoryview(record.tlvs[TlvType.LOCALIZED_ICON]))
    assert localized == {"ja": (control / "icon_Japanese.dat").read_bytes(),
                         "en-gb": (control / "icon_BritishEnglish.dat").read_bytes()}


def test_icon_flag_replaces_every_languages_icon(tmp_path: Path) -> None:
    """--icon replaces the console's image: its other-language icons are not added beside it."""
    content = make_dump(tmp_path / "big", title_id=APP, seed=b"b")
    add_control(content, "1.0.0", icon_size=200_000)
    cover = tmp_path / "cover.jpg"
    cover.write_bytes(b"\xff\xd8\xff\xe0" + b"new cover" * 100)
    out = tmp_path / "big.nup"
    assert nup_main(["pack", str(content), "-o", str(out), "--icon", str(cover)]) == 0
    record = record_of(out)
    assert record.tlvs[TlvType.ICON] == cover.read_bytes()
    assert TlvType.LOCALIZED_ICON not in record.tlvs


def test_icon_flag_naming_the_trees_own_icon_keeps_the_other_languages(tmp_path: Path) -> None:
    """--icon control/icon_<default>.dat is the console's image, not a new one for every language."""
    content = make_dump(tmp_path / "big", title_id=APP, seed=b"b")
    add_control(content, "1.0.0", icon_size=200_000)
    default = content / "control/icon_AmericanEnglish.dat"
    default.write_bytes(b"\xff\xd8\xff" + default.read_bytes())   # a JPEG --icon keeps as it is
    out = tmp_path / "big.nup"
    assert nup_main(["pack", str(content), "-o", str(out), "--icon", str(default)]) == 0
    assert set(parse_localized(memoryview(record_of(out).tlvs[TlvType.LOCALIZED_ICON]))) == {"ja", "en-gb"}


def test_lang_icon_flag_keeps_the_other_languages_icons(tmp_path: Path) -> None:
    """--lang-icon replaces its own language's icon: the console's other ones stay."""
    content = make_dump(tmp_path / "big", title_id=APP, seed=b"b")
    add_control(content, "1.0.0", icon_size=200_000)
    korean = tmp_path / "ko.jpg"
    korean.write_bytes(b"\xff\xd8\xff\xe0" + b"korean" * 100)
    out = tmp_path / "big.nup"
    assert nup_main(["pack", str(content), "-o", str(out), "--lang-icon", f"ko={korean}"]) == 0
    localized = parse_localized(memoryview(record_of(out).tlvs[TlvType.LOCALIZED_ICON]))
    control = content / "control"
    assert localized == {"ko": korean.read_bytes(),
                         "ja": (control / "icon_Japanese.dat").read_bytes(),
                         "en-gb": (control / "icon_BritishEnglish.dat").read_bytes()}


def test_one_image_for_every_language_is_stored_once(tmp_path: Path) -> None:
    content = make_dump(tmp_path / "same", title_id=APP, seed=b"s")
    add_control(content, "1.0.0")
    for icon in (content / "control").glob("icon_*.dat"):
        icon.write_bytes(b"\xff\xd8\xff" + b"one image" * 20_000)
    out = tmp_path / "same.nup"
    assert nup_main(["pack", str(content), "-o", str(out)]) == 0
    record = record_of(out)
    assert len(record.tlvs[TlvType.ICON]) == 3 + 9 * 20_000
    assert TlvType.LOCALIZED_ICON not in record.tlvs


def test_icon_over_the_cap_is_reencoded(tmp_path: Path) -> None:
    """An icon over one TLV's 1 MiB cap is stored as a 256x256 JPEG within it, with Pillow (SPEC §3.1)."""
    pil = pytest.importorskip("PIL.Image")
    import io, os
    content = make_dump(tmp_path / "huge", title_id=APP, seed=b"h")
    add_control(content, "1.0.0")
    noise = pil.frombytes("RGB", (1024, 1024), os.urandom(1024 * 1024 * 3))   # random pixels: a JPEG over 1 MiB
    big = io.BytesIO(); noise.save(big, format="JPEG", quality=100)
    assert big.tell() > 0x100000
    for icon in (content / "control").glob("icon_*.dat"):
        icon.write_bytes(big.getvalue())
    out = tmp_path / "huge.nup"
    assert nup_main(["pack", str(content), "-o", str(out)]) == 0
    icon = record_of(out).tlvs[TlvType.ICON]
    assert icon[:3] == b"\xff\xd8\xff" and len(icon) <= 0x100000
    assert pil.open(io.BytesIO(icon)).size == (256, 256)


def test_icon_left_out_when_it_cannot_fit(tmp_path: Path) -> None:
    """An icon over the cap that is no image Pillow can read is left out (the name still comes from the NACP)."""
    content = make_dump(tmp_path / "big", title_id=APP, seed=b"b")
    add_control(content, "1.0.0", icon_size=0x200000)   # (add_control's sizes scale with the language name: all over 1 MiB)
    out = tmp_path / "big.nup"
    assert nup_main(["pack", str(content), "-o", str(out)]) == 0
    record = record_of(out)
    assert TlvType.ICON not in record.tlvs
    assert text(record, TlvType.TITLE_NAME) == "Wonder Title"


def test_base_without_control_takes_the_newest_updates_identity(
        console_bundle: Path, tmp_path: Path, monkeypatch) -> None:
    """A dump of an installed game: the update's Control replaced the base's (SPEC §3.1)."""
    import shutil
    shutil.rmtree(console_bundle / "base/program/0/control")
    add_control(console_bundle / "updates/65536/program/0", "1.0.1", AmericanEnglish=("Old Name", "Old Pub"))
    monkeypatch.chdir(tmp_path)
    assert nup_main(["pack", str(console_bundle)]) == 0
    base = record_of(tmp_path / "Wonder.nup")
    assert text(base, TlvType.TITLE_NAME) == "Wonder Title" and text(base, TlvType.PUBLISHER) == "Wonder Pub"   # 131072's, the newest
    icon = console_bundle / "updates/131072/program/0/control/icon_AmericanEnglish.dat"
    assert base.tlvs[TlvType.ICON] == icon.read_bytes()
    assert TlvType.DISPLAY_VERSION not in base.tlvs   # the update's version is not the base's
    assert text(record_of(tmp_path / "Wonder.update.131072.nup"), TlvType.DISPLAY_VERSION) == "1.1.0"


def test_dump_without_control_keeps_working(base_dump: Path, tmp_path: Path) -> None:
    out = tmp_path / "plain.nup"
    assert nup_main(["pack", str(base_dump), "-o", str(out)]) == 0
    assert TlvType.TITLE_NAME not in record_of(out).tlvs
