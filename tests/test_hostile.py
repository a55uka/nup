"""Hostile containers (SPEC §6.4)."""

import hashlib
import os
import struct
from pathlib import Path

import pytest

from conftest import BASE_TITLE_ID, nup_main
from nup.errors import NupError
from nup.extract import extract_package
from nup.reader import read_container
from nup.tree import (case_insensitive, collisions, check_extract_paths, normalization_insensitive,
                      windows_name_problem)


def data_start_of(data: bytes) -> int:
    _magic, count, table_size, _reserved = struct.unpack_from("<4sIII", data)
    return 0x10 + 0x40 * count + table_size


def re_sign_all(data: bytearray) -> None:
    """What a malicious packer does after tampering: recompute the header hash
    in meta.nup, then meta.nup's digest. No secret stops it (SPEC §6.4)."""
    start = data_start_of(data)
    meta_size = struct.unpack_from("<Q", data, 0x10 + 0x08)[0]
    data[start + 0x18:start + 0x38] = hashlib.sha256(bytes(data[:start])).digest()
    end = start + meta_size
    data[end - 32:end] = hashlib.sha256(bytes(data[start:end - 32])).digest()


def tampered(base_nup: Path, tmp_path: Path, change) -> Path:
    data = bytearray(base_nup.read_bytes())
    change(data)
    re_sign_all(data)
    out = tmp_path / "hostile.nup"
    out.write_bytes(data)
    return out


def entry_field(index: int, offset: int) -> int:
    return 0x10 + 0x40 * index + offset


def link(target: Path, at: Path) -> None:
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(at))
    else:
        os.symlink(target, at, target_is_directory=True)


# ---- readers (§6.4 rules 1-3) ----

def test_resigned_container_still_opens(base_nup, tmp_path):
    with read_container(str(tampered(base_nup, tmp_path, lambda data: None))):
        pass


def test_duplicate_entry_names_are_refused(base_nup, tmp_path):
    def same_name(data):
        first = struct.unpack_from("<I", data, entry_field(1, 0x10))[0]
        struct.pack_into("<I", data, entry_field(2, 0x10), first)
    with pytest.raises(NupError, match="appears twice"):
        read_container(str(tampered(base_nup, tmp_path, same_name)))


def test_wrong_hashed_size_is_refused(base_nup, tmp_path):
    def hashed(data):
        size = struct.unpack_from("<Q", data, entry_field(3, 0x08))[0]
        struct.pack_into("<I", data, entry_field(3, 0x14), min(size, 0x200) ^ 1)
    with pytest.raises(NupError, match="hashed size"):
        read_container(str(tampered(base_nup, tmp_path, hashed)))


def test_entry_outside_the_file_is_refused(base_nup, tmp_path):
    def far(data):
        offset = struct.unpack_from("<Q", data, entry_field(2, 0x00))[0]
        struct.pack_into("<Q", data, entry_field(2, 0x00), offset + 0x200 * 1_000_000)
    with pytest.raises(NupError, match="outside the container"):
        read_container(str(tampered(base_nup, tmp_path, far)))


# ---- extractors (§6.4 rules 4-6) ----

def test_extract_never_writes_through_a_link(base_nup, tmp_path):
    out = tmp_path / "out"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (out / "base").mkdir(parents=True)
    link(elsewhere, out / "base" / "romfs")
    with read_container(str(base_nup)) as reader:
        with pytest.raises(NupError, match="through the link"):
            extract_package(reader, reader.meta.packages[0], str(out))
    assert list(elsewhere.iterdir()) == []


def test_extract_never_writes_through_a_linked_scope_folder(base_nup, tmp_path):
    """out/base/ itself a link: the scope folder is checked as the paths in it are."""
    out = tmp_path / "out"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    out.mkdir()
    link(elsewhere, out / "base")
    with read_container(str(base_nup)) as reader:
        with pytest.raises(NupError, match="through the link"):
            extract_package(reader, reader.meta.packages[0], str(out))
    assert list(elsewhere.iterdir()) == []


def test_windows_name_rules():
    assert windows_name_problem("CON") and windows_name_problem("aux.bin")
    assert windows_name_problem("a:b") and windows_name_problem("trail.")
    assert windows_name_problem("lpt9.txt") and windows_name_problem("x\x01")
    assert windows_name_problem("Console.bfres") is None and windows_name_problem("data.bin") is None
    assert windows_name_problem("NUL .txt") and windows_name_problem("conout$")
    assert windows_name_problem("COM¹.log") and windows_name_problem("lpt³")


def test_case_collisions_refused_only_where_case_folds(tmp_path):
    assert collisions(["romfs/A.bin", "romfs/a.bin", "romfs/b.bin"], str.lower) == [("romfs/A.bin", "romfs/a.bin")]
    assert collisions(["romfs/straße", "romfs/strasse"], str.lower) == []   # no filesystem folds ß to ss
    if case_insensitive(str(tmp_path)):
        with pytest.raises(NupError, match="folds case"):
            check_extract_paths(str(tmp_path), ["romfs/A.bin", "romfs/a.bin"])
    else:
        check_extract_paths(str(tmp_path), ["romfs/A.bin", "romfs/a.bin"])


def test_a_container_is_never_written_over_its_own_source(base_nup, capsys):
    """`nup edit x.nup -o x.nup` would empty x.nup before copying its data out of it."""
    before = base_nup.read_bytes()
    assert nup_main(["edit", str(base_nup), "-o", str(base_nup), "--set-tlv", "name=Foo"]) == 1
    assert "also where this container's data is read from" in capsys.readouterr().err
    assert base_nup.read_bytes() == before
    assert nup_main(["edit", str(base_nup), "--set-tlv", "name=Foo"]) == 0   # in place: through a temp file


def test_the_folding_probes_leave_existing_files_alone(tmp_path):
    for name in (".NupCaseProbe", ".nupcaseprobe", ".NupFormProbeé"):
        (tmp_path / name).write_bytes(b"keep me")
    before = sorted(p.name for p in tmp_path.iterdir())
    case_insensitive(str(tmp_path))
    normalization_insensitive(str(tmp_path))
    assert sorted(p.name for p in tmp_path.iterdir()) == before   # no probe left behind
    for name in (".NupCaseProbe", ".nupcaseprobe", ".NupFormProbeé"):
        assert (tmp_path / name).read_bytes() == b"keep me"


def test_folder_collisions_refused(tmp_path):
    """A file that is another path's folder, anywhere; a file and a folder, or two
    folders, whose names differ only in case, where the folder folds case."""
    with pytest.raises(NupError, match="is a file and the folder of"):
        check_extract_paths(str(tmp_path), ["romfs/data", "romfs/data/x.bin"])
    for paths in (["romfs/Data", "romfs/data/x.bin"], ["romfs/Data/x.bin", "romfs/data/y.bin"]):
        if case_insensitive(str(tmp_path)):
            with pytest.raises(NupError, match="folds case"):
                check_extract_paths(str(tmp_path), paths)
        else:
            check_extract_paths(str(tmp_path), paths)


def test_normalization_collisions_refused_only_where_the_folder_folds_them(tmp_path):
    """Composed and decomposed spellings of one name (APFS and HFS+ treat them as one)."""
    composed, decomposed = "romfs/café.bin", "romfs/café.bin"
    if normalization_insensitive(str(tmp_path)):
        with pytest.raises(NupError, match="Unicode normalization"):
            check_extract_paths(str(tmp_path), [composed, decomposed])
    else:
        check_extract_paths(str(tmp_path), [composed, decomposed])


# ---- packers (§6.4) ----

def test_packer_refuses_links_in_a_dump(base_dump, tmp_path, capsys):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "secret.bin").write_bytes(b"not part of the dump")
    link(target, base_dump / "romfs" / "linked")
    assert nup_main(["pack", str(base_dump), "-o", str(tmp_path / "x.nup"),
                     "--title-id", f"{BASE_TITLE_ID:x}"]) == 1
    assert "is a link" in capsys.readouterr().err
