"""Shared fixtures: synthetic Switch dumps and container builders."""

import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nup.cli import main as nup_main  # noqa: E402

BASE_TITLE_ID = 0x010074A01BF12000
UPDATE_TITLE_ID = BASE_TITLE_ID + 0x800
ADDON_TITLE_ID = BASE_TITLE_ID + 0x1000

REAL_DUMPS = Path(os.environ.get("NUP_TEST_REAL_ROOT", "/home/cat/Documents/NX2/Jeux"))


def npdm_bytes(program_id: int) -> bytes:
    aci0_offset = 0x380 + 0x1C0
    header = b"META" + os.urandom(0x380 - 4)
    body = bytearray(os.urandom(0x100))
    aci0 = bytearray(b"ACI0" + bytes(12))
    aci0 += struct.pack("<Q", program_id)   # as the console has it: 01… a Switch program, 04… a Switch 2 one (SPEC §4)
    aci0 += bytes(aci0_offset - len(aci0) - 0x14)
    return header + body + bytes(aci0)


def nso_bytes(payload_size: int = 5000, seed: bytes = b"") -> bytes:
    build_id = (seed + bytes(0x20))[:0x20]
    body = os.urandom(max(payload_size - 0x60, 0))
    return b"NSO0" + bytes(0x3C) + build_id + body


def make_dump(root: Path, *, title_id: int, seed: bytes = b"") -> Path:
    (root / "exefs").mkdir(parents=True, exist_ok=True)
    (root / "romfs").mkdir(parents=True, exist_ok=True)
    (root / "exefs" / "main").write_bytes(nso_bytes(5000, seed))
    (root / "exefs" / "main.npdm").write_bytes(npdm_bytes(title_id))
    return root


@pytest.fixture
def base_dump(tmp_path: Path) -> Path:
    root = make_dump(tmp_path / "DKB-base", title_id=BASE_TITLE_ID, seed=b"base-main")
    (root / "romfs" / "small.bin").write_bytes(b"hello")
    (root / "romfs" / "empty.bin").write_bytes(b"")
    (root / "romfs" / "big.bin").write_bytes(os.urandom(0x3000))
    (root / "romfs" / "data").mkdir()
    (root / "romfs" / "data" / "table.bin").write_bytes(os.urandom(0x150))
    (root / "romfs" / "junk.listing").write_bytes(b"dump artifact")
    (root / "romfs" / "todelete.bin").write_bytes(b"remove me")
    return root


@pytest.fixture
def update_dump(tmp_path: Path) -> Path:
    root = make_dump(tmp_path / "DKB-update", title_id=UPDATE_TITLE_ID, seed=b"update-main")
    (root / "romfs" / "small.bin").write_bytes(b"HELLO")
    (root / "romfs" / "big.bin").write_bytes(os.urandom(0x4000))
    (root / "romfs" / "extra.bin").write_bytes(b"added in update")
    return root


@pytest.fixture
def addon_dump(tmp_path: Path) -> Path:
    root = make_dump(tmp_path / "dkc0", title_id=ADDON_TITLE_ID, seed=b"addon-main")
    (root / "romfs" / "level.pack.zs").write_bytes(os.urandom(0x700))
    return root


def pack_base(dump: Path, out: Path, **kwargs) -> Path:
    args = ["pack", str(dump), "-o", str(out)]
    args += [f"--{key.replace("_", "-")}={value}" for key, value in kwargs.items()]
    assert nup_main(args) == 0
    return out


def pack_update(dump: Path, base_nup: Path, out: Path, version: int, chain=None, **kwargs) -> Path:
    args = ["pack", str(dump), "--base", str(base_nup), "-o", str(out), f"--version={version}"]
    links = [chain] if isinstance(chain, (str, Path)) else list(chain or [])
    for link in links:
        args += ["--chain", str(link)]
    args += [f"--{key.replace("_", "-")}={value}" for key, value in kwargs.items()]
    assert nup_main(args) == 0
    return out


@pytest.fixture
def base_nup(base_dump: Path, tmp_path: Path) -> Path:
    return pack_base(
        base_dump,
        tmp_path / "base.nup",
        name="Test Title",
        publisher="Test Pub",
        display_version="1.0.0",
    )


@pytest.fixture
def update_nup(update_dump: Path, base_nup: Path, tmp_path: Path) -> Path:
    return pack_update(
        update_dump,
        base_nup,
        tmp_path / "update.nup",
        458752,
        display_version="3.2.0",
    )


@pytest.fixture
def standalone_nup(base_dump: Path, update_dump: Path, tmp_path: Path) -> Path:
    from nup.pack import pack_standalone_container

    out = tmp_path / "standalone.nup"
    pack_standalone_container(
        str(out),
        str(base_dump),
        str(update_dump),
        update_version=458752,
        base_title_id=BASE_TITLE_ID,
        base_tlvs={0x0005: b"Test Title"},
    )
    return out


def tree_of(root: Path) -> dict[str, bytes]:
    files = {}
    for path in root.rglob("*"):
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def flip_byte(path: Path, offset: int) -> Path:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    corrupt = path.with_suffix(".corrupt.nup")
    corrupt.write_bytes(data)
    return corrupt
