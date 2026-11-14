"""Known-good lists (SPEC §6.5)."""

import json

import pytest

from conftest import BASE_TITLE_ID, nup_main
from nup.errors import NupError
from nup.hashlist import check_against, format_list, parse_list, read_lists
from nup.layout import META_NAME
from nup.reader import read_container
from nup.verify import package_label


def test_hashlist_round_trip(base_nup, update_nup, tmp_path, capsys):
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(base_nup), str(update_nup), "-o", str(listing)]) == 0
    entries = parse_list(listing.read_text(encoding="utf-8"))
    assert [e.kind for e in entries] == ["base", "update"]
    # the update lands on the base listed beside it: its state is recomputed and sized
    assert entries[0].files is not None and entries[1].files is not None
    assert format_list(entries) == listing.read_text(encoding="utf-8")
    capsys.readouterr()
    assert nup_main(["verify", str(base_nup), "--level", "full", "--against", str(listing)]) == 0
    assert "known:" in capsys.readouterr().out
    # bind hashes no file data: the container only claims the state (SPEC §6.5)
    assert nup_main(["verify", str(base_nup), "--level", "bind", "--against", str(listing), "--json"]) == 1
    (known,) = json.loads(capsys.readouterr().out)["known"]
    assert known["listed"] and not known["known"] and "not hashed" in known["unverified"]
    # a diff's hash is only proven by materializing it on its base
    assert nup_main(["verify", str(update_nup), "--against", str(listing)]) == 1
    assert "not proven" in capsys.readouterr().out
    assert nup_main(["verify", str(update_nup), "--against", str(listing), "--base", str(base_nup)]) == 0
    assert "known:" in capsys.readouterr().out


def test_a_forged_update_hash_is_not_known(base_nup, update_nup, tmp_path):
    """An update whose record claims a listed state it does not produce."""
    from nup.edit import EditOps, edit_container

    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(update_nup), "--base", str(base_nup), "-o", str(listing)]) == 0
    assert parse_list(listing.read_text(encoding="utf-8"))[0].files is not None   # materialized: sized
    extra = tmp_path / "extra.bin"
    extra.write_bytes(b"not in the listed state")
    forged = tmp_path / "forged.nup"
    with read_container(str(update_nup)) as reader:
        scope = package_label(reader, reader.meta.packages[0])
    edit_container(str(update_nup), str(forged),
                   EditOps(package_selector="0", add_files={f"{scope}/extra.bin": str(extra)}))
    with read_container(str(update_nup)) as original, read_container(str(forged)) as reader, \
            read_container(str(base_nup)) as base:
        reader.meta.packages[0].content_hash = original.meta.packages[0].content_hash   # the forged claim
        (match,) = check_against(reader, read_lists([str(listing)]), hashed={scope}, bases=[base])
    assert not match.ok and "does not match the state" in match.problem
    # nor does hashlist vouch for it: edited without --base, the stored hash is not its state
    assert nup_main(["hashlist", str(forged), "--base", str(base_nup)]) == 1


def test_a_base_with_tampered_data_proves_nothing(base_nup, update_nup, tmp_path, capsys):
    """A diff's state takes its unchanged files from the base: --base is hashed too."""
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(update_nup), "--base", str(base_nup), "-o", str(listing)]) == 0
    tampered = tmp_path / "tampered.nup"
    data = bytearray(base_nup.read_bytes())
    with read_container(str(base_nup)) as reader:
        entry = next(e for e in reader.entries if e.size and e.name != META_NAME)
        data[reader.data_start + entry.data_offset] ^= 0xFF
    tampered.write_bytes(bytes(data))
    capsys.readouterr()
    assert nup_main(["hashlist", str(update_nup), "--base", str(tampered)]) == 1
    assert "hash mismatch" in capsys.readouterr().err
    assert nup_main(["verify", str(update_nup), "--against", str(listing), "--base", str(tampered)]) == 1
    assert "hash mismatch" in capsys.readouterr().err


def test_a_diff_alone_is_listed_as_claimed(update_nup, tmp_path, capsys):
    """Without the base it lands on, a diff's stored hash is listed, unsized, with a warning."""
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(update_nup), "-o", str(listing)]) == 0
    assert parse_list(listing.read_text(encoding="utf-8"))[0].files is None
    assert "not recomputed" in capsys.readouterr().err


def test_an_unhashed_base_in_the_same_file_proves_nothing(standalone_nup, tmp_path, capsys):
    """--level package hashes one package: a diff landing on the file's unhashed base
    only claims its state (SPEC §6.5)."""
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(standalone_nup), "-o", str(listing)]) == 0
    with read_container(str(standalone_nup)) as reader:
        update = next(package_label(reader, r) for r in reader.meta.packages if r.kind.name == "UPDATE")
    capsys.readouterr()
    assert nup_main(["verify", str(standalone_nup), "--level", "package", "--package", update,
                     "--against", str(listing)]) == 1
    assert "were not hashed" in capsys.readouterr().out
    assert nup_main(["verify", str(standalone_nup), "--level", "full", "--against", str(listing)]) == 0
    # --package without --level hashes and looks up that package alone
    capsys.readouterr()
    assert nup_main(["verify", str(standalone_nup), "--package", "base", "--against", str(listing)]) == 0
    out = capsys.readouterr().out
    assert "package verification" in out and update not in out
    # the package --level package hashed is looked up, the one it left out is not
    assert nup_main(["verify", str(standalone_nup), "--level", "package", "--package", "base",
                     "--against", str(listing)]) == 0
    out = capsys.readouterr().out
    assert "base" in out and update not in out


def test_a_size_column_left_unknown_is_not_compared(base_nup, tmp_path, capsys):
    """A list line may give the file count and leave the bytes '-': only what it gives is checked."""
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(base_nup), "-o", str(listing)]) == 0
    lines = listing.read_text(encoding="utf-8").split("\n")
    fields = lines[2].split("\t")
    fields[6] = "-"
    lines[2] = "\t".join(fields)
    listing.write_text("\n".join(lines), encoding="utf-8")
    assert nup_main(["verify", str(base_nup), "--against", str(listing)]) == 0
    fields[5] = str(int(fields[5]) + 1)
    lines[2] = "\t".join(fields)
    listing.write_text("\n".join(lines), encoding="utf-8")
    capsys.readouterr()
    assert nup_main(["verify", str(base_nup), "--against", str(listing)]) == 1
    assert "files / - bytes" in capsys.readouterr().out


def test_a_deleted_path_the_base_lacks_lands_nowhere(update_nup):
    """As extract refuses it, the state a list proves is never one no reader builds."""
    from nup.diff import overlay_update_rows

    with read_container(str(update_nup)) as reader:
        with pytest.raises(NupError, match="which the tree does not contain"):
            overlay_update_rows(reader, reader.meta.packages[0], {})


@pytest.mark.parametrize("column, value", [(2, "-1"), (2, "0x0100000000000000"), (3, "+5"), (5, " 12")])
def test_list_numbers_are_plain_digits(base_nup, tmp_path, column, value):
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(base_nup), "-o", str(listing)]) == 0
    lines = listing.read_text(encoding="utf-8").split("\n")
    fields = lines[2].split("\t")
    fields[column] = value
    lines[2] = "\t".join(fields)
    with pytest.raises(NupError, match="plain decimal digits"):
        parse_list("\n".join(lines))


def test_a_list_saved_with_a_byte_order_mark(base_nup, tmp_path):
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(base_nup), "-o", str(listing)]) == 0
    listing.write_bytes(b"\xef\xbb\xbf" + listing.read_bytes())
    assert nup_main(["verify", str(base_nup), "--against", str(listing)]) == 0


def test_unknown_and_mismatched_packages_fail(base_nup, update_nup, tmp_path, capsys):
    listing = tmp_path / "known.nuplist"
    assert nup_main(["hashlist", str(update_nup), "-o", str(listing)]) == 0
    capsys.readouterr()
    assert nup_main(["verify", str(base_nup), "--against", str(listing)]) == 1
    assert "not in the list" in capsys.readouterr().out
    assert nup_main(["hashlist", str(base_nup), "-o", str(listing)]) == 0
    text = listing.read_text(encoding="utf-8").replace(f"{BASE_TITLE_ID:016x}", f"{BASE_TITLE_ID + 1:016x}")
    listing.write_text(text, encoding="utf-8")
    capsys.readouterr()
    assert nup_main(["verify", str(base_nup), "--against", str(listing)]) == 1
    assert "listed as base" in capsys.readouterr().out


def test_list_syntax_errors():
    with pytest.raises(NupError, match="first line"):
        parse_list("content_hash\tkind\n")
    with pytest.raises(NupError, match="64 lowercase hex"):
        parse_list("#nuplist 1\nABC\tbase\t0\t0\t0\t-\t-\tx\n")
    with pytest.raises(NupError, match="columns"):
        parse_list("#nuplist 1\n" + "a" * 64 + "\tbase\n")
    assert parse_list("#nuplist 1\n# a comment\n\n" + "a" * 64 + "\tbase\t0100\t0\t0\t-\t-\tname with spaces\n")[0].name \
        == "name with spaces"


@pytest.mark.parametrize("breaker", ["\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029"])
def test_names_with_line_breaks_round_trip(base_nup, tmp_path, breaker):
    listing = tmp_path / "known.nuplist"
    assert nup_main(["edit", str(base_nup), "--set-tlv", f"name=Won{breaker}der\tGame"]) == 0
    assert nup_main(["hashlist", str(base_nup), "-o", str(listing)]) == 0
    (entry,) = parse_list(listing.read_text(encoding="utf-8", newline=""))
    assert entry.name.startswith("Won der Game")
    assert nup_main(["verify", str(base_nup), "--level", "full", "--against", str(listing)]) == 0
