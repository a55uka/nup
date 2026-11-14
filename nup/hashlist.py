"""Known-good lists (SPEC §6.5): package states identified by content hash.

A list is UTF-8 tab-separated text, one package state per line, keyed by
the content hash of SPEC §6.2 (the materialized state, so the same state
matches however it was containered).  No keys or signatures: a list is as
trustworthy as the place it came from.

    #nuplist 1
    content_hash<TAB>kind<TAB>title_id<TAB>version<TAB>program<TAB>files<TAB>bytes<TAB>name
    <64 hex><TAB>base<TAB>010015100b514000<TAB>0<TAB>0<TAB>12345<TAB>3500000000<TAB>Wonder 1.0.0
"""

from dataclasses import dataclass
import re

from .diff import overlay_update_rows, sorted_identity
from .errors import NupError
from .layout import DELETED_NAME, DIFF_KINDS, FileRow, Kind, TlvType, content_hash
from .reader import NupReader

MAGIC = "#nuplist 1"
COLUMNS = ("content_hash", "kind", "title_id", "version", "program", "files", "bytes", "name")
KIND_NAMES = {kind: kind.name.lower() for kind in Kind}
UNKNOWN = "-"
HEX16 = re.compile(r"[0-9a-fA-F]{1,16}")
DIGITS = re.compile(r"[0-9]+")


@dataclass(slots=True, frozen=True)
class ListEntry:
    content_hash: str
    kind: str
    title_id: int
    version: int
    program: int
    files: int | None
    bytes: int | None
    name: str
    source: str = ""  # list file and line, for messages

    def same_identity(self, other: "ListEntry") -> bool:
        return (self.kind, self.title_id, self.version, self.program) == (
            other.kind, other.title_id, other.version, other.program)


@dataclass(slots=True)
class Match:
    label: str
    entry: ListEntry       # this container's package, as a list entry
    known: ListEntry | None
    problem: str | None    # identity disagreement with the list
    unverified: str | None = None  # why the hash is only claimed: data not hashed, diff not materialized

    @property
    def ok(self) -> bool:
        """Known, and proven: only a hash recomputed from hashed data says the
        data is the listed state (SPEC §6.5)."""
        return self.known is not None and self.problem is None and self.unverified is None


Rows = dict[str, FileRow]


def materialized_states(readers: list[NupReader]) -> dict[int, Rows]:
    """The materialized rows of every diff in readers that lands on a state they
    hold (a base or add-on, or a diff that does; SPEC §5.1, §5.4), keyed by
    id(record): its content hash recomputed rather than taken from the record."""
    return proven_states(readers)[0]


def proven_states(readers: list[NupReader], usable=None) -> tuple[dict[int, Rows], set[int]]:
    """(materialized_states, proven): proven holds id(record) of each diff whose
    state is built from usable packages only, usable(reader, record) saying
    whether a package's file data was hashed (by default every package's)."""
    ok = (lambda _reader, _record: True) if usable is None else usable
    pool: dict[bytes, Rows] = {}
    proven_identities: set[bytes] = set()
    for reader in readers:
        for record in reader.meta.packages:
            if record.kind not in DIFF_KINDS:
                rows = {row.path: row for row in record.files}
                identity = sorted_identity(rows.values())
                pool.setdefault(identity, rows)
                if ok(reader, record):
                    proven_identities.add(identity)
    pending = sorted(((reader, record) for reader in readers for record in reader.meta.packages
                      if record.kind in DIFF_KINDS), key=lambda item: item[1].version)
    states: dict[int, Rows] = {}
    landed: list[tuple[NupReader, object, bytes]] = []   # (reader, record, the identity it produces)
    progress = True
    while pending and progress:  # a chain lands link by link, whatever order the readers came in
        progress = False
        for item in list(pending):
            reader, record = item
            base = pool.get(record.base_content_hash)
            if base is None:
                continue
            rows = dict(base)
            overlay_update_rows(reader, record, rows)
            identity = sorted_identity(rows.values())
            pool.setdefault(identity, rows)
            states[id(record)] = rows
            landed.append((reader, record, identity))
            pending.remove(item)
            progress = True
    # a state is proven when some chain of usable packages produces it
    proven: set[int] = set()
    progress = True
    while progress:
        progress = False
        for reader, record, identity in landed:
            if id(record) not in proven and ok(reader, record) \
                    and record.base_content_hash in proven_identities:
                proven.add(id(record))
                proven_identities.add(identity)
                progress = True
    return states, proven


def entry_of(reader: NupReader, record, materialized: Rows | None = None) -> ListEntry:
    """A package as a list entry. A base or add-on's content hash is recomputed
    from its file table; a diff's from the state it materializes when that is
    given (materialized_states), else it is the record's stored claim."""
    if materialized is not None:
        rows = list(materialized.values())
        digest = sorted_identity(rows)
    else:
        rows = [row for row in record.files if row.path != DELETED_NAME]
        digest = record.content_hash if record.kind in DIFF_KINDS else content_hash(record.files)
    known_size = materialized is not None or record.kind not in DIFF_KINDS
    name = " ".join(
        record.tlvs[t].decode("utf-8", "replace") for t in (TlvType.TITLE_NAME, TlvType.DISPLAY_VERSION)
        if t in record.tlvs
    )
    return ListEntry(
        digest.hex(), KIND_NAMES[record.kind], record.title_id, record.version, record.program_index,
        len(rows) if known_size else None, sum(row.size for row in rows) if known_size else None,
        " ".join(name.split()),  # every tab and line break (\r, \x85, U+2028, ...) is one space
    )


def value(number: int | None) -> str:
    """A size column: the number, or '-' when it is unknown."""
    return UNKNOWN if number is None else str(number)


def format_entry(entry: ListEntry) -> str:
    return "\t".join((entry.content_hash, entry.kind, f"{entry.title_id:016x}", str(entry.version),
                      str(entry.program), value(entry.files), value(entry.bytes), entry.name))


def format_list(entries: list[ListEntry]) -> str:
    return "\n".join([MAGIC, "\t".join(COLUMNS), *(format_entry(e) for e in entries)]) + "\n"


def parse_list(text: str, source: str = "list") -> list[ListEntry]:
    text = text.removeprefix("﻿")  # a byte-order mark an editor saved
    lines = [line.removesuffix("\r") for line in text.split("\n")]  # \n ends a line, nothing else
    if not lines or lines[0].strip() != MAGIC:
        raise NupError(f"{source}: not a known-good list (first line must be {MAGIC!r}, SPEC §6.5)")
    entries = []
    for number, line in enumerate(lines[1:], 2):
        if not line.strip() or line.startswith("#") or line.split("\t", 1)[0] == COLUMNS[0]:
            continue
        fields = line.split("\t")
        if len(fields) != len(COLUMNS):
            raise NupError(f"{source}:{number}: {len(fields)} columns, expected {len(COLUMNS)}")
        digest, kind, title, version, program, files, size, name = fields
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise NupError(f"{source}:{number}: content hash must be 64 lowercase hex digits")
        if kind not in KIND_NAMES.values():
            raise NupError(f"{source}:{number}: unknown kind {kind!r}")
        # plain digits only, as format_entry writes them: no sign, prefix or padding
        if not HEX16.fullmatch(title) or not all(
                DIGITS.fullmatch(value) for value in (version, program)) or not all(
                value == UNKNOWN or DIGITS.fullmatch(value) for value in (files, size)):
            raise NupError(f"{source}:{number}: title id must be up to 16 hex digits, the other numbers "
                           f"plain decimal digits ('{UNKNOWN}' for an unknown size)")
        try:
            entries.append(ListEntry(
                digest, kind, int(title, 16), int(version), int(program),
                None if files == UNKNOWN else int(files), None if size == UNKNOWN else int(size),
                name, f"{source}:{number}",
            ))
        except ValueError as error:
            raise NupError(f"{source}:{number}: {error}") from None
    return entries


def read_lists(paths: list[str]) -> dict[str, list[ListEntry]]:
    index: dict[str, list[ListEntry]] = {}
    for path in paths:
        # utf-8-sig: an editor's byte-order mark is not part of the first line
        with open(path, encoding="utf-8-sig", newline="") as handle:  # parse_list splits the lines
            for entry in parse_list(handle.read(), path):
                index.setdefault(entry.content_hash, []).append(entry)
    return index


def check_against(reader: NupReader, index: dict[str, list[ListEntry]], *,
                  hashed: set[str], bases: list[NupReader] = (),
                  only: set[str] | None = None) -> list[Match]:
    """Look every package up (SPEC §6.5), or those whose labels are in only.
    hashed: the labels of the packages whose file data was hashed against
    their file table; bases: containers holding the states the diffs land
    on, so their hashes are recomputed."""
    from .verify import package_label

    # a package of this file whose data was not hashed proves no state it lands on
    claimed, proven = proven_states(
        [*bases, reader],
        lambda owner, record: owner is not reader or package_label(reader, record) in hashed,
    )
    matches = []
    for record in reader.meta.packages:
        if only is not None and package_label(reader, record) not in only:
            continue
        materialized = claimed.get(id(record)) if id(record) in proven else None
        entry = entry_of(reader, record, materialized)
        label = package_label(reader, record)
        unverified = None
        if label not in hashed:
            unverified = "file data not hashed (use --level full)"
        elif record.kind in DIFF_KINDS and materialized is None:
            unverified = (
                "the package(s) it lands on in this file were not hashed (use --level full)"
                if id(record) in claimed else
                "a diff's content hash is the state it produces: pass --base with the "
                "container(s) it lands on to recompute it"
            )
        problem = None
        if entry.content_hash != record.content_hash.hex():
            problem = ("stored content hash does not match the state the diff produces"
                       if record.kind in DIFF_KINDS else "stored content hash does not match the file table")
        candidates = index.get(entry.content_hash, [])
        known = next((c for c in candidates if c.same_identity(entry)), candidates[0] if candidates else None)
        if known is not None and problem is None and not known.same_identity(entry):
            problem = (f"listed as {known.kind} {known.title_id:016x} v{known.version} "
                       f"program {known.program} ({known.source})")
        # each size column compares where both sides know it: '-' is unknown (SPEC §6.5)
        if known is not None and problem is None and any(
                None not in (listed, actual) and listed != actual
                for listed, actual in ((known.files, entry.files), (known.bytes, entry.bytes))):
            problem = (f"listed with {value(known.files)} files / {value(known.bytes)} bytes "
                       f"({known.source})")
        matches.append(Match(label, entry, known, problem, unverified))
    return matches
