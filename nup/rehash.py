"""Content-hash recomputation for edited containers.

An edit changes entry bytes, TLVs, or the file table, so every affected
identity must be recomputed: per-package content hashes, scope numbering,
and (for update packages) the materialized-state identity, which needs the
base table and the @deleted manifest (see SPEC_ISSUES
['update-content-hash']).
"""

from .diff import base_rows_of, sorted_identity   # one identity for edit, pack and hashlist alike
from .errors import NupError
from .layout import DELETED_NAME, DIFF_KINDS, FileRow, Kind
from .model import PackageRecord
from .reader import NupReader
from .tree import parse_deleted_manifest


def recompute_identities(
    reader: NupReader,
    records: list[PackageRecord],
    base_path: str | None,
    report,
) -> None:
    """A diff whose file table is unchanged keeps its stored identity: it is the
    materialized state it produces, which a TLV edit does not change and its
    own rows cannot reproduce (SPEC §6.2) — unless the base it lands on in
    the same container (a standalone one) was edited: it then binds to the
    edited base, and its state is recomputed on it."""
    pairs = list(zip(records, reader.meta.packages, strict=True))
    edited_bases: dict[bytes, PackageRecord] = {}   # the original identity of each edited base
    for record, original in pairs:
        if record.kind not in DIFF_KINDS:
            record.content_hash = sorted_identity(record.files)
            edited = record.files != original.files
            if record.kind is Kind.BASE and edited:
                edited_bases[sorted_identity(original.files)] = record
                # an update beside it follows it here; those in other files cannot
                report.warnings.append(
                    f"base {record.title_id:#x} changed: updates packed against it in other files "
                    "(its .update.<v>.nup) no longer land on it; repack them with `nup pack --base`")
            if record.kind is Kind.ADDON and edited:
                # its data patches live in another file: they cannot follow it here
                report.warnings.append(
                    f"add-on {record.title_id:#x} changed: data patches packed against it "
                    "(its .dlc.update.nup) no longer land on it; repack them with `nup pack --kind dlc`")
    base_rows = None
    for record, original in pairs:
        if record.kind not in DIFF_KINDS:
            continue
        moved = edited_bases.get(original.base_content_hash)
        if record.files == original.files and moved is None:
            continue
        if record.kind is Kind.ADDON_UPDATE:
            raise NupError(
                "editing an add-on update's files changes the state later data patches "
                "chain from; repack it with `nup pack --kind dlc`"
            )
        if moved is not None:
            rows = base_rows_of(moved)
            record.base_content_hash = moved.content_hash
        else:
            if base_rows is None:
                base_rows = load_base_rows(base_path)
            if base_rows is not None and sorted_identity(base_rows.values()) != original.base_content_hash:
                # a chained update lands on its predecessor's state, not on the base
                raise NupError(f"--base {base_path!r} is not the state update v{record.version} lands on "
                               "(an update packed with --chain lands on the one before it); "
                               "repack it with `nup pack --chain`")
            rows = base_rows if base_rows is not None else own_base_rows(reader, original)
        record.content_hash = sorted_identity(update_identity_rows(reader, record, original, rows, report))


def own_base_rows(reader: NupReader, update: PackageRecord) -> dict[str, FileRow] | None:
    """The rows of the base in the update's own container (a standalone one)
    when the update lands on it as stored."""
    for record in reader.meta.packages:
        if record.kind is Kind.BASE and sorted_identity(record.files) == update.base_content_hash:
            return base_rows_of(record)
    return None


def load_base_rows(base_path: str | None) -> dict[str, FileRow] | None:
    if base_path is None:
        return None
    from .pack import load_base_for_diff

    base_record = load_base_for_diff(base_path)
    return base_rows_of(base_record)


def update_identity_rows(
    reader: NupReader,
    record: PackageRecord,
    original: PackageRecord,
    base_rows: dict[str, FileRow] | None,
    report,
) -> list[FileRow]:
    removed = deleted_paths(reader, record, original)   # refuses an edited @deleted either way
    if base_rows is None:
        report.warnings.append(
            "update-package identity recomputed over its own rows; pass --base "
            "to recompute the materialized-state identity"
        )
        return list(record.files)
    materialized = dict(base_rows)
    for row in record.files:
        if row.path != DELETED_NAME:
            materialized[row.path] = row
    for path in removed:
        # as extract.apply_updates refuses it: no state is written that no reader builds
        if materialized.pop(path, None) is None:
            raise NupError(f"the update's {DELETED_NAME} names {path!r}, which its base no longer "
                           "holds after this edit; repack the update with `nup pack`")
    return list(materialized.values())


def deleted_paths(reader: NupReader, record: PackageRecord, original: PackageRecord) -> list[str]:
    """The paths the edited record's @deleted manifest removes, read where the
    source container stores it: the record's own numbering has moved with the edit."""
    row = next((row for row in record.files if row.path == DELETED_NAME), None)
    offset = next((i for i, old in enumerate(original.files) if old.path == DELETED_NAME), None)
    if (row is None) != (offset is None) or (row is not None and original.files[offset] != row):
        raise NupError(f"an edit cannot add, replace or remove {DELETED_NAME}: it is the update's own "
                       "record of the files it removes; repack the update with `nup pack`")
    if row is None:
        return []
    entry = reader.entries[original.first_entry_index + offset]
    return parse_deleted_manifest(reader.read_entry_bytes(entry))


def renumber(records: list[PackageRecord]) -> None:
    first_index = 1
    for record in records:
        record.first_entry_index = first_index
        first_index += len(record.files)
