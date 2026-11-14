"""Tree diffing and package packing from dump directories.

``pack_tree_package`` walks a dump, hashes every file once, and either
stores everything (base/add-on) or only what differs from the target state
(update).  The update record's content hash is the materialized-state
identity (SPEC_ISSUES['update-content-hash']); @deleted manifests stay in
the record's file table but are consumed by apply.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .errors import NupError
from .identity import resolve_identity
from .layout import (
    DELETED_NAME,
    FileRow,
    Flags,
    Kind,
    TlvType,
    content_hash,
    encode_localized,
    parse_localized,
    scope_prefix,
)
from .model import PackageRecord
from .nacp import control_icon, control_localized_icons, control_tlvs, read_control
from .reader import NupReader, read_container
from .tree import (
    encode_deleted_manifest,
    hash_bytes,
    hash_source,
    parse_deleted_manifest,
    walk_content_dir,
)

if TYPE_CHECKING:
    from .pack import PackageInput, PackedPackage

READ_CHUNK = 4 << 20


@dataclass(slots=True)
class HashedSource:
    path: str
    fs_path: str
    size: int
    sha256: bytes
    prefix_hash: bytes


def relative_path(container_path: str, scope: str) -> str:
    prefix = scope + "/"
    if not container_path.startswith(prefix):
        raise NupError(f"{container_path!r} is not under scope {scope!r}")
    return container_path[len(prefix) :]


def hashed_sources(content_dir: str, scope: str) -> list[HashedSource]:
    hashed = []
    for source in walk_content_dir(content_dir, scope):
        whole, prefix = hash_source(source)
        hashed.append(
            HashedSource(
                relative_path(source.container_path, scope),
                source.fs_path,
                source.size,
                whole,
                prefix,
            )
        )
    return hashed


def build_identity_tlvs(content_dir: str) -> dict[int, bytes]:
    _program_id, build_id = resolve_identity(content_dir)
    tlvs: dict[int, bytes] = {}
    if build_id:
        tlvs[TlvType.BUILD_ID] = build_id.hex().encode("ascii")
    return tlvs


def localized_merged(tlvs: dict[int, bytes], overrides: dict[int, bytes]) -> dict[int, bytes]:
    """overrides, with their localized titles merged language by language into
    the ones tlvs already hold: a --lang-name replaces its own language's
    record, not the other languages the Control content names."""
    merged = dict(overrides)
    if TlvType.LOCALIZED_TITLE in overrides and TlvType.LOCALIZED_TITLE in tlvs:
        records = parse_localized(memoryview(tlvs[TlvType.LOCALIZED_TITLE]))
        records.update(parse_localized(memoryview(overrides[TlvType.LOCALIZED_TITLE])))
        merged[TlvType.LOCALIZED_TITLE] = encode_localized(records)
    return merged


def merged_tlvs(content_dir: str, overrides: dict[int, bytes] | None,
                kind: Kind = Kind.BASE, control_fallback: str | None = None) -> dict[int, bytes]:
    """Build id, then the Control content's metadata (SPEC §3.1), then the
    caller's explicit values, which win field by field. A base without
    Control content of its own takes the identity TLVs, not the display
    version, from control_fallback: the newest update of its program that
    has one (on the console an installed update's Control replaces the
    base's, so a dump of an installed game has only the update's)."""
    tlvs = build_identity_tlvs(content_dir)
    control = read_control(content_dir) if kind in (Kind.BASE, Kind.UPDATE) else None
    if control is not None:
        tlvs.update(control_tlvs(control, identity=kind is Kind.BASE))
    elif kind is Kind.BASE and control_fallback:
        control = read_control(control_fallback)
        if control is not None:
            borrowed = control_tlvs(control, identity=True)
            borrowed.pop(TlvType.DISPLAY_VERSION, None)   # the update's version, not the base's
            tlvs.update(borrowed)
    if overrides:
        tlvs.update(localized_merged(tlvs, overrides))
    default_icon = control_icon(control) if control is not None and kind is Kind.BASE else None
    if default_icon is not None and TlvType.ICON not in tlvs:
        tlvs[TlvType.ICON] = default_icon
    # the console's other-language icons stand beside its default one: an icon the
    # caller gives replaces the image for every language, so none of them apply,
    # unless it is that default icon itself (nup convert passes v1's, mostly the
    # tree's); a --lang-icon replaces its own language's and the others stay
    icon_given = bool(overrides) and TlvType.ICON in overrides and overrides[TlvType.ICON] != default_icon
    if control is not None and kind is Kind.BASE and not icon_given:
        given = tlvs.get(TlvType.LOCALIZED_ICON)
        localized = control_localized_icons(control, tlvs.get(TlvType.ICON),
                                            parse_localized(memoryview(given)) if given else None)
        if localized is not None:
            tlvs[TlvType.LOCALIZED_ICON] = localized
    return tlvs


def base_rows_of(record: PackageRecord) -> dict[str, FileRow]:
    return {row.path: row for row in record.files}


def sorted_identity(rows) -> bytes:
    """A package state's identity (SPEC §6.2): the content hash of its rows,
    any order (content_hash sorts them by path bytes). The one helper pack,
    edit, extract and hashlist compute it with."""
    return content_hash(list(rows))


def pack_tree_package(
    package_input: "PackageInput",
    *,
    first_entry_index: int,
    base_rows: dict[str, FileRow] | None = None,
    base_identity: int | None = None,
) -> "PackedPackage":
    """Walk a dump tree into a package record plus writable blobs.

    With ``base_rows`` the package stores only added and changed files and
    carries the diff flag; unchanged files survive in the materialized
    identity via the base table.
    """
    from .pack import PackedPackage

    scope = scope_prefix(package_input.kind, package_input.version, package_input.addon_position)
    record = new_package_record(package_input, first_entry_index, base_rows is not None)
    materialized: dict[str, FileRow] = dict(base_rows) if base_rows is not None else {}
    hashed = hashed_sources(package_input.content_dir, scope)
    blobs, update_paths = collect_scope_entries(record, scope, hashed, base_rows, materialized)
    if base_rows is not None:
        record.base_content_hash = base_identity if base_identity is not None else sorted_identity(base_rows.values())
        attach_deleted_manifest(record, blobs, scope, base_rows, update_paths, materialized)
    record.files.sort(key=lambda row: row.path_bytes)
    blobs.sort(key=lambda blob: blob.name.encode("utf-8"))
    record.content_hash = sorted_identity(materialized.values())
    return PackedPackage(record, sorted(blobs, key=lambda blob: blob.name.encode("utf-8")), materialized)


def new_package_record(package_input, first_entry_index: int, diff: bool) -> PackageRecord:
    return PackageRecord(
        kind=package_input.kind,
        flags=Flags.DIFF if diff else 0,
        title_id=package_input.title_id or 0,
        application_id=package_input.application_id,
        version=package_input.version,
        first_entry_index=first_entry_index,
        tlvs=merged_tlvs(package_input.content_dir, package_input.tlvs or None, package_input.kind,
                         package_input.control_fallback),
        program_index=package_input.program_index,
    )


def collect_scope_entries(record, scope, hashed, base_rows, materialized) -> tuple[list, set]:
    from .pack import Blob

    blobs: list = []
    update_paths: set[str] = set()
    for source in hashed:
        update_paths.add(source.path)
        row = FileRow(source.path, source.size, source.sha256)
        unchanged = base_rows is not None and base_rows.get(source.path) == row
        if not unchanged:
            record.files.append(row)
            blobs.append(
                Blob(scope + "/" + source.path, source.size, source.prefix_hash,
                     fs_path=source.fs_path)
            )
        materialized[source.path] = row
    return blobs, update_paths


def attach_deleted_manifest(record, blobs, scope, base_rows, update_paths, materialized) -> None:
    from .pack import Blob

    removed = sorted(set(base_rows) - update_paths)
    if not removed:
        return
    manifest = encode_deleted_manifest(removed)
    digest, prefix = hash_bytes(manifest)
    record.files.append(FileRow(DELETED_NAME, len(manifest), digest))
    blobs.append(Blob(scope + "/" + DELETED_NAME, len(manifest), prefix, data=manifest))
    for path in removed:
        del materialized[path]


def chain_state(base_record: PackageRecord, chain_paths: list[str]) -> tuple[dict[str, FileRow], int]:
    """Rows and identity of base overlaid with already-packed updates."""
    rows = base_rows_of(base_record)
    identity = sorted_identity(rows.values())
    for path in chain_paths:
        rows, identity = apply_chain_link(rows, identity, path)
    return rows, identity


def apply_chain_link(rows: dict[str, FileRow], identity: int, path: str):
    with read_container(path) as reader:
        record = require_chain_update(reader, path)
        if record.base_content_hash != identity:
            raise NupError(
                f"{path!r} binds to {record.base_content_hash.hex()} but the "
                f"chained tree is {identity.hex()}"
            )
        overlay_update_rows(reader, record, rows)
        return rows, sorted_identity(rows.values())


def require_chain_update(reader: NupReader, path: str) -> PackageRecord:
    updates = [record for record in reader.meta.packages if record.kind is Kind.UPDATE]
    if len(updates) != 1 or any(record.kind is Kind.BASE for record in reader.meta.packages):
        raise NupError(f"chain links must be single-update containers: {path!r}")
    return updates[0]


def overlay_update_rows(reader: NupReader, record: PackageRecord, rows: dict[str, FileRow]) -> None:
    for offset, row in enumerate(record.files):
        if row.path == DELETED_NAME:
            entry = reader.entries[record.first_entry_index + offset]
            for removed in parse_deleted_manifest(reader.read_entry_bytes(entry)):
                # as extract.apply_updates refuses it: no state is proven that no reader builds
                if rows.pop(removed, None) is None:
                    raise NupError(f"the v{record.version} @deleted manifest names {removed!r}, "
                                   "which the tree does not contain")
            continue
        rows[row.path] = row
