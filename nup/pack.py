"""NUP v2 packer orchestration: dump trees and base containers -> .nup files.

Container variants (SPEC §1 rule 7, §5): base, diff update against a base
package, standalone (base + one diff update), and add-on collections.
Packing a lone update dump emits a base container instead (SPEC §5.2).

Blob and the tree-to-record machinery live in writer and diff; this module
routes user intent (base, update, standalone, dlc) into them.
"""

from dataclasses import dataclass, field
import itertools
import os

from .diff import base_rows_of, chain_state, pack_tree_package, sorted_identity
from .errors import NupError
from .layout import ADDON_OFFSET, PATCH_OFFSET, Kind
from .model import PackageRecord
from .reader import NupReader, read_container
from .writer import Blob, write_container


@dataclass(slots=True)
class PackageInput:
    kind: Kind
    content_dir: str
    version: int = 0
    addon_position: int = 0
    title_id: int | None = None
    application_id: int = 0
    tlvs: dict[int, bytes] = field(default_factory=dict)
    program_index: int = 0
    control_fallback: str | None = None   # a base's: whose Control content to take when it has none (SPEC §3.1)


@dataclass(slots=True)
class PackedPackage:
    record: PackageRecord
    blobs: list[Blob]
    materialized: dict = field(default_factory=dict)  # rows of the state the package produces


@dataclass(slots=True)
class AddonPatchInput:
    """One add-on data patch dump: its tree is the add-on with the patch applied."""

    content_dir: str
    version: int
    title_id: int
    addon_title_id: int
    tlvs: dict[int, bytes] = field(default_factory=dict)


def pack_base_container(
    out_path: str,
    content_dir: str,
    *,
    title_id: int,
    version: int = 0,
    tlvs: dict[int, bytes] | None = None,
    program_index: int = 0,
    application_id: int = 0,
    control_fallback: str | None = None,
) -> PackageRecord:
    """A base container; for a program other than 0, application_id binds it to
    program 0's title (SPEC §4.1). control_fallback: an update of the same
    program whose Control content gives the identity when the base has none
    (SPEC §3.1)."""
    package_input = PackageInput(
        Kind.BASE, content_dir, version=version, title_id=title_id, tlvs=tlvs or {},
        application_id=application_id if program_index else 0, program_index=program_index,
        control_fallback=control_fallback,
    )
    packed = pack_tree_package(package_input, first_entry_index=1)
    write_container(out_path, [packed])
    return packed.record


def load_base_for_diff(base_path: str) -> PackageRecord:
    """The base record of a container, which is closed again at once: an open
    file stays locked on Windows, so a failed pack could not remove it."""
    with read_container(base_path) as reader:
        bases = [record for record in reader.meta.packages if record.kind is Kind.BASE]
    if not bases:
        raise NupError(f"{base_path!r} carries no base package to diff against")
    return bases[0]


def pack_update_container(
    out_path: str,
    content_dir: str,
    base_path: str,
    *,
    version: int,
    title_id: int | None = None,
    application_id: int | None = None,
    tlvs: dict[int, bytes] | None = None,
    chain: list[str] | None = None,
) -> PackageRecord:
    """Diff container against a base, optionally landing on already-packed
    updates whose materialized state is the diff target (SPEC §5.1 chains)."""
    base_record = load_base_for_diff(base_path)
    application = application_id if application_id is not None else application_of(base_record)
    target_rows, target_identity = chain_state(base_record, chain or [])
    package_input = PackageInput(
        Kind.UPDATE,
        content_dir,
        version=version,
        title_id=title_id if title_id is not None else base_record.title_id + PATCH_OFFSET,
        application_id=application,
        tlvs=tlvs or {},
        program_index=base_record.program_index,
    )
    packed = pack_tree_package(
        package_input,
        first_entry_index=1,
        base_rows=target_rows,
        base_identity=target_identity,
    )
    write_container(out_path, [packed])
    return packed.record


def pack_standalone_container(
    out_path: str,
    base: str,
    update_dir: str,
    *,
    update_version: int,
    base_title_id: int | None = None,
    base_version: int = 0,
    base_tlvs: dict[int, bytes] | None = None,
    update_tlvs: dict[int, bytes] | None = None,
    update_title_id: int | None = None,
    program_index: int = 0,
    application_id: int | None = None,
) -> tuple[PackageRecord, PackageRecord]:
    """Base and its diff in one container so the pair travels together (§5.3).
    A base packed from a dump without Control content takes its identity from
    the update's (SPEC §3.1). program_index, application_id: a base packed
    from a dump that is another program than 0 (SPEC §4.1)."""
    base_record, base_blobs = load_or_pack_base(base, base_title_id, base_version, base_tlvs,
                                                control_fallback=update_dir, program_index=program_index,
                                                application_id=application_id)
    update_input = PackageInput(
        Kind.UPDATE,
        update_dir,
        version=update_version,
        title_id=update_title_id if update_title_id is not None else base_record.title_id + PATCH_OFFSET,
        application_id=application_of(base_record),
        tlvs=update_tlvs or {},
        program_index=base_record.program_index,
    )
    packed_update = pack_tree_package(
        update_input,
        first_entry_index=1 + len(base_record.files),
        base_rows=base_rows_of(base_record),
    )
    write_container(
        out_path,
        [PackedPackage(base_record, base_blobs), packed_update],
    )
    return base_record, packed_update.record


def application_of(base_record: PackageRecord) -> int:
    """The application a base belongs to: its own title for program 0, its
    application id for another program (SPEC §4.1)."""
    return base_record.application_id or base_record.title_id


def load_or_pack_base(base: str, title_id, version: int, tlvs,
                      control_fallback: str | None = None, program_index: int = 0,
                      application_id: int | None = None) -> tuple[PackageRecord, list[Blob]]:
    if base.endswith(".nup") and os.path.isfile(base):
        base_record = load_base_for_diff(base)
        return base_record, reuse_container_blobs_from(base, base_record)
    if title_id is None:
        raise NupError("standalone packing from a dump dir needs --title-id")
    packed = pack_tree_package(
        PackageInput(Kind.BASE, base, version=version, title_id=title_id, tlvs=tlvs or {},
                     control_fallback=control_fallback, program_index=program_index,
                     application_id=application_id or 0),
        first_entry_index=1,
    )
    return packed.record, packed.blobs


def reuse_container_blobs(reader: NupReader, record: PackageRecord) -> list[Blob]:
    return reuse_container_blobs_from(reader.path, record)


def reuse_container_blobs_from(container_path: str, record: PackageRecord) -> list[Blob]:
    """Point blobs at the existing container's bytes so standalone packing
    streams the base instead of re-reading the dump."""
    with read_container(container_path) as reader:
        return [blob_for_entry(reader, record, offset) for offset in range(len(record.files))]


def blob_for_entry(reader: NupReader, record: PackageRecord, offset: int) -> Blob:
    entry = reader.entries[record.first_entry_index + offset]
    return Blob(
        entry.name,
        entry.size,
        entry.prefix_hash,
        fs_path=reader.path,
        offset=reader.data_start + entry.data_offset,
    )


def pack_addon_container(
    out_path: str,
    addon_dirs: list[str],
    *,
    application_id: int,
    title_ids: list[int] | None = None,
    tlvs: list[dict[int, bytes]] | None = None,
    versions: list[int | None] | None = None,
) -> list[PackageRecord]:
    if not addon_dirs:
        raise NupError("an add-on container needs at least one add-on dump")
    order = sorted(range(len(addon_dirs)), key=lambda i: addon_dirs[i])  # ids, tlvs, versions follow their dirs
    title_ids = [title_ids[i] if title_ids and i < len(title_ids) else None for i in order] if title_ids else None
    tlvs = [tlvs[i] for i in order] if tlvs else None
    versions = [versions[i] if versions and i < len(versions) else None for i in order]
    named = [title_id for title_id in title_ids or [] if title_id]
    if len(set(named)) != len(named):
        twice = next(title_id for title_id in named if named.count(title_id) > 1)
        raise NupError(f"add-on {twice:#x} is given twice; a container holds each add-on once")
    taken = {title_id - application_id - ADDON_OFFSET for title_id in named}
    free_indexes = (index for index in itertools.count(1) if index not in taken)
    packed = []
    first_index = 1
    for position, content_dir in enumerate(addon_dirs[i] for i in order):
        package_input = addon_input(position, content_dir, application_id, title_ids, tlvs, free_indexes)
        package_input.version = versions[position] or 0
        packed_package = pack_tree_package(package_input, first_entry_index=first_index)
        packed.append(packed_package)
        first_index += len(packed_package.record.files)
    write_container(out_path, packed)
    return [packed_package.record for packed_package in packed]


def pack_addon_update_container(
    out_path: str,
    patches: list[AddonPatchInput],
    dlc_path: str,
) -> list[PackageRecord]:
    """Add-on data patches as diffs against their add-ons in dlc_path (SPEC
    §5.4); several patches of one add-on chain in version order."""
    if not patches:
        raise NupError("an add-on update container needs at least one data patch dump")
    _kept, repeated = first_per_key(patches, lambda patch: (patch.title_id, patch.version))
    if repeated:
        # one scope, addonupdate/<i>/<v>, for both: a container holds each patch once
        raise NupError(f"data patch {repeated[0].title_id:#x} v{repeated[0].version} is given twice")
    with read_container(dlc_path) as reader:
        addons = {record.title_id: record for record in reader.meta.packages if record.kind is Kind.ADDON}
    # an add-on's state as extract and hashlist see it: recomputed from its file table
    initial = {title: sorted_identity(base_rows_of(addon).values()) for title, addon in addons.items()}
    states: dict[int, tuple[dict, bytes]] = {}
    packed = []
    first_index = 1
    # in version order, as a reader applies them (extract): the states the
    # ambiguity check below sees are the ones the reader will
    for patch in sorted(patches, key=lambda item: (item.version, item.addon_title_id)):
        addon = addons.get(patch.addon_title_id)
        if addon is None:
            raise NupError(f"{dlc_path!r} has no add-on {patch.addon_title_id:#x} for data patch "
                           f"{patch.title_id:#x}")
        rows, identity = states.get(patch.addon_title_id) or (base_rows_of(addon), initial[patch.addon_title_id])
        rivals = [title for title in initial if title != patch.addon_title_id
                  and (states[title][1] if title in states else initial[title]) == identity]
        if rivals and patch.title_id != patch.addon_title_id + PATCH_OFFSET:
            # the record keeps no add-on id: a reader tells add-ons that share a state
            # apart only by the patch id being theirs + 0x800 (extract, SPEC §5.4)
            raise NupError(f"data patch {patch.title_id:#x} patches add-on {patch.addon_title_id:#x}, "
                           "but another add-on has the same files and the patch id is not "
                           f"{patch.addon_title_id + PATCH_OFFSET:#x}: no reader could tell which it patches")
        position = patch.title_id - addon.application_id - ADDON_OFFSET
        if position < 0:   # as an add-on's id is checked (addon_input, SPEC §4)
            raise NupError(f"data patch {patch.title_id:#x} is smaller than application id "
                           f"{addon.application_id:#x} + 0x1000 (SPEC §4)")
        package_input = PackageInput(
            Kind.ADDON_UPDATE,
            patch.content_dir,
            version=patch.version,
            addon_position=position,
            title_id=patch.title_id,
            application_id=addon.application_id,
            tlvs=patch.tlvs,
        )
        packed_package = pack_tree_package(
            package_input, first_entry_index=first_index, base_rows=rows, base_identity=identity
        )
        states[patch.addon_title_id] = (packed_package.materialized, packed_package.record.content_hash)
        packed.append(packed_package)
        first_index += len(packed_package.record.files)
    write_container(out_path, packed)
    return [packed_package.record for packed_package in packed]


def newest_per_title(items: list, title_of, version_of) -> tuple[list, list[tuple]]:
    """(kept, passed over): one item per title id, the newest version of each
    (a dlc container holds each add-on once), the first of equal versions,
    plus every item without an id, in their order; passed over: (left out,
    kept in its place) for each one left out."""
    kept: dict[object, object] = {}
    passed_over = []
    for item in items:
        title = title_of(item)
        key = ("id", title) if title is not None else ("item", id(item))
        other = kept.get(key)
        if other is not None:
            if version_of(item) <= version_of(other):
                passed_over.append((item, other))
                continue
            passed_over.append((other, item))
        kept[key] = item
    return list(kept.values()), passed_over


def first_per_key(items: list, key_of) -> tuple[list, list]:
    """(kept, repeated): the first item of each key, in order, and the others."""
    seen: set = set()
    kept, repeated = [], []
    for item in items:
        (repeated if key_of(item) in seen else kept).append(item)
        seen.add(key_of(item))
    return kept, repeated


def split_lone_patches(patches: list, present: set[int], addon_of, version_of) -> tuple[list, list]:
    """(lone, chained) data patches.  SPEC §5.4: a data patch whose add-on
    (addon_of, not in present) was not dumped packs as that add-on; of several
    versions of one, the oldest does, and the newer ones are add-on updates
    chained on it, so the dlc container holds each add-on once."""
    lone: dict[int, object] = {}
    for patch in sorted(patches, key=version_of):
        if addon_of(patch) not in present:
            lone.setdefault(addon_of(patch), patch)
    stand_ins = {id(patch) for patch in lone.values()}
    return list(lone.values()), [patch for patch in patches if id(patch) not in stand_ins]


def addon_input(position: int, content_dir: str, application_id: int, title_ids, tlvs,
                free_indexes) -> PackageInput:
    """Scope index follows the console id: title - application - 0x1000
    (DKB's dlc dump is index 1), so writer and reader derive the same
    `addon/N/...` paths.  An add-on without an id takes the next index from
    free_indexes, which skips those the named add-ons hold: without explicit
    ids the first add-on is index 1, matching Nintendo's observed assignment."""
    if title_ids and title_ids[position]:
        title_id = title_ids[position]
        scope_index = title_id - application_id - ADDON_OFFSET
        if scope_index < 0:
            raise NupError(
                f"add-on title id {title_id:#x} is smaller than application "
                f"{application_id:#x} + 0x1000 (SPEC §4)"
            )
    else:
        scope_index = next(free_indexes)
        title_id = application_id + ADDON_OFFSET + scope_index
    return PackageInput(
        Kind.ADDON,
        content_dir,
        addon_position=scope_index,
        title_id=title_id,
        application_id=application_id,
        tlvs=(tlvs[position] if tlvs else {}) or {},
    )
