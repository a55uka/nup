"""Container editing: TLV and entry changes, rebuilt as a fresh container.

Unchanged entry bytes are streamed from the source file; hashes, content
identities, and both digest layers are recomputed.  Editing an update
package's entries changes its materialized identity, so pass --base to keep
the ancestry binding honest; without it the identity falls back to the
package's own rows and the result says so.
"""

from dataclasses import dataclass, field
import os

from .errors import NupError
from .layout import FileRow, Kind, TlvType, merge_localized
from .model import PackageRecord, scope_of
from .pack import Blob, PackedPackage, write_container
from .reader import NupReader, read_container
from .tree import SourceFile, hash_source, validate_container_path


@dataclass(slots=True)
class EditOps:
    package_selector: str | None = None  # None: the only package, else the base (select_record)
    set_tlvs: dict[int, bytes] = field(default_factory=dict)
    del_tlvs: set[int] = field(default_factory=set)
    lang_names: dict[str, str] = field(default_factory=dict)
    icon: bytes | None = None  # image bytes, fitted by prepare_icon
    lang_icons: dict[str, bytes] = field(default_factory=dict)
    add_files: dict[str, str] = field(default_factory=dict)
    replace_files: dict[str, str] = field(default_factory=dict)
    remove_files: set[str] = field(default_factory=set)
    base_path: str | None = None


@dataclass(slots=True)
class EditReport:
    output: str = ""
    tlvs_set: int = 0
    tlvs_removed: int = 0
    files_added: int = 0
    files_replaced: int = 0
    files_removed: int = 0
    warnings: list[str] = field(default_factory=list)


def edit_container(src: str, out: str, ops: EditOps) -> EditReport:
    reader = read_container(src)
    try:
        blobs_by_path = reusable_blobs(reader)
        records = clone_records(reader)
        report = EditReport()
        apply_file_ops(records, blobs_by_path, ops, report)
        apply_tlv_ops(reader, records, ops, report)
        from .rehash import recompute_identities, renumber

        renumber(records)
        recompute_identities(reader, records, ops.base_path, report)
        packed = [
            PackedPackage(record, blobs_for(record, blobs_by_path)) for record in records
        ]
        write_container(out, packed)
        report.output = out
        return report
    finally:
        reader.close()


def reusable_blobs(reader: NupReader) -> dict[str, Blob]:
    blobs = {}
    for record in reader.meta.packages:
        for offset, row in enumerate(record.files):
            name = reader.entry_name_of(record, offset)
            entry = reader.entries[record.first_entry_index + offset]
            blobs[name] = Blob(
                name,
                entry.size,
                entry.prefix_hash,
                fs_path=reader.path,
                offset=reader.data_start + entry.data_offset,
            )
    return blobs


def clone_records(reader: NupReader) -> list[PackageRecord]:
    clones = []
    for record in reader.meta.packages:
        clones.append(
            PackageRecord(
                kind=record.kind,
                flags=record.flags,
                title_id=record.title_id,
                application_id=record.application_id,
                version=record.version,
                first_entry_index=record.first_entry_index,
                content_hash=record.content_hash,
                base_content_hash=record.base_content_hash,
                tlvs=dict(record.tlvs),
                files=list(record.files),
                program_index=record.program_index,
            )
        )
    return clones


def apply_file_ops(
    records: list[PackageRecord],
    blobs_by_path: dict[str, Blob],
    ops: EditOps,
    report: EditReport,
) -> None:
    for path, fs_path in ops.add_files.items():
        record = record_for_path(records, path, must_be_absent=True)
        row, blob = hash_new_file(record, path, fs_path)
        record.files.append(row)
        blobs_by_path[path] = blob
        report.files_added += 1
    for path, fs_path in ops.replace_files.items():
        record = record_for_path(records, path, must_be_absent=False)
        row, blob = hash_new_file(record, path, fs_path)
        record.files = [existing for existing in record.files if existing.path != row.path]
        record.files.append(row)
        blobs_by_path[path] = blob
        report.files_replaced += 1
    for path in sorted(ops.remove_files):
        record = record_for_path(records, path, must_be_absent=False)
        before = len(record.files)
        record.files = [existing for existing in record.files if existing.path != path_of(record, path)]
        if len(record.files) == before:
            raise NupError(f"{path!r} is not in any package scope")
        blobs_by_path.pop(path, None)
        report.files_removed += 1
    for record in records:
        record.files.sort(key=lambda row: row.path_bytes)


def path_of(record: PackageRecord, container_path: str) -> str:
    prefix = scope_of(record) + "/"
    if not container_path.startswith(prefix):
        raise NupError(f"{container_path!r} does not belong to scope {prefix!r}")
    return container_path[len(prefix):]


def record_for_path(records: list[PackageRecord], container_path: str, *, must_be_absent: bool):
    validate_container_path(container_path)
    for record in records:
        prefix = scope_of(record) + "/"
        if container_path.startswith(prefix):
            relative = container_path[len(prefix):]
            present = any(row.path == relative for row in record.files)
            if must_be_absent and present:
                raise NupError(f"{container_path!r} already exists; use --replace-file")
            return record
    raise NupError(
        f"{container_path!r} matches no package scope; edits cannot create new packages"
    )


def hash_new_file(record: PackageRecord, container_path: str, fs_path: str):
    source = SourceFile(
        container_path,
        fs_path,
        os.path.getsize(fs_path),
    )
    sha256, prefix_hash = hash_source(source)
    row = FileRow(path_of(record, container_path), source.size, sha256)
    blob = Blob(container_path, source.size, prefix_hash, fs_path=fs_path)
    return row, blob


def apply_tlv_ops(reader: NupReader, records: list[PackageRecord], ops: EditOps, report: EditReport) -> None:
    if not (ops.set_tlvs or ops.del_tlvs or ops.lang_names or ops.icon is not None or ops.lang_icons):
        return   # file edits only: no package to pick
    record = select_record(reader, records, ops.package_selector)
    # as `nup pack` gives it (split_display_version): without --package, the display
    # version names the newest update the container holds, the version that was dumped
    updates = [other for other in records if other.kind is Kind.UPDATE]
    versioned = max(updates, key=lambda other: other.version) \
        if ops.package_selector is None and updates else record
    for tlv_type, value in ops.set_tlvs.items():
        (versioned if tlv_type == TlvType.DISPLAY_VERSION else record).tlvs[tlv_type] = value
        report.tlvs_set += 1
    for tlv_type in ops.del_tlvs:
        target = versioned if tlv_type == TlvType.DISPLAY_VERSION else record
        if target.tlvs.pop(tlv_type, None) is not None:
            report.tlvs_removed += 1
    for lang, name in ops.lang_names.items():
        merge_localized(record.tlvs, TlvType.LOCALIZED_TITLE, lang, name.encode("utf-8"))
        report.tlvs_set += 1
    apply_icons(record, ops, report)


def apply_icons(record: PackageRecord, ops: EditOps, report: EditReport) -> None:
    """Images go in last, each within its TLV's cap (1 MiB, SPEC §3): stored
    as they are when they fit, else converted (image.prepare_icon)."""
    from .image import add_localized_icon, prepare_icon
    from .layout import TLV_MAX_LENGTH

    if ops.icon is not None:
        record.tlvs[TlvType.ICON] = prepare_icon(ops.icon, TLV_MAX_LENGTH, "--icon")
        report.tlvs_set += 1
        # the image for every language, as `nup pack --icon` gives it (diff.merged_tlvs):
        # the console's other-language icons no longer apply; --lang-icon adds its own
        if record.tlvs.pop(TlvType.LOCALIZED_ICON, None) is not None:
            report.tlvs_removed += 1
            report.warnings.append("--icon replaces every language's icon: the localized icons were removed")
    for lang, data in ops.lang_icons.items():
        add_localized_icon(record.tlvs, lang, data, f"--lang-icon {lang}")
        report.tlvs_set += 1


def select_record(reader: NupReader, records: list[PackageRecord], selector: str | None) -> PackageRecord:
    """The one package metadata edits go to, of records (reader's packages,
    cloned in order). selector as every --package takes it
    (verify.select_packages); none: the only package, else the base, never
    one picked by its place in the file."""
    from .verify import package_label, select_packages

    if selector is None:
        bases = [record for record in records if record.kind is Kind.BASE]
        if len(records) == 1:
            return records[0]
        if len(bases) == 1:
            return bases[0]
        labels = ", ".join(f"{index}: {package_label(reader, record)}"
                           for index, record in enumerate(reader.meta.packages))
        raise NupError(f"this container holds {len(records)} packages ({labels}): "
                       "pass --package with the scope label or index of the one to edit")
    matches = select_packages(reader, selector)
    if len(matches) != 1:
        raise NupError(f"package selector {selector!r} matches {len(matches)} packages: "
                       "use the scope label or index of one")
    return records[next(index for index, record in enumerate(reader.meta.packages) if record is matches[0])]


def blobs_for(record: PackageRecord, blobs_by_path: dict[str, Blob]) -> list[Blob]:
    prefix = scope_of(record) + "/"
    blobs = []
    for row in record.files:
        container_path = prefix + row.path
        blob = blobs_by_path.get(container_path)
        if blob is None:
            raise NupError(f"no byte source for {container_path!r}")
        blobs.append(blob)
    return blobs


def edit_in_place(src: str, ops: EditOps) -> EditReport:
    tmp = src + ".edit.tmp"
    report = edit_container(src, tmp, ops)
    os.replace(tmp, src)
    report.output = src
    return report


def split_specs(specs: list[str]):
    for spec in specs:
        path, _, source = spec.partition("=")
        if not path or not source:
            raise NupError(f"expected PATH=SRC, got {spec!r}")
        yield path, source


def split_lang(spec: str, flag: str) -> tuple[str, str]:
    lang, separator, value = spec.partition("=")
    if not separator or not lang or not value:
        raise NupError(f"{flag} expects LANG=VALUE, got {spec!r}")
    return lang, value


def parse_tlv_type(text: str) -> int:
    names = {
        "icon": TlvType.ICON,
        "display-version": TlvType.DISPLAY_VERSION,
        "name": TlvType.TITLE_NAME,
        "publisher": TlvType.PUBLISHER,
        "build-id": TlvType.BUILD_ID,
        "provenance": TlvType.SOURCE_DUMP,
        "localized-title": TlvType.LOCALIZED_TITLE,
        "localized-icon": TlvType.LOCALIZED_ICON,
    }
    return names[text].value if text in names else int(text, 16)


def parse_set_tlv(spec: str) -> tuple[int, bytes]:
    type_text, separator, value = spec.partition("=")
    if not separator:
        raise NupError(f"expected TYPE=VALUE, got {spec!r}")
    return parse_tlv_type(type_text), decode_tlv_value(type_text, parse_tlv_type(type_text), value)


def decode_tlv_value(type_text: str, tlv_type: int, value: str) -> bytes:
    from pathlib import Path

    if value.startswith("@"):
        return Path(value[1:]).read_bytes()
    if tlv_type in {TlvType.ICON.value, TlvType.LOCALIZED_ICON.value}:
        raise NupError(f"TLV {type_text} carries binary data; use @file")
    return value.encode("utf-8")


def ops_from_args(args) -> EditOps:
    from pathlib import Path

    set_tlvs = dict(parse_set_tlv(spec) for spec in args.set_tlv)
    del_tlvs = {parse_tlv_type(text) for text in args.del_tlv}
    for tlv_type, value in ((TlvType.TITLE_NAME, args.name),
                            (TlvType.DISPLAY_VERSION, args.display_version),
                            (TlvType.PUBLISHER, args.publisher)):
        if value:
            set_tlvs[tlv_type.value] = value.encode("utf-8")
        elif value is not None:   # --publisher "": no empty TLV, the field is cleared
            del_tlvs.add(tlv_type.value)
    return EditOps(
        package_selector=args.package,
        set_tlvs=set_tlvs,
        lang_names=dict(split_lang(spec, "--lang-name") for spec in args.lang_name),
        icon=Path(args.icon).read_bytes() if args.icon else None,
        lang_icons={lang: Path(path).read_bytes()
                    for lang, path in (split_lang(spec, "--lang-icon") for spec in args.lang_icon)},
        del_tlvs=del_tlvs,
        add_files=dict(split_specs(args.add_file)),
        replace_files=dict(split_specs(args.replace_file)),
        remove_files=set(args.rm_file),
        base_path=args.base,
    )
