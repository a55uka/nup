"""Container info: JSON-ready description and a human rendering."""

from .errors import NupError
from .identity import title_number
from .layout import ADDON_OFFSET, PATCH_OFFSET, TlvType, TEXT_TLV_TYPES, parse_localized
from .model import scope_of
from .reader import NupReader


def container_info(reader: NupReader, *, include_entries: bool = False) -> dict:
    info: dict = {
        "file": reader.path,
        "size_bytes": reader.file_size,
        "entry_count": reader.entry_count,
        "data_region_start": reader.data_start,
        "meta": {
            "patch_version": reader.meta.patch_version,
            "package_count": len(reader.meta.packages),
            "file_count": reader.entry_count - 1,
            "digest_verified": True,
            "header_hash_verified": True,
        },
        "packages": [
            package_info(reader, record) for record in reader.meta.packages
        ],
    }
    if include_entries:
        info["entries"] = [
            {
                "index": index,
                "name": entry.name,
                "size": entry.size,
                "data_offset": entry.data_offset,
                "hashed_size": entry.hashed_size,
            }
            for index, entry in enumerate(reader.entries)
        ]
    return info


def package_info(reader: NupReader, record) -> dict:
    scope = scope_of(record)
    payload = {
        "kind": record.kind.name.lower(),
        "scope": scope,
        "program_index": record.program_index,
        "title_id": f"{record.title_id:016x}",
        "application_id": f"{record.application_id:016x}",
        "version": record.version,
        "display_version": decode_text(record.tlvs, TlvType.DISPLAY_VERSION),
        "name": decode_text(record.tlvs, TlvType.TITLE_NAME),
        "publisher": decode_text(record.tlvs, TlvType.PUBLISHER),
        "build_id": decode_text(record.tlvs, TlvType.BUILD_ID),
        "flags": record.flags,
        "is_diff": record.is_diff,
        "first_entry_index": record.first_entry_index,
        "file_count": len(record.files),
        "content_hash": record.content_hash.hex(),
        "base_content_hash": render_base_hash(record),
        "tlv_types": sorted(record.tlvs),
        "localized_languages": localized_languages(record),
        "conformance": conformance_notes(reader, record),
    }
    icon = record.tlvs.get(TlvType.ICON)
    if icon is not None:
        payload["icon_bytes"] = len(icon)
    return payload


def localized_languages(record) -> list[str]:
    """Languages of the localized title TLV; a malformed one is reported, not fatal (PR #37)."""
    value = record.tlvs.get(TlvType.LOCALIZED_TITLE)
    if value is None:
        return []
    try:
        return sorted(parse_localized(memoryview(value)))
    except NupError:
        return []


def render_base_hash(record) -> str:
    from .layout import ZERO_DIGEST

    return "none" if record.base_content_hash == ZERO_DIGEST else record.base_content_hash.hex()


def decode_text(tlvs: dict[int, bytes], tlv_type: int) -> str | None:
    value = tlvs.get(tlv_type)
    if value is None or tlv_type not in TEXT_TLV_TYPES:
        return None
    return value.decode("utf-8", errors="replace")


def conformance_notes(reader: NupReader, record) -> list[str]:
    notes = []
    application = record.application_id or app_id_of(reader, record)
    if record.kind.name == "BASE" and not record.program_index and record.title_id % 0x1000:
        notes.append("base title id does not end in 000 (SPEC §4)")
    # a program's id may be in another platform's range than its application's
    # (a Switch 2 Edition's program 1): compared without the platform byte (SPEC §4.1)
    if record.kind.name == "UPDATE" and application and \
            title_number(record.title_id) != title_number(application) + record.program_index + PATCH_OFFSET:
        notes.append("update title id is not its program's id (application id + program index) "
                     "+ 0x800 (SPEC §4, §4.1)")
    if record.kind.name == "ADDON" and application:
        index = record.title_id - application - ADDON_OFFSET
        if index < 0:
            notes.append("add-on title id is not application id + 0x1000 + index (SPEC §4)")
    if record.program_index and record.kind.name == "BASE" and \
            title_number(record.title_id) != title_number(application) + record.program_index:
        notes.append("program title id is not application id + program index (SPEC §4.1)")
    if TlvType.LOCALIZED_TITLE in record.tlvs:
        try:
            parse_localized(memoryview(record.tlvs[TlvType.LOCALIZED_TITLE]))
        except NupError as error:
            notes.append(f"localized title TLV is malformed: {error} (SPEC §3)")
    return notes


def app_id_of(reader: NupReader, record) -> int:
    for other in reader.meta.packages:
        if other.kind.name == "BASE":
            return other.title_id
    return 0


def render_info(info: dict) -> str:
    lines = [
        info["file"],
        f"  size {info['size_bytes']:,} bytes, {info['entry_count']} entries, "
        f"data region at {info['data_region_start']:#x}",
        f"  meta: {info['meta']['package_count']} packages, {info['meta']['file_count']} files, "
        f"patch version {info['meta']['patch_version']}, digest+header hash verified",
    ]
    for package in info["packages"]:
        lines.append(package_line(package))
    return "\n".join(lines)


def package_line(package: dict) -> str:
    parts = [
        f"  [{package['kind']}] scope {package['scope']}/"
        + (f" program {package['program_index']}" if package["program_index"] else ""),
        f"title {package['title_id']}",
        f"app {package['application_id']}",
        f"version {package['version']}",
        f"files {package['file_count']}",
        f"entries {package['first_entry_index']}..{package['first_entry_index'] + package['file_count'] - 1}",
        f"content {package['content_hash']}",
    ]
    if package["is_diff"]:
        parts.append(f"diff against {package['base_content_hash']}")
    if package["name"]:
        parts.append(f"name {package['name']!r}")
    if package["display_version"]:
        parts.append(f"display {package['display_version']!r}")
    if package["build_id"]:
        parts.append(f"build id {package['build_id']}")
    line = "\n    ".join(parts)
    notes = package.get("conformance") or []
    if notes:
        line += "\n    ! " + "\n    ! ".join(notes)
    return line
