"""``nup pack`` command: dump discovery routing, naming, and TLV arguments."""

import argparse
from dataclasses import replace
from pathlib import Path
import re
import sys

from .discover import discover_dumps
from .errors import NupError
from .identity import require_title_id, resolve_identity
from .edit import split_lang
from .image import add_localized_icon, prepare_icon
from .layout import PATCH_OFFSET, TLV_MAX_LENGTH, TlvType, merge_localized
from .pack import (
    pack_addon_container,
    pack_addon_update_container,
    pack_base_container,
    pack_standalone_container,
    pack_update_container,
    first_per_key,
    newest_per_title,
    split_lone_patches,
)


def command_pack(args) -> int:
    discovery = discover_dumps(args.source)
    tlvs = collect_tlvs(args)
    title_id = parse_title_id(args.title_id)
    application_id = parse_title_id(getattr(args, "application_id", None), "--application-id")
    if args.base is not None:
        return pack_update_flow(args, discovery, tlvs, title_id)
    if args.kind == "standalone":
        return pack_standalone_flow(args, discovery, tlvs, title_id)
    if discovery.mode == "content":
        return pack_single_flow(args, discovery, tlvs, title_id)
    return pack_bundle_flow(args, discovery, tlvs, title_id, args.kind, application_id)


def pack_update_flow(args, discovery, tlvs, title_id) -> int:
    update_dir, version = require_update_dir(discovery, args)
    out = args.out or default_name(update_dir, "update", version, program0_stem(args, discovery))
    record = pack_update_container(
        out,
        update_dir,
        args.base,
        version=version,
        title_id=title_id,
        tlvs=tlvs,
        chain=args.chain,
    )
    print(f"packed {out}: update v{version}, {len(record.files)} diff files")
    for index, dump in sorted(discovery.programs.items()):
        for path in [dump.base_dir, *dump.updates.values()]:
            if path is not None:   # --base names program 0's base: another program needs its own
                print(f"nup: warning: {path!r} is program {index}, not packed: pack it with "
                      f"--base <its program's base>", file=sys.stderr)
    return 0


def pack_standalone_flow(args, discovery, tlvs, title_id) -> int:
    update_version = args.version or (max(discovery.updates) if discovery.updates else None)
    if discovery.base_dir is None or update_version is None:
        raise NupError(
            "standalone packing needs a bundle with base/ and updates/<version>/, "
            "plus --version when the dump lacks an updates/ dir"
        )
    update_dir = update_dir_of(discovery, update_version)
    out = args.out or default_name(update_dir, "standalone", update_version, program0_stem(args, discovery))
    base_tlvs, update_tlvs = split_display_version(tlvs)
    base_record, update_record = pack_standalone_container(
        out,
        discovery.base_dir,
        update_dir,
        update_version=update_version,
        base_title_id=resolve_title_id(title_id, discovery.base_dir),
        base_tlvs=base_tlvs,
        update_tlvs=update_tlvs,
    )
    print(
        f"packed {out}: base ({len(base_record.files)} files) + update v{update_version} "
        f"({len(update_record.files)} diff files)"
    )
    # the other programs as program 0 is: each base with this version's update in one file
    for line in pack_other_programs(args, discovery, base_record.title_id, standalone_version=update_version):
        print(f"packed {line}")
    return 0


def pack_single_flow(args, discovery, tlvs, title_id) -> int:
    content_dir = discovery.base_dir
    version = args.version or next(iter(discovery.updates), 0)
    out = args.out or default_name(content_dir, "base", 0)
    record = pack_base_container(
        out,
        content_dir,
        title_id=resolve_title_id(title_id, content_dir),
        version=version,
        tlvs=tlvs,
    )
    print(f"packed {out}: base, {len(record.files)} files")
    # program<N>/ beside exefs/ and romfs/: each program in its own container, beside out (SPEC §4.1)
    for line in pack_other_programs(args, discovery, record.title_id, out=out, version=version):
        print(f"packed {line}")
    return 0


def pack_bundle_flow(args, discovery, tlvs, title_id, kind, application_id=None) -> int:
    if kind == "dlc":
        return pack_dlc_flow(args, discovery, title_id, application_id)
    if discovery.base_dir is None:
        if not discovery.updates and not discovery.programs:
            if discovery.addons or discovery.addon_patches:
                raise NupError("this bundle holds only add-ons and data patches: pack them with --kind dlc")
            raise NupError("this bundle holds nothing to pack")
        if not discovery.updates and discovery.programs and title_id is None:
            raise NupError("this bundle holds only other programs (SPEC §4.1): pass --title-id "
                           "with program 0's title id, their application id")
        result = pack_updates_as_base_flow(args, discovery, tlvs, title_id)
        if discovery.programs:
            application = title_id if title_id is not None else \
                resolve_title_id(None, discovery.updates[min(discovery.updates)])
            for line in pack_other_programs(args, discovery, application):
                print(f"packed {line}")
        return result
    stem = program0_stem(args, discovery)
    base_out = args.out or default_name(discovery.base_dir, "base", 0, stem)
    title = resolve_title_id(title_id, discovery.base_dir)
    base_tlvs, update_tlvs = split_display_version(tlvs) if discovery.updates else (tlvs, {})
    pack_base_container(base_out, discovery.base_dir, title_id=title, tlvs=base_tlvs,
                        control_fallback=newest_control(discovery.updates))
    written = [base_out]
    written.extend(pack_bundle_updates(args, discovery, title, base_out, stem, update_tlvs))
    written.extend(pack_other_programs(args, discovery, title))
    for line in written:
        print(f"packed {line}")
    return 0


def bundle_stem(args) -> str:
    return name_stem(args.name) or Path(args.source).resolve().name


NOT_IN_FILE_NAMES = re.compile(r'\s*[<>:"/\\|?*\x00-\x1f]+\s*')


def name_stem(name: str | None) -> str | None:
    """--name as a file name stem: it is the title's name ('Zelda: Tears of the
    Kingdom'), so what a file name cannot hold on any host becomes ' - '."""
    from .tree import windows_name_problem

    if not name:
        return None
    stem = NOT_IN_FILE_NAMES.sub(" - ", name).strip(" .-")
    # a device name (CON, AUX, ...) is no file on Windows, whatever follows the dot
    return (stem + "_" if windows_name_problem(stem) else stem) or None


def program0_stem(args, discovery) -> str | None:
    """The name of a bundle's program 0 containers: --name, else the bundle's
    when its folders name nothing (the console layout's base/program/0/ and
    updates/<v>/program/0/) or the title has other programs, named after the
    bundle too (pack_other_programs); else None, the folder's own name."""
    if discovery.mode == "content":
        return None   # a content folder is named by its folder, as ever
    if args.name:
        return name_stem(args.name)
    source = Path(args.source)
    console_layout = (discovery.base_dir is not None and Path(discovery.base_dir) != source / "base") or \
        any(Path(update).parent != source / "updates" for update in discovery.updates.values())
    return bundle_stem(args) if console_layout or discovery.programs else None


def pack_other_programs(args, discovery, application_id: int, *, out: str | None = None,
                        version: int = 0, standalone_version: int | None = None) -> list[str]:
    """The programs other than 0 (SPEC §4.1), each in its own containers,
    beside program 0's (out, else -o) and named after it; version: their
    bases' (a single content folder's, as program 0's); standalone_version:
    a --kind standalone pack's, each base with that version's update in one
    file (§5.3) as program 0's, else the base alone."""
    if not discovery.programs:
        return []
    written = []
    place = out or args.out
    stem = out_stem(place) if place else bundle_stem(args)

    def placed(name: str) -> str:
        return str(Path(place).parent / name) if place else name

    for index, dump in sorted(discovery.programs.items()):
        if dump.base_dir is None:
            # SPEC §5.2: a program that arrived in an update has no base to diff against
            for update_version in sorted(dump.updates):
                standalone = placed(default_name(dump.updates[update_version], "standalone",
                                                 update_version, stem, index))
                pack_base_container(
                    standalone, dump.updates[update_version],
                    title_id=program_title_id(dump.updates[update_version], application_id, index),
                    version=update_version, program_index=index, application_id=application_id,
                )
                written.append(standalone)
            continue
        title = program_title_id(dump.base_dir, application_id, index)
        if standalone_version is not None:
            if standalone_version in dump.updates:
                pair = placed(default_name(dump.base_dir, "standalone", standalone_version, stem, index))
                pack_standalone_container(pair, dump.base_dir, dump.updates[standalone_version],
                                          update_version=standalone_version, base_title_id=title,
                                          base_version=version, program_index=index,
                                          application_id=application_id)
                written.append(pair)
                continue
            dump = replace(dump, updates={})   # its other versions are not this pack's, as program 0's are not
        base_out = placed(default_name(dump.base_dir, "base", 0, stem, index))
        pack_base_container(
            base_out, dump.base_dir,
            title_id=title,
            version=version, program_index=index, application_id=application_id,
            control_fallback=newest_control(dump.updates),
        )
        written.append(base_out)
        for update_version in sorted(dump.updates):
            update_out = placed(default_name(dump.updates[update_version], "update", update_version, stem, index))
            pack_update_container(update_out, dump.updates[update_version], base_out, version=update_version,
                                  application_id=application_id)
            written.append(update_out)
    return written


def newest_control(updates: dict[int, str]) -> str | None:
    """The newest update dir that serves Control content: a base without its
    own takes its identity from it (SPEC §3.1)."""
    from .nacp import read_control
    for version in sorted(updates, reverse=True):
        if read_control(updates[version]) is not None:
            return updates[version]
    return None


def program_title_id(content_dir: str, application_id: int, index: int,
                     fallback: int | None = None) -> int:
    """A program's own id from its NPDM, else the fallback the caller knows
    (nup convert: the v1 package's), else the console's application id + index."""
    program_id, _build_id = resolve_identity(content_dir)
    if program_id is not None:
        return program_id
    return fallback if fallback is not None else application_id + index


def pack_bundle_updates(args, discovery, application_id, base_out, stem,
                        update_tlvs: dict[int, bytes] | None = None) -> list[str]:
    """update_tlvs go to the newest update only (split_display_version)."""
    written = []
    if args.out:
        stem = out_stem(args.out)
    for version in sorted(discovery.updates):
        update_dir = discovery.updates[version]
        update_out = beside_out(args, default_name(update_dir, "update", version, stem))
        pack_update_container(
            update_out,
            update_dir,
            base_out,
            version=version,
            application_id=application_id,
            tlvs=update_tlvs if version == max(discovery.updates) else None,
        )
        written.append(update_out)
    return written


def split_display_version(tlvs: dict[int, bytes]) -> tuple[dict[int, bytes], dict[int, bytes]]:
    """(base, newest update) TLVs of a pack that writes a base and its updates:
    the display version a user gives names the version they dumped, the newest
    update's; the base and older updates keep their Control content's (SPEC §3.1)."""
    base = dict(tlvs)
    version = base.pop(TlvType.DISPLAY_VERSION, None)
    return base, {TlvType.DISPLAY_VERSION: version} if version is not None else {}


def pack_updates_as_base_flow(args, discovery, tlvs, title_id) -> int:
    stem = bundle_stem(args)
    if len(discovery.updates) > 1 and args.out:
        raise NupError(
            f"-o names one file, but this dump packs {len(discovery.updates)} updates as bases; "
            "pack each updates/<version>/ folder on its own, or leave out -o"
        )
    if len(discovery.updates) > 1 and args.display_version is not None:
        raise NupError(
            f"--display-version names one package, but this dump packs {len(discovery.updates)} "
            "updates as bases; pack each updates/<version>/ folder on its own, or let each "
            "take its Control content's display version"
        )
    for version in sorted(discovery.updates):
        update_dir = discovery.updates[version]
        out = args.out or default_name(update_dir, "standalone", version, stem)
        record = pack_base_container(
            out,
            update_dir,
            title_id=resolve_title_id(title_id, update_dir),
            version=version,
            tlvs=tlvs,
        )
        print(
            f"packed {out}: update dump alone, stored as base v{version} "
            f"({len(record.files)} files) per SPEC §5.2"
        )
    return 0


def pack_dlc_flow(args, discovery, addon_title_id, application_id) -> int:
    if not discovery.addons and not discovery.addon_patches:
        raise NupError("this bundle has no dlc/ or addons/ content")
    if application_id is None and discovery.base_dir is not None:
        application_id = derive_application_id(discovery.base_dir)
    if application_id is None:
        raise NupError(
            "--application-id is required: add-on dumps are RomFS-only and "
            "carry no npdm to derive the application id from"
        )
    # one data patch under several version folders of its add-on (dlc/<id>/<v>/updates/<pv>/)
    unique, repeated = first_per_key(discovery.addon_patches, lambda patch: (patch.title_id, patch.version))
    for patch in repeated:
        print(f"nup: warning: {patch.content_dir!r}: data patch {patch.title_id:016x} v{patch.version} "
              "again; packed once", file=sys.stderr)
    lone, patches = split_dump_patches(discovery, unique)
    addons = unique_addons(discovery)
    dirs = addons + [patch.content_dir for patch in lone]
    ids = [discovery.addon_title_ids.get(path) for path in addons]
    ids += [patch.addon_title_id for patch in lone]
    # a lone data patch keeps its own version, as a lone update does as a base (SPEC §5.2)
    versions = [discovery.addon_versions.get(path) for path in addons]
    versions += [patch.version for patch in lone]
    if addon_title_id and len(dirs) != 1:
        raise NupError(f"--title-id names one add-on, but this bundle packs {len(dirs)}: "
                       "pack each add-on folder on its own to give it an id")
    if addon_title_id:
        # the add-on's patches chain on it by id: they follow it to the new one, and a
        # patch id that was the add-on's + 0x800 stays so (SPEC §4, §5.4)
        patches = [replace(patch, addon_title_id=addon_title_id,
                           title_id=addon_title_id + PATCH_OFFSET
                           if patch.title_id == ids[0] + PATCH_OFFSET else patch.title_id)
                   if ids[0] is not None and patch.addon_title_id == ids[0] else patch
                   for patch in patches]
        ids = [addon_title_id]
    named = discovery.addon_title_ids or discovery.addon_patches
    stem = name_stem(args.name) or (Path(args.source).resolve().name if named else None)
    out = args.out or default_name(dirs[0], "dlc", 0, stem)
    records = pack_addon_container(out, dirs, application_id=application_id,
                                   title_ids=ids if any(ids) else None, versions=versions)
    print(f"packed {out}: {len(records)} add-on packages")
    if patches:
        # beside the dlc container, named after it
        update_out = str(Path(out).parent / default_name(dirs[0], "dlc.update", 0, out_stem(out)))
        records = pack_addon_update_container(update_out, patches, out)
        print(f"packed {update_out}: {len(records)} add-on update packages (SPEC §5.4)")
    return 0


def unique_addons(discovery) -> list[str]:
    """The add-on folders, one per title id (a dlc container holds each add-on
    once): of several version folders of one (dlc/<id>/<version>/), the newest."""
    kept, passed_over = newest_per_title(sorted(discovery.addons), discovery.addon_title_ids.get,
                                         lambda path: discovery.addon_versions.get(path) or 0)
    for left_out, packed in passed_over:
        print(f"nup: warning: {left_out!r}: another version folder of add-on "
              f"{discovery.addon_title_ids[left_out]:016x}; {packed!r} packed instead, the newest "
              "(the first of equal versions)", file=sys.stderr)
    return sorted(kept)


def split_dump_patches(discovery, patches: list) -> tuple[list, list]:
    """(lone, chained) data patches of a dump (pack.split_lone_patches)."""
    known = {discovery.addon_title_ids.get(path) for path in discovery.addons}
    return split_lone_patches(patches, known,
                                   lambda patch: patch.addon_title_id, lambda patch: patch.version)


def derive_application_id(content_dir: str) -> int | None:
    from .identity import exefs_file, read_npdm_program_id

    npdm = exefs_file(content_dir, "main.npdm")
    return read_npdm_program_id(npdm) if npdm else None


def resolve_title_id(title_id, content_dir) -> int:
    return title_id if title_id is not None else require_title_id(content_dir, None)


def require_update_dir(discovery, args) -> tuple[str, int]:
    if discovery.mode == "content":
        if args.version is None:
            raise NupError("--version is required when diffing a bare content directory")
        return discovery.base_dir, args.version
    if not discovery.updates:
        raise NupError("no updates/<version>/ directory found to diff")
    if len(discovery.updates) > 1 and args.version is None:
        raise NupError("--version is required: the bundle carries several updates")
    version = args.version or max(discovery.updates)
    return update_dir_of(discovery, version), version


def update_dir_of(discovery, version: int) -> str:
    """The updates/<version>/ folder --version names, else a one-line error."""
    if version not in discovery.updates:
        found = ", ".join(str(v) for v in sorted(discovery.updates)) or "none"
        raise NupError(f"--version {version}: the dump has no updates/{version}/ (updates: {found})")
    return discovery.updates[version]


OUT_SUFFIX = re.compile(r"(\.dlc(\.update)?|(\.standalone)?\.update\.\d+)?\.nup$")


def out_stem(out: str) -> str:
    """The name stem of an -o file, its default_name suffix taken off."""
    return OUT_SUFFIX.sub("", Path(out).name)


def beside_out(args, name: str) -> str:
    """Where a pack's other containers go: beside the -o file when one is
    given, named after it (out_stem), else in the working folder."""
    return str(Path(args.out).parent / name) if args.out else name


def default_name(source_dir: str, variant: str, version: int, stem: str | None = None,
                 program: int = 0) -> str:
    name = stem or Path(source_dir).resolve().name
    if program:
        name += f".program{program}"
    suffixes = {
        "base": f"{name}.nup",
        "update": f"{name}.update.{version}.nup",
        "standalone": f"{name}.standalone.update.{version}.nup",
        "dlc": f"{name}.dlc.nup",
        "dlc.update": f"{name}.dlc.update.nup",
    }
    if variant not in suffixes:
        raise NupError(f"unknown naming variant {variant!r}")
    return suffixes[variant]


def parse_title_id(text: str | None, flag: str = "--title-id") -> int | None:
    """A 64-bit id in hex (an optional 0x prefix), else a one-line error."""
    if text is None:
        return None
    try:
        value = int(text, 16)
    except ValueError:
        raise NupError(f"{flag} expects up to 16 hex digits, got {text!r}") from None
    if not 0 <= value < 1 << 64:
        raise NupError(f"{flag} {text!r} does not fit in 64 bits (16 hex digits)")
    return value


def collect_tlvs(args) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    text_tlvs = {
        TlvType.TITLE_NAME: args.name,
        TlvType.PUBLISHER: args.publisher,
        TlvType.DISPLAY_VERSION: args.display_version,
        TlvType.SOURCE_DUMP: args.provenance,
    }
    for tlv_type, value in text_tlvs.items():
        if value:
            tlvs[tlv_type] = value.encode("utf-8")
    for spec in args.lang_name:
        lang, text = split_lang(spec, "--lang-name")
        merge_localized(tlvs, TlvType.LOCALIZED_TITLE, lang, text.encode("utf-8"))
    # images as `nup edit` takes them: a JPEG that fits as it is, else converted (image.prepare_icon)
    if args.icon:
        tlvs[TlvType.ICON] = prepare_icon(Path(args.icon).read_bytes(), TLV_MAX_LENGTH, "--icon")
    for spec in args.lang_icon:
        lang, path = split_lang(spec, "--lang-icon")
        add_localized_icon(tlvs, lang, Path(path).read_bytes(), f"--lang-icon {lang}")
    return tlvs


def add_pack_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("source", help="dump directory (content dir, bundle, or updates/)")
    parser.add_argument("-o", "--out", help="output .nup path (default: convention)")
    parser.add_argument("--kind", choices=("base", "update", "dlc", "standalone"), default=None)
    parser.add_argument("--base", help="base .nup to diff against (update kind)")
    parser.add_argument("--chain", action="append", default=[], metavar="UPDATE_NUP",
                        help="already-packed update(s) the diff lands on, in version order")
    parser.add_argument("--title-id", help="title id, 16 hex digits")
    parser.add_argument("--application-id", help="application id for dlc packs, 16 hex digits")
    parser.add_argument("--version", type=int, help="package version (NCM-style u32)")
    # metadata flags override the dump's control/control.nacp (SPEC §3.1); in a
    # pack that writes several packages they describe the title, on the base,
    # but --display-version names the update when the pack writes one (a dump
    # of an installed game is at its update's version); every other package
    # takes its display version from its own Control content
    parser.add_argument("--name", help="title name (default: from control.nacp)")
    parser.add_argument("--display-version", help="display version of the newest package: the update "
                        "when the pack writes base + update (default: from control.nacp)")
    parser.add_argument("--publisher", help="publisher (default: from control.nacp)")
    parser.add_argument("--icon", help="icon image for the default-language TLV; a JPEG that fits "
                        "is kept as is, anything else becomes a 256x256 JPEG (needs Pillow) "
                        "(default: control/icon_<Language>.dat)")
    parser.add_argument("--lang-name", action="append", default=[], metavar="LANG=TEXT")
    parser.add_argument("--lang-icon", action="append", default=[], metavar="LANG=IMAGE")
    parser.add_argument("--provenance", help="source dump provenance string (TLV 0x000C)")
