"""Dump discovery: recognize the on-disc layouts the packer accepts.

Accepted layouts: a content directory (exefs/ and/or romfs/), a bundle
(base/ plus updates/<decimal>/ plus optional dlc/ or addons/), or an
update-only bundle (updates/ without base/), which packs as a base
(SPEC §5.2).

Bundles come in the shapes of the dump tools: flattened (exefs/ and romfs/
in base/ and updates/<v>/), the console's layout as OunceCake serves it
(each content at base/program/<index>/ and updates/<v>/program/<index>/,
add-ons at dlc/<id>/<v>/base/program/0/ with data patches at
.../updates/<v>/program/0/), and Yoink's (a Switch 2 Edition's program at
switch2/updates/<v>/, data patches at dlc/<data patch id>/<v>/).  Program 0
is the bundle's base and updates; other programs are kept apart (SPEC §4.1).
"""

from dataclasses import dataclass, field
import os
import re
import struct

from .errors import NupError
from .layout import PATCH_OFFSET, PROGRAM_INDEX_MAX
from .pack import AddonPatchInput
from .tree import CONTENT_MARKERS, PROGRAM_DIR, is_content_dir, is_program_dir, walk_own_content

DECIMAL = re.compile(r"^\d+$")
HEX_ID = re.compile(r"^[0-9a-fA-F]{16}$")
CNMT_ADDON = 0x82
CNMT_DATA_PATCH = 0x84


@dataclass(slots=True)
class ProgramDump:
    base_dir: str | None = None
    updates: dict[int, str] = field(default_factory=dict)


@dataclass(slots=True)
class Discovery:
    mode: str
    base_dir: str | None = None
    updates: dict[int, str] = field(default_factory=dict)
    addons: list[str] = field(default_factory=list)
    addon_title_ids: dict[str, int] = field(default_factory=dict)  # from dlc/<id>/ folder names
    addon_versions: dict[str, int] = field(default_factory=dict)  # from dlc/<id>/<version>/ folder names
    addon_patches: list[AddonPatchInput] = field(default_factory=list)  # as the packer takes them
    programs: dict[int, ProgramDump] = field(default_factory=dict)  # program index >= 1


def discover_dumps(source: str) -> Discovery:
    check_untarred(source)
    if is_content_dir(source):
        # program<N>/ beside exefs/ and romfs/ is another program, not program 0's files
        programs = {index: ProgramDump(base_dir=path) for index, path in flattened_programs(source)}
        return Discovery(mode="content", base_dir=source, programs=programs)
    if os.path.isdir(os.path.join(source, "base")) or os.path.isdir(os.path.join(source, "updates")):
        return discover_bundle(source)
    raise NupError(
        f"{source!r} is neither a content directory (exefs/ or romfs/) nor a dump "
        "bundle (base/, updates/, dlc/)"
    )


def discover_bundle(source: str) -> Discovery:
    discovery = Discovery(mode="bundle")
    base = os.path.join(source, "base")
    if os.path.isdir(base):
        for index, content in programs_of(base):
            program(discovery, index).base_dir = content
    updates_dir = os.path.join(source, "updates")
    for version, path in version_dirs(updates_dir):
        for index, content in programs_of(path):
            program(discovery, index).updates[version] = content
    collect_switch2(source, discovery)
    collect_addons(source, discovery)
    main = discovery.programs.pop(0, ProgramDump())
    discovery.base_dir, discovery.updates = main.base_dir, main.updates
    discovery.mode = "bundle" if discovery.base_dir else "updates-only"
    if (discovery.base_dir is None and not discovery.updates and not discovery.addons
            and not discovery.programs and not discovery.addon_patches):
        raise NupError(f"{source!r} has no packable content")
    return discovery


def program(discovery: Discovery, index: int) -> ProgramDump:
    return discovery.programs.setdefault(index, ProgramDump())


def programs_of(version_dir: str) -> list[tuple[int, str]]:
    """(program index, content dir) of a version folder: program/<index>/ in
    the console layout (program/<index>/program/ when a data content shares
    the index), else the folder itself as program 0."""
    program_root = os.path.join(version_dir, "program")
    # (index, folder name): a name may spell its index with leading zeros
    indexes = sorted((int(name), name) for name in os.listdir(program_root)
                     if DECIMAL.match(name)) if os.path.isdir(program_root) else []
    for (index, name), (other, other_name) in zip(indexes, indexes[1:]):
        if index == other:
            raise NupError(f"{program_root!r}: {name}/ and {other_name}/ are both program {index}")
    if not indexes:
        check_untarred(version_dir)
        # program 0 only when the folder holds files of its own, not just program<N>/
        found = [(0, version_dir)] if has_own_files(version_dir) else []
        return found + flattened_programs(version_dir)
    if is_content_dir(version_dir):
        raise NupError(f"{version_dir!r} holds both exefs/ or romfs/ and program/<index>/")
    found = []
    for index, name in indexes:
        check_program_index(index, os.path.join(program_root, name))
        for candidate in (os.path.join(program_root, name),
                          os.path.join(program_root, name, "program")):
            check_untarred(candidate)
            if is_content_dir(candidate) and bundle_has_files(candidate):
                found.append((index, candidate))
                break
    return found


def check_program_index(index: int, path: str) -> int:
    if index > PROGRAM_INDEX_MAX:
        raise NupError(f"{path!r}: program index {index} does not fit the package record "
                       f"(at most {PROGRAM_INDEX_MAX}, SPEC §4.1)")
    return index


def has_own_files(version_dir: str) -> bool:
    """bundle_has_files, leaving out the program<N>/ folders beside exefs/ and romfs/."""
    return any(not filename.endswith(".listing")
               for _dirpath, _dirnames, filenames in walk_own_content(version_dir)
               for filename in filenames)


def flattened_programs(version_dir: str) -> list[tuple[int, str]]:
    """(index, dir) of the program<N>/ folders a flattened version folder
    holds beside its own exefs/ and romfs/ (base/program1/,
    updates/<v>/program1/): a Switch 2 Edition's program 1 kept with its
    version. Program 0's walk leaves them out (tree.walk_content_dir)."""
    if not os.path.isdir(version_dir):
        return []
    found = []
    for name in sorted(os.listdir(version_dir)):
        if is_program_dir(version_dir, name):
            path = os.path.join(version_dir, name)
            check_untarred(path)
            if bundle_has_files(path):
                found.append((check_program_index(int(PROGRAM_DIR.match(name).group(1)), path), path))
    return found


def collect_switch2(source: str, discovery: Discovery) -> None:
    """Yoink keeps a Switch 2 Edition's program apart: switch2/base/ and
    switch2/updates/<v>/, flattened content dirs of program 1."""
    root = os.path.join(source, "switch2")
    base = os.path.join(root, "base")
    if os.path.isdir(base):
        check_untarred(base)
    if is_content_dir(base) and bundle_has_files(base):
        set_once(program(discovery, 1), "base", None, base)
    for version, path in version_dirs(os.path.join(root, "updates")):
        check_untarred(path)
        if is_content_dir(path):
            set_once(program(discovery, 1), "update", version, path)


def set_once(dump: ProgramDump, what: str, version: int | None, path: str) -> None:
    """Program 1 found in switch2/ and in base/ or updates/ too: two dumps of
    one package, neither of which may silently win."""
    current = dump.base_dir if what == "base" else dump.updates.get(version)
    if current is not None and os.path.normpath(current) != os.path.normpath(path):
        named = "base" if what == "base" else f"update v{version}"
        raise NupError(f"program 1's {named} is both {current!r} and {path!r}; keep one")
    if what == "base":
        dump.base_dir = path
    else:
        dump.updates[version] = path


def version_dirs(parent: str) -> list[tuple[int, str]]:
    if not os.path.isdir(parent):
        return []
    return sorted(
        (int(name), os.path.join(parent, name)) for name in os.listdir(parent)
        if DECIMAL.match(name) and os.path.isdir(os.path.join(parent, name))
        and bundle_has_files(os.path.join(parent, name))
    )


def check_untarred(path: str) -> None:
    """OunceCake's --tar mode serves <section>.tar in place of the folder."""
    tars = [section for section in CONTENT_MARKERS
            if os.path.isfile(os.path.join(path, f"{section}.tar"))
            and not os.path.isdir(os.path.join(path, section))]
    if tars:
        raise NupError(
            f"{path!r} holds {', '.join(t + '.tar' for t in tars)} (OunceCake's --tar mode): "
            "unpack each into a folder of its name first, e.g. tar -xf romfs.tar -C romfs"
        )


def bundle_has_files(path: str) -> bool:
    for _dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            if not filename.endswith(".listing"):
                return True
    return False


def collect_addons(source: str, discovery: Discovery) -> None:
    for parent in ("dlc", "addons"):
        addon_root = os.path.join(source, parent)
        if not os.path.isdir(addon_root):
            continue
        for name in sorted(os.listdir(addon_root)):
            path = os.path.join(addon_root, name)
            title_id = int(name, 16) if HEX_ID.match(name) else None
            if is_content_dir(path):
                # dlc/<id>/ itself: an add-on, or a data patch its content meta record names
                collect_addon_version(discovery, path, "", title_id)
                continue
            for nested in sorted(os.listdir(path)) if os.path.isdir(path) else ():
                collect_addon_version(discovery, os.path.join(path, nested), nested, title_id)


def collect_addon_version(discovery: Discovery, path: str, name: str, title_id: int | None) -> None:
    """One dlc/<id>/<n>/ folder: a flattened add-on (or Yoink's data patch filed
    under its own id), or the console layout's base/ and updates/<v>/."""
    if not os.path.isdir(os.path.join(path, "base")) and not os.path.isdir(os.path.join(path, "updates")):
        check_untarred(path)
        if not is_content_dir(path):
            return
        patch = cnmt_records(path, CNMT_DATA_PATCH)
        # without a content meta record the 0x800 bit marks a data patch; with one,
        # its type decides (an add-on of index 0x800 or more has the bit too)
        guessed = not patch and title_id is not None and title_id & PATCH_OFFSET \
            and not cnmt_records(path, CNMT_ADDON)
        if patch or guessed:
            # Yoink: a data patch beside its add-on (add-on = CNMT DataId, else id - 0x800);
            # its own id from its content meta record, as in the console layout, else the folder's
            own = patch[0][0] if patch and patch[0][0] else title_id
            if own is None:
                raise NupError(f"{path!r}: a data patch whose folder and content meta record name no id")
            version = int(name) if DECIMAL.match(name) else 0
            if patch and patch[0][1]:
                addon = patch[0][1]
            elif own & PATCH_OFFSET:
                addon = own - PATCH_OFFSET
            else:
                raise NupError(f"{path!r}: data patch {own:016X} names no add-on (its content meta "
                               "record's DataId is 0 and the id is not an add-on id + 0x800)")
            discovery.addon_patches.append(AddonPatchInput(path, version, own, addon))
        else:
            add_addon(discovery, path, title_id, int(name) if DECIMAL.match(name) else None)
        return
    if title_id is None:
        raise NupError(f"{path!r}: an add-on folder in the console layout is named by its title id")
    base = addon_content(os.path.join(path, "base"))
    if base:
        wrong = [rid for rid, _data in cnmt_records(base, CNMT_ADDON) if rid != title_id]
        if wrong:
            raise NupError(f"{base!r}: its content meta record is add-on {wrong[0]:016X}, "
                           f"the folder is {title_id:016X}")
        add_addon(discovery, base, title_id, int(name) if DECIMAL.match(name) else None)
    for version, update in version_dirs(os.path.join(path, "updates")):
        content = addon_content(update)
        if content is None:
            continue
        patch = cnmt_records(content, CNMT_DATA_PATCH)
        if patch and patch[0][1] and patch[0][1] != title_id:  # DataId 0: not recorded
            raise NupError(f"{content!r}: its content meta record is data patch {patch[0][0]:016X} "
                           f"of add-on {patch[0][1]:016X}, the folder is {title_id:016X}")
        # id from the CNMT, else add-on id + 0x800
        discovery.addon_patches.append(
            AddonPatchInput(content, version, patch[0][0] if patch else title_id + PATCH_OFFSET, title_id)
        )


def add_addon(discovery: Discovery, path: str, title_id: int | None, version: int | None = None) -> None:
    """version: the dump tools name an add-on's folder by its version (dlc/<id>/<version>/)."""
    discovery.addons.append(path)
    if title_id is not None:
        discovery.addon_title_ids[path] = title_id
    if version is not None:
        discovery.addon_versions[path] = version


def addon_content(package_dir: str) -> str | None:
    """An add-on package's content dir: program/0/ or program/0/data/."""
    for candidate in (os.path.join(package_dir, "program", "0"),
                      os.path.join(package_dir, "program", "0", "data")):
        if is_content_dir(candidate) and bundle_has_files(candidate):
            return candidate
    return None


def cnmt_records(content: str, cnmt_type: int) -> list[tuple[int, int]]:
    """(id, DataId) of the CNMT records of a type in <content>/meta/ (switchbrew
    layout; DataId is a data patch's add-on, else 0)."""
    meta = os.path.join(content, "meta")
    found = []
    for name in sorted(os.listdir(meta)) if os.path.isdir(meta) else ():
        if not name.endswith(".cnmt"):
            continue
        with open(os.path.join(meta, name), "rb") as handle:
            head = handle.read(0x28)
        if len(head) < 0x20:
            raise NupError(f"{os.path.join(meta, name)!r} is not a content meta record")
        record_id, _version, record_type, _platform, extended = struct.unpack_from("<QIBBH", head)
        if record_type != cnmt_type:
            continue
        data_id = 0
        if record_type == CNMT_DATA_PATCH and extended >= 8 and len(head) >= 0x28:
            data_id, = struct.unpack_from("<Q", head, 0x20)
        found.append((record_id, data_id))
    return found
