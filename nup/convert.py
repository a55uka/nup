"""Best-effort conversion of a NUP v1 container into NUP v2 containers.

v1 keeps a whole title in one file, every package a full tree; v2 splits it
the way `nup pack` does (SPEC §1 rule 7): a base container per program,
every update a diff against its base, a lone update stored as a base
(§5.2), add-ons in `<name>.dlc.nup` and their data patches as diffs in
`<name>.dlc.update.nup` (§5.4).  Each v1 package is unpacked into a work
folder (decompressed and hash-checked) and packed by the v2 packer, so the
result is exactly what packing the same dump would give.

Metadata maps onto the v2 TLVs (SPEC §3, §3.1): name, publisher, display
version and localized names carry over, the NACP fills what they lack,
icons go in as `nup pack --icon` takes them (image.prepare_icon): a JPEG
within the 1 MiB TLV cap as stored, anything else re-encoded as a JPEG,
which needs Pillow (else the icon is dropped, and said so).  NPDM and build id TLVs
are dropped (v2 reads both from the tree).  What cannot be carried over is
reported, not silently lost.
"""

from dataclasses import dataclass, field
import os
import shutil
import tempfile

from .discover import flattened_programs
from .errors import NupError
from .identity import title_number
from .layout import PATCH_OFFSET, PROGRAM_INDEX_MAX, TLV_MAX_LENGTH, TlvType, merge_localized, parse_localized
from .nacp import NACP_MIN_SIZE, control_tlvs, parse_nacp, read_control
from .pack import (
    AddonPatchInput,
    pack_addon_container,
    pack_addon_update_container,
    pack_base_container,
    pack_update_container,
    first_per_key,
    newest_per_title,
    split_lone_patches,
)
from .packcli import default_name, name_stem, program_title_id
from .tree import check_extract_paths, safe_target
from .v1 import (
    KIND_ADDON,
    KIND_ADDON_UPDATE,
    KIND_BASE,
    KIND_SYSTEM,
    KIND_UPDATE,
    PKG_FLAG_STANDALONE,
    V1Package,
    V1Reader,
    V1Tlv,
)

APPLICATION_MASK = ~0x1FFF
KNOWN_V1_TLVS = frozenset({
    V1Tlv.NPDM, V1Tlv.NACP, V1Tlv.ICON, V1Tlv.DISPLAY_VERSION, V1Tlv.TITLE_NAME,
    V1Tlv.PUBLISHER, V1Tlv.BUILD_ID, V1Tlv.SOURCE_DUMP, V1Tlv.LOCALIZED_TITLES,
    V1Tlv.LOCALIZED_ICONS,
})


@dataclass(slots=True)
class ConvertReport:
    written: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Program:
    base: V1Package | None = None
    updates: dict[int, V1Package] = field(default_factory=dict)  # by version


def convert_v1(src: str, out_dir: str | None = None, *, stem: str | None = None,
               work_dir: str | None = None, application_id: int | None = None,
               report: ConvertReport | None = None) -> ConvertReport:
    """report: where the warnings go as they come, the caller's to show when
    the conversion fails partway too."""
    report = report if report is not None else ConvertReport()
    # --name as `nup pack` takes it: a title's name, made a safe file name
    stem = name_stem(stem) or os.path.splitext(os.path.basename(src))[0]
    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(src)), stem + ".v2")
    made_out = not os.path.isdir(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    try:
        return convert_into(src, out_dir, stem, work_dir, application_id, report)
    except BaseException:
        if made_out:   # a folder this run made goes too, once nothing of it is left inside
            try:
                os.rmdir(out_dir)
            except OSError:
                pass
        raise


def convert_into(src: str, out_dir: str, stem: str, work_dir: str | None,
                 application_id: int | None, report: ConvertReport) -> ConvertReport:
    staged: list[tuple[str, str]] = []  # (partial, final): each claimed before it is written
    with V1Reader(src) as reader:
        work = tempfile.mkdtemp(prefix=".nup-convert-", dir=work_dir or out_dir)
        try:
            Converter(reader, src, out_dir, stem, work, application_id, report, staged).run()
        except BaseException:
            for partial, _final in staged:  # no half conversion left behind
                if os.path.isfile(partial):
                    os.remove(partial)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)
    created: list[str] = []
    try:
        for partial, final in staged:  # every container is whole: only now do they take their names
            if os.path.exists(final):
                report.warnings.append(f"replaced the existing {final!r}")
            else:
                created.append(final)
            os.replace(partial, final)
            report.written.append(final)
    except BaseException:
        # no half conversion left behind: the containers not yet named go, and so do
        # those this run named fresh (a container it replaced cannot come back)
        for partial, _final in staged:
            if os.path.isfile(partial):
                os.remove(partial)
        for final in created:
            if final in report.written and os.path.isfile(final):
                os.remove(final)
        raise
    return report


class Converter:
    def __init__(self, reader: V1Reader, src: str, out_dir: str, stem: str, work: str,
                 application_id: int | None, report: ConvertReport,
                 staged: list[tuple[str, str]]) -> None:
        self.reader, self.src, self.out_dir, self.stem, self.work = reader, src, out_dir, stem, work
        self.report, self.staged = report, staged
        self.packages = [p for p in reader.packages if self.keep(p)]
        if not self.packages:
            raise NupError(f"{src!r} holds no package to convert")
        self.app = application_id if application_id is not None else self.derive_application()
        self.refiled: set[int] = set()   # v1 package indexes program_of re-filed, said once
        self.app_meta, self.app_meta_label = self.application_metadata()
        self.title_tlvs: dict[int, bytes] | None = None   # identity_tlvs(app_meta), made on first use
        self.program_packages = self.programs()
        self.v1_programs = set(self.program_packages)
        self.nested_bases: dict[int, str] = {}   # program<N>/ folders found in program 0's base tree

    def warn(self, text: str) -> None:
        self.report.warnings.append(text)

    def keep(self, package: V1Package) -> bool:
        if package.kind == KIND_SYSTEM:
            self.warn(f"{package.label}: system packages have no v2 equivalent; skipped")
            return False
        if not package.files:
            self.warn(f"{package.label}: no files; skipped")
            return False
        unknown = sorted(t for t in package.tlvs if t not in KNOWN_V1_TLVS)
        if unknown:
            self.warn(f"{package.label}: dropped TLV type(s) {', '.join(f'{t:#06x}' for t in unknown)}")
        return True

    def derive_application(self) -> int:
        """Application ids are 0x2000-aligned; a program, patch or add-on id
        masks back to its application (SPEC §4); a data patch is filed
        under its add-on's id."""
        ids = [p.title_id for p in self.packages]
        apps = {title_number(i) & APPLICATION_MASK for i in ids}
        if len(apps) > 1:
            raise NupError(
                "the packages name several applications ("
                + ", ".join(f"{a:016x}" for a in sorted(apps))
                + "); pass --application-id"
            )
        # in the lowest range present: a Switch 2 Edition's application is its
        # Switch program 0's (01…), its Switch 2 program's id is in 04… (SPEC §4.1)
        return min(i & APPLICATION_MASK for i in ids)

    def application_metadata(self) -> tuple[dict[int, bytes], str]:
        """The title's metadata and the label of the package that holds it: on
        program 0's base in v1, else on program 0's first update (v1 SPEC
        §5.1), else on any program package that carries a name, program 0's
        first; never an add-on's, whose name is not the title's."""
        candidates = sorted((p for p in self.packages if p.kind in (KIND_BASE, KIND_UPDATE)),
                            key=lambda p: (self.program_of(p) != 0, p.kind != KIND_BASE,
                                           self.program_of(p), p.index))
        for package in candidates:
            if V1Tlv.TITLE_NAME in package.tlvs or V1Tlv.NACP in package.tlvs:
                return package.tlvs, package.label
        return (candidates[0].tlvs, candidates[0].label) if candidates else ({}, "the title")

    # ---- metadata

    def tlvs_for(self, package: V1Package, *, identity: bool, label: str,
                 inherit: bool = True) -> dict[int, bytes]:
        """v2 TLVs for a package: its own display version (its TLV, else its
        NACP's); with identity, the names, icons and provenance from its own
        metadata, or (inherit: a program's package) the title's when it
        carries none (SPEC §3.1). An add-on's are its own: the title's name
        is not the add-on's."""
        own = package.tlvs
        tlvs: dict[int, bytes] = {}
        own_control = control_of(own)
        stated = own.get(V1Tlv.DISPLAY_VERSION)
        if own_control and own_control.display_version:
            # the package's own NACP says what it is; v1 put the title's one version
            # on the base, which may name the newest update instead
            tlvs[TlvType.DISPLAY_VERSION] = own_control.display_version.encode("utf-8")
            if stated and bytes(stated) != tlvs[TlvType.DISPLAY_VERSION]:
                self.warn(f"{label}: display version {bytes(stated).decode('utf-8', 'replace')!r} differs "
                          f"from its NACP's {own_control.display_version!r}; the NACP's kept (set another "
                          "with `nup edit --display-version`)")
        else:
            self.put_text(tlvs, TlvType.DISPLAY_VERSION, stated, label)
        if not identity:
            return tlvs
        carries = V1Tlv.TITLE_NAME in own or V1Tlv.NACP in own
        if carries or not inherit:
            tlvs.update(self.identity_tlvs(own, label))
        else:   # the title's, made once for every package that takes it (its warnings said once)
            if self.title_tlvs is None:
                self.title_tlvs = self.identity_tlvs(self.app_meta, self.app_meta_label)
            tlvs.update(self.title_tlvs)
        return tlvs

    def identity_tlvs(self, source: dict[int, bytes], label: str) -> dict[int, bytes]:
        """Names, icons and provenance from one package's v1 metadata."""
        tlvs: dict[int, bytes] = {}
        source_control = control_of(source)
        if source_control:
            names = control_tlvs(source_control, identity=True)
            names.pop(TlvType.DISPLAY_VERSION, None)  # the version is the package's own
            tlvs.update(names)
        self.put_text(tlvs, TlvType.TITLE_NAME, source.get(V1Tlv.TITLE_NAME), label)
        self.put_text(tlvs, TlvType.PUBLISHER, source.get(V1Tlv.PUBLISHER), label)
        titles = self.localized(source, V1Tlv.LOCALIZED_TITLES, label)
        for tag, title in titles.items():   # language by language over the NACP's
            try:
                bytes(title).decode("utf-8")   # a title is text, as put_text has it
            except UnicodeDecodeError:
                self.warn(f"{label}: localized title {tag!r} is not UTF-8; dropped")
                continue
            merge_localized(tlvs, TlvType.LOCALIZED_TITLE, tag, title)
        provenance = bytes(source.get(V1Tlv.SOURCE_DUMP) or b"unknown").decode("utf-8", "replace")
        tlvs[TlvType.SOURCE_DUMP] = f"{provenance}; converted from NUP v1".encode("utf-8")
        self.add_icons(tlvs, source, label)
        return tlvs

    def put_text(self, tlvs: dict[int, bytes], tlv_type: TlvType, value, label: str) -> None:
        if not value:
            return
        try:
            bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            self.warn(f"{label}: TLV {tlv_type.name.lower()} is not UTF-8; dropped")
            return
        tlvs[tlv_type] = bytes(value)

    def localized(self, source: dict[int, bytes], v1_type: int, label: str) -> dict[str, bytes]:
        if v1_type not in source:
            return {}
        try:
            records = parse_localized(memoryview(bytes(source[v1_type])), lenient=True)
        except NupError as error:
            self.warn(f"{label}: localized TLV {v1_type:#06x} dropped ({error})")
            return {}
        for tag in [tag for tag in records if not tag.isascii()]:  # v2 tags are ASCII (layout.localized_tag)
            self.warn(f"{label}: localized TLV {v1_type:#06x}: tag {tag!r} is not ASCII; its record dropped")
            del records[tag]
        return records

    def add_icons(self, tlvs: dict[int, bytes], source: dict[int, bytes], label: str) -> None:
        """The default icon as v1 stored it, re-encoded only past the TLV cap;
        localized icons whose bytes differ from it, while the localized TLV
        has room (SPEC §3, §3.1)."""
        from .image import add_localized_icon, prepare_icon

        icon = source.get(V1Tlv.ICON)
        if icon:
            try:
                tlvs[TlvType.ICON] = prepare_icon(bytes(icon), TLV_MAX_LENGTH, f"{label} icon")
            except NupError as error:
                self.warn(f"{label}: icon dropped ({error})")
        for tag, data in self.localized(source, V1Tlv.LOCALIZED_ICONS, label).items():
            if icon and bytes(data) == bytes(icon):
                continue  # the default already shows it
            try:
                add_localized_icon(tlvs, tag, bytes(data), f"{label} icon {tag}")
            except NupError as error:
                self.warn(f"{label}: localized icon {tag!r} dropped ({error})")

    # ---- packing

    def run(self) -> None:
        for index, program in sorted(self.program_packages.items()):
            self.convert_program(index, program)
        self.convert_addons()

    def programs(self) -> dict[int, Program]:
        programs: dict[int, Program] = {}
        for package in self.packages:
            if package.kind not in (KIND_BASE, KIND_UPDATE):
                continue
            index = self.program_of(package)
            program = programs.setdefault(index, Program())
            if package.kind == KIND_BASE:
                if program.base is not None:
                    self.warn(f"{package.label}: a second base of program {index}; skipped")
                    continue
                program.base = package
            elif package.version in program.updates:
                self.warn(f"{package.label}: a second update v{package.version} of program {index}; skipped")
            else:
                program.updates[package.version] = package
        return programs

    def program_of(self, package: V1Package) -> int:
        """v1 has no program index: Yoink filed a Switch 2 Edition's program
        among program 0's packages with the program's own id, so such a
        package takes the index its id gives: an update whether or not
        program 0 has one of its version, and a base the same way."""
        if package.kind not in (KIND_BASE, KIND_UPDATE):
            return 0
        offset = (title_number(package.title_id) - title_number(self.app)) & ~PATCH_OFFSET
        if 0 < offset <= PROGRAM_INDEX_MAX:
            if package.index not in self.refiled:
                self.refiled.add(package.index)
                kind = "base" if package.kind == KIND_BASE else "update"
                self.warn(f"{package.label}: a {kind} named after program {offset}; converted as that program")
            return offset
        return 0

    def program_id(self, package: V1Package, index: int, directory: str) -> int:
        """The id `nup pack` gives the unpacked tree (packcli.program_title_id):
        its NPDM's, else the v1 package's (a patch id is 0x800 above its
        program's), else the application id + index."""
        title = package.title_id
        if (title_number(title) - title_number(self.app)) & PATCH_OFFSET:
            title -= PATCH_OFFSET
        fallback = title if title_number(title) != title_number(self.app) or index == 0 else None
        return program_title_id(directory, self.app, index, fallback)

    def out(self, variant: str, version: int = 0, program: int = 0) -> str:
        """Where to pack an output: a hidden partial file, named for real once the
        whole conversion has succeeded (convert_v1)."""
        name = os.path.basename(default_name(".", variant, version, self.stem, program))
        path = os.path.join(self.out_dir, name)
        # samefile: a name that differs only in case is the source on a folder that folds case
        if os.path.exists(path) and os.path.samefile(path, self.src):
            raise NupError(f"converting would overwrite {self.src!r}; pass -o with another folder")
        partial = os.path.join(self.out_dir, f".{name}.partial.nup")
        self.staged.append((partial, path))
        return partial

    def unpack(self, package: V1Package, files=None, name: str = "p") -> str:
        """files of the package (all by default) into a work folder of their own,
        decompressed and hash-checked, refused where a host could not hold them (SPEC §6.4)."""
        files = package.files if files is None else files
        target_root = os.path.join(self.work, f"{name}{package.index}")
        os.makedirs(target_root)
        check_extract_paths(target_root, [f.path for f in files])
        for entry in files:
            target = safe_target(target_root, entry.path)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            self.reader.copy_file(entry, target)
        return target_root

    def nested_programs(self, package: V1Package, directory: str, index: int) -> list[tuple[int, str]]:
        """program<N>/ folders beside exefs/ and romfs/ of an unpacked tree: v1
        packed a flattened dump as one package, `nup pack` keeps each program
        apart (SPEC §4.1), so they convert as programs of their own."""
        found = []
        for nested, path in flattened_programs(directory):
            if index or nested in self.v1_programs:
                why = (f"inside program {index}'s tree" if index else
                       "which the file also holds as packages of its own")
                self.warn(f"{package.label}: its {os.path.basename(path)}/ folder is program {nested}, "
                          f"{why}; its files dropped")
                continue
            found.append((nested, path))
        return found

    def convert_nested(self, package: V1Package, directory: str, index: int, version: int,
                       as_base: bool) -> None:
        for nested, path in self.nested_programs(package, directory, index):
            title = program_title_id(path, self.app, nested)
            if as_base:
                out = self.out("base", 0, nested)
                pack_base_container(out, path, title_id=title, version=version, program_index=nested,
                                    application_id=self.app)
                self.nested_bases[nested] = out
            elif nested in self.nested_bases:
                pack_update_container(self.out("update", version, nested), path, self.nested_bases[nested],
                                      version=version, application_id=self.app)
            else:   # SPEC §5.2: a program that arrived in an update is stored as a base
                pack_base_container(self.out("standalone", version, nested), path, title_id=title,
                                    version=version, program_index=nested, application_id=self.app)

    def convert_program(self, index: int, program: Program) -> None:
        if program.base is None:
            # SPEC §5.2: an update without its base is stored as a base
            for version, update in sorted(program.updates.items()):
                directory = self.unpack(update)
                out = self.out("standalone", version, index)
                pack_base_container(
                    out, directory, title_id=self.program_id(update, index, directory), version=version,
                    # the title's v1 metadata only where the tree has no Control content of its own
                    tlvs=self.tree_version_kept(self.tlvs_for(update, identity=True, label=update.label,
                                                              inherit=read_control(directory) is None),
                                                directory, update.label),
                    program_index=index, application_id=self.app,
                )
                self.convert_nested(update, directory, index, version, as_base=False)
                shutil.rmtree(directory, ignore_errors=True)
            return
        base = program.base
        unversioned = [u for u in program.updates.values()
                       if V1Tlv.DISPLAY_VERSION not in u.tlvs and control_of(u.tlvs) is None]
        if V1Tlv.DISPLAY_VERSION in base.tlvs and control_of(base.tlvs) is None and unversioned:
            self.warn(f"{base.label}: v1 keeps one display version "
                      f"({bytes(base.tlvs[V1Tlv.DISPLAY_VERSION]).decode('utf-8', 'replace')!r}) on the base; "
                      "it may describe the newest update, set it with `nup edit --display-version`")
        directory = self.unpack(base)
        fallback = self.update_control(program, directory)
        base_out = self.out("base", 0, index)
        pack_base_container(
            base_out, directory, title_id=self.program_id(base, index, directory), version=base.version,
            # the title's v1 metadata only where no Control content (its own or its update's) names it
            tlvs=self.tree_version_kept(self.tlvs_for(base, identity=True, label=base.label,
                                                      inherit=read_control(directory) is None and fallback is None),
                                        directory, base.label),
            program_index=index, application_id=self.app, control_fallback=fallback,
        )
        self.convert_nested(base, directory, index, base.version, as_base=True)
        shutil.rmtree(directory, ignore_errors=True)
        if fallback is not None:
            shutil.rmtree(fallback, ignore_errors=True)
        for version, update in sorted(program.updates.items()):
            if update.flags & PKG_FLAG_STANDALONE:
                self.warn(f"{update.label}: marked standalone, but its base is in the file; diffed against it")
            directory = self.unpack(update)
            out = self.out("update", version, index)
            pack_update_container(out, directory, base_out, version=version, application_id=self.app,
                                  tlvs=self.tree_version_kept(self.tlvs_for(update, identity=False, label=update.label),
                                                              directory, update.label))
            self.convert_nested(update, directory, index, version, as_base=False)
            shutil.rmtree(directory, ignore_errors=True)

    def tree_version_kept(self, tlvs: dict[int, bytes], directory: str, label: str) -> dict[int, bytes]:
        """tlvs without v1's display version when the unpacked tree's own NACP
        names another: v1 put the title's one version on the base, which may
        name the newest update; the tree's Control content says what it is."""
        tree = read_control(directory)
        stated = tlvs.get(TlvType.DISPLAY_VERSION)
        if tree is None or not tree.display_version or stated is None \
                or stated == tree.display_version.encode("utf-8"):
            return tlvs
        self.warn(f"{label}: display version {stated.decode('utf-8', 'replace')!r} differs from its "
                  f"tree's NACP's {tree.display_version!r}; the NACP's kept (set another with "
                  "`nup edit --display-version`)")
        return {tlv: value for tlv, value in tlvs.items() if tlv != TlvType.DISPLAY_VERSION}

    def update_control(self, program: Program, base_dir: str) -> str | None:
        """The Control content of the program's newest update that has one,
        unpacked on its own, for a base without its own (base_dir: the base's
        unpacked tree) to take its identity from, as `nup pack` does
        (packcli.newest_control, SPEC §3.1)."""
        if read_control(base_dir) is not None:
            return None   # the base's own serves
        for _version, update in sorted(program.updates.items(), reverse=True):
            # where read_control looks (nacp.find_control_dir): control/, else the tree's root
            files = [entry for entry in update.files if entry.path.startswith("control/")]
            if not any(entry.path == "control/control.nacp" for entry in files):
                # the Control files only: the root may also hold a romfs.img of gigabytes
                files = [entry for entry in update.files if entry.path == "control.nacp"
                         or (entry.path.startswith("icon_") and entry.path.endswith(".dat")
                             and "/" not in entry.path)]
                if not any(entry.path == "control.nacp" for entry in files):
                    continue
            root = self.unpack(update, files, name="control")
            if read_control(root) is not None:
                return root
            shutil.rmtree(root, ignore_errors=True)
        return None

    def addon_tlvs(self, package: V1Package) -> dict[int, bytes]:
        """An add-on's or data patch's own name, icons, display version and provenance."""
        return self.tlvs_for(package, identity=True, inherit=False, label=package.label)

    def unique_addons(self) -> list[V1Package]:
        """The add-ons, one per title id (a dlc container holds each once): of
        several versions of one, the newest."""
        kept, passed_over = newest_per_title([p for p in self.packages if p.kind == KIND_ADDON],
                                             lambda p: p.title_id, lambda p: p.version)
        for left_out, kept_one in passed_over:
            self.warn(f"{left_out.label}: a second add-on {left_out.title_id:016x}; "
                      f"v{kept_one.version} ({kept_one.label}) kept, the newest (the first of equal "
                      f"versions), v{left_out.version} skipped")
        return kept

    def convert_addons(self) -> None:
        addons = self.unique_addons()
        patches = []
        for package in (p for p in self.packages if p.kind == KIND_ADDON_UPDATE):
            # v1.0 reserves the kind and names no add-on: Yoink files a data patch
            # under its add-on's id; the console's patch id is the add-on's + 0x800
            addon_id = package.title_id
            patch_id = addon_id + PATCH_OFFSET
            self.warn(f"{package.label}: data patch id taken as {patch_id:016x}")
            patches.append((package, addon_id, patch_id))
        # a container holds each data patch once: its scope is addonupdate/<i>/<v>
        patches, repeated = first_per_key(patches, lambda item: (item[2], item[0].version))
        for package, _addon_id, patch_id in repeated:
            self.warn(f"{package.label}: data patch {patch_id:016x} v{package.version} again; skipped")
        # SPEC §5.4: a data patch whose add-on is absent packs as that add-on; its
        # newer versions chain on it as add-on updates
        lone, patches = split_lone_patches(patches, {p.title_id for p in addons},
                                           lambda item: item[1], lambda item: item[0].version)
        if not addons and not lone:
            return
        members = [(p, p.title_id, p.version) for p in addons]
        members += [(p, addon_id, p.version) for p, addon_id, _patch in lone]
        dirs = [self.unpack(p) for p, _id, _v in members]
        dlc_out = self.out("dlc")
        pack_addon_container(dlc_out, dirs, application_id=self.app,
                             title_ids=[i for _p, i, _v in members], versions=[v for _p, _i, v in members],
                             tlvs=[self.addon_tlvs(p) for p, _i, _v in members])
        for directory in dirs:
            shutil.rmtree(directory, ignore_errors=True)
        if not patches:
            return
        inputs = [AddonPatchInput(self.unpack(p), p.version, patch_id, addon_id, self.addon_tlvs(p))
                  for p, addon_id, patch_id in patches]
        update_out = self.out("dlc.update")
        pack_addon_update_container(update_out, inputs, dlc_out)
        for patch in inputs:
            shutil.rmtree(patch.content_dir, ignore_errors=True)


def control_of(tlvs: dict[int, bytes]):
    nacp = tlvs.get(V1Tlv.NACP)
    return parse_nacp(bytes(nacp)) if nacp and len(nacp) >= NACP_MIN_SIZE else None


