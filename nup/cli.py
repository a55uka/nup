"""Command line interface: pack, info, verify, hashlist, extract, edit, convert."""

import argparse
from contextlib import ExitStack
import json
import os
import sys

from . import __version__
from .errors import NupError
from .packcli import add_pack_arguments, command_pack
from .reader import NupReader, read_container


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    container = getattr(args, "file", None)
    if container is not None and os.path.isdir(container):
        hint = "; use `nup pack` to turn a dump folder into a .nup" if args.command == "info" else ""
        print(f"nup: error: {container!r} is a folder, expected a .nup file{hint}", file=sys.stderr)
        return 1
    try:
        return args.handler(args)
    except NupError as error:
        print(f"nup: error: {error}{v1_hint(args, container)}", file=sys.stderr)
        return 1
    except OSError as error:  # a missing or unreadable file: one line, not a traceback (PR #22)
        if error.filename and os.path.isdir(error.filename):   # a folder as --base, --chain, ...
            print(f"nup: error: {error.filename!r} is a folder, expected a .nup file", file=sys.stderr)
        else:
            print(f"nup: error: {error}", file=sys.stderr)
        return 1


def v1_hint(args, container: str | None) -> str:
    """A NUP v1 file handed to a v2 command: say how to convert it."""
    from .v1 import MAGIC

    if container is None or args.command == "convert":
        return ""
    try:
        with open(container, "rb") as handle:
            is_v1 = handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return ""
    return f" ({container!r} is a NUP v1 file: `nup convert` turns it into v2 containers)" if is_v1 else ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nup", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack", help="pack a dump directory into a .nup container")
    add_pack_arguments(pack)
    pack.set_defaults(handler=command_pack)

    info = sub.add_parser("info", help="describe a container")
    info.add_argument("file")
    info.add_argument("--json", action="store_true")
    info.add_argument("--entries", action="store_true")
    info.set_defaults(handler=command_info)

    verify = sub.add_parser("verify", help="check container integrity")
    verify.add_argument("file")
    verify.add_argument("--level", choices=("bind", "package", "full"), default=None,
                        help="default: bind, or full with --against")
    verify.add_argument("--package", default=None,
                        help="package scope for --level package (the level it implies without --level)")
    verify.add_argument("--against", action="append", default=[], metavar="LIST",
                        help="known-good list(s) to look every package up in (SPEC §6.5)")
    verify.add_argument("--base", action="append", default=[], metavar="NUP",
                        help="with --against: container(s) an update or add-on update lands on "
                        "(base, earlier updates, dlc), to recompute its content hash")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=command_verify)

    hashlist = sub.add_parser("hashlist", help="write known-good list lines for containers (SPEC §6.5)")
    hashlist.add_argument("files", nargs="+")
    hashlist.add_argument("-o", "--out", help="list file to write (default: stdout)")
    hashlist.add_argument("--base", action="append", default=[], metavar="NUP",
                          help="container(s) the updates or add-on updates land on, to recompute "
                          "their content hash and state size")
    hashlist.set_defaults(handler=command_hashlist)

    convert = sub.add_parser("convert", help="convert a NUP v1 file into v2 containers (best effort)")
    convert.add_argument("file", help="NUP v1 file")
    convert.add_argument("-o", "--out", help="output folder (default: <name>.v2/ beside the input)")
    convert.add_argument("--name", help="output name stem (default: the input's file name)")
    convert.add_argument("--work-dir", help="folder for unpacking packages: one program package at a "
                         "time, every add-on together (they pack into one container), then every "
                         "data patch (default: inside the output folder)")
    convert.add_argument("--application-id", help="application id, 16 hex digits "
                         "(default: derived from the packages' title ids)")
    convert.set_defaults(handler=command_convert)

    extract = sub.add_parser("extract", help="write container entries to a directory")
    add_extract_arguments(extract)
    extract.set_defaults(handler=command_extract)

    edit = sub.add_parser("edit", help="modify a container")
    add_edit_arguments(edit)
    edit.set_defaults(handler=command_edit)
    return parser


def add_extract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file")
    parser.add_argument("-o", "--out", required=True)
    parser.add_argument("--apply", action="store_true", help="materialize the game tree")
    parser.add_argument("--base", help="base .nup when materializing an update container")
    parser.add_argument("--chain", action="append", default=[], metavar="UPDATE_NUP",
                        help="intermediate update container(s) to apply first, in version order")
    parser.add_argument("--package", default=None, help="extract one package scope only")
    parser.add_argument("--no-verify", action="store_true", help="skip per-file hash checks")
    parser.add_argument("--json", action="store_true")


def add_edit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("file")
    parser.add_argument("-o", "--out", help="output path (default: edit in place)")
    parser.add_argument("--package", default=None,
                        help="package for metadata edits: scope label (addon/2), kind when only "
                        "one package has it, or index "
                        "(default: the only package, else the base)")
    meta = parser.add_argument_group("metadata (SPEC §3)")
    meta.add_argument("--name", help="title name, default language")
    meta.add_argument("--display-version", help="display version string, e.g. 1.2.0; without --package "
                      "it names the newest update the container holds, as in pack")
    meta.add_argument("--publisher")
    meta.add_argument("--icon", metavar="IMAGE",
                      help="icon image; a JPEG that fits is kept as is, anything else becomes "
                      "a 256x256 JPEG (needs Pillow)")
    meta.add_argument("--lang-name", action="append", default=[], metavar="LANG=TEXT",
                      help="localized title, BCP 47 tag (e.g. ja=...)")
    meta.add_argument("--lang-icon", action="append", default=[], metavar="LANG=IMAGE")
    parser.add_argument("--set-tlv", action="append", default=[], metavar="TYPE=VALUE")
    parser.add_argument("--del-tlv", action="append", default=[], metavar="TYPE")
    parser.add_argument("--add-file", action="append", default=[], metavar="PATH=SRC")
    parser.add_argument("--replace-file", action="append", default=[], metavar="PATH=SRC")
    parser.add_argument("--rm-file", action="append", default=[], metavar="PATH")
    parser.add_argument("--base", help="base .nup for update identity recomputation")


def command_info(args) -> int:
    from .info import container_info, render_info

    with NupReader(args.file) as reader:
        info = container_info(reader, include_entries=args.entries)
    print(json.dumps(info, indent=2) if args.json else render_info(info))
    return 0


def command_verify(args) -> int:
    from .verify import verify_container

    if args.base and not args.against:
        raise NupError("--base recomputes content hashes for --against; pass a known-good list")
    # --package names what to hash: without --level it means --level package
    level = args.level or ("package" if args.package else "full" if args.against else "bind")
    with ExitStack() as stack:
        # a base's data counts as hashed only when the file's is (--level full)
        bases = open_verified(stack, args.base, "bind" if level == "bind" else "full")
        reader = stack.enter_context(NupReader(args.file))
        report = verify_container(reader, level, args.package)
        # --level package looks up the package(s) it hashed, not the ones left out
        only = set(report.packages_checked) if level == "package" else None
        matches = against_lists(reader, args.against, set(report.packages_checked), bases, only) \
            if args.against else []
    if args.json:
        payload = report.as_dict()
        if args.against:
            payload["known"] = [
                {"package": m.label, "content_hash": m.entry.content_hash, "known": m.ok,
                 "listed": m.known is not None, "name": m.known.name if m.known else None,
                 "problem": m.problem, "unverified": m.unverified}
                for m in matches
            ]
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"{args.file}: {report.level} verification passed "
            f"({report.entries_hashed} entries, {report.bytes_hashed:,} bytes hashed)"
        )
        for m in matches:
            print(f"  {m.label}: {match_state(m)}")
    return 0 if all(m.ok for m in matches) else 1


def match_state(m) -> str:
    if m.problem:
        return m.problem
    if m.known is None:
        return "not in the list(s)" + (f" ({m.unverified})" if m.unverified else "")
    name = m.known.name or m.known.source
    # after bind, or for a diff not materialized, the file only claims the state (SPEC §6.5)
    return f"claims: {name}; not proven: {m.unverified}" if m.unverified else f"known: {name}"


def open_verified(stack: ExitStack, paths: list[str], level: str) -> list[NupReader]:
    """Containers open on stack, each verified at level before its file table
    counts toward a diff's recomputed content hash."""
    from .verify import verify_container

    bases = []
    for path in paths:
        base = stack.enter_context(read_container(path))
        verify_container(base, level)
        bases.append(base)
    return bases


def against_lists(reader, paths: list[str], hashed: set[str], bases, only: set[str] | None = None):
    from .hashlist import check_against, read_lists

    return check_against(reader, read_lists(paths), hashed=hashed, bases=bases, only=only)


def command_hashlist(args) -> int:
    from .hashlist import entry_of, format_list, materialized_states
    from .layout import DIFF_KINDS
    from .verify import package_label

    entries = []
    with ExitStack() as stack:
        # list what the data is, not what the meta claims: a diff's state takes
        # the unchanged files from its base, so the base's data is hashed too;
        # a diff lands on a base listed beside it as on one given with --base
        bases = open_verified(stack, args.base, "full")
        readers = open_verified(stack, args.files, "full")
        states = materialized_states([*bases, *readers])
        for path, reader in zip(args.files, readers):
            for record in reader.meta.packages:
                if record.kind in DIFF_KINDS and id(record) not in states:
                    print(f"nup: warning: {path}: {package_label(reader, record)}: content hash taken "
                          "from the container, not recomputed (pass --base with the container(s) "
                          "it lands on)", file=sys.stderr)
                entry = entry_of(reader, record, states.get(id(record)))
                if entry.content_hash != record.content_hash.hex():
                    # what verify --against reports as a problem is no state to vouch for
                    raise NupError(f"{path}: {package_label(reader, record)}: the stored content hash "
                                   "does not match the state its data makes; not listed")
                entries.append(entry)
    text = format_list(entries)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


def command_convert(args) -> int:
    from .convert import ConvertReport, convert_v1
    from .packcli import parse_title_id

    application = parse_title_id(args.application_id, "--application-id")
    report = ConvertReport()
    try:
        convert_v1(args.file, args.out, stem=args.name, work_dir=args.work_dir,
                   application_id=application, report=report)
    finally:   # what it noticed before a failure can be why it failed
        for line in report.warnings:
            print(f"nup: warning: {line}", file=sys.stderr)
    for path in report.written:
        print(f"converted {path}")
    return 0


def command_extract(args) -> int:
    from .extract import extract_with_options, summarize

    with ExitStack() as stack:   # every container opened is closed, also when a later one fails to open
        base_reader = stack.enter_context(read_container(args.base)) if args.base else None
        chain = [stack.enter_context(read_container(link)) for link in args.chain]
        reader = stack.enter_context(NupReader(args.file))
        report = extract_with_options(
            reader,
            args.out,
            package=args.package,
            apply=args.apply,
            base_reader=base_reader,
            chain=chain,
            verify=not args.no_verify,
        )
    print(summarize(report))
    return 0


def command_edit(args) -> int:
    from .edit import edit_container, edit_in_place, ops_from_args

    ops = ops_from_args(args)
    report = edit_container(args.file, args.out, ops) if args.out else edit_in_place(args.file, ops)
    for line in report.warnings:
        print(f"nup: warning: {line}", file=sys.stderr)
    print(
        f"edited {report.output}: {report.tlvs_set} TLVs set, {report.tlvs_removed} removed, "
        f"{report.files_added} added, {report.files_replaced} replaced, {report.files_removed} removed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
