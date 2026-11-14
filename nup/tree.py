"""Dump-tree walking: container paths, ordering rules, and exclusions."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import PurePosixPath
import re
import unicodedata

from .errors import NupError
from .layout import ARTIFACT_SUFFIXES, DELETED_NAME, META_NAME

READ_CHUNK = 4 << 20
PREFIX_SIZE = 0x200


@dataclass(slots=True)
class SourceFile:
    """One packable file: its container path and where the bytes live."""

    container_path: str
    fs_path: str
    size: int


def validate_container_path(path: str) -> None:
    if not path or path != path.strip():
        raise NupError(f"invalid entry path {path!r}")
    if path.startswith("/") or "//" in path or path.endswith("/"):
        raise NupError(f"invalid entry path {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise NupError(f"invalid entry path {path!r}")
    if "\\" in path:
        raise NupError(f"entry path {path!r} contains a backslash")


WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{port}{n}" for port in ("COM", "LPT") for n in [*"123456789", "¹", "²", "³"]}
)
WINDOWS_INVALID = frozenset('<>:"|?*') | frozenset(chr(code) for code in range(0x20))


def windows_name_problem(part: str) -> str | None:
    """Why Windows cannot hold a path component as it is, or None."""
    # the device name before any extension, trailing spaces dropped as Windows drops them ('NUL .txt')
    if part.split(".", 1)[0].rstrip(" ").upper() in WINDOWS_RESERVED:
        return "a reserved device name"
    if any(char in WINDOWS_INVALID for char in part):
        return "a character Windows does not allow"
    if part.endswith((".", " ")):
        return "a trailing dot or space"
    return None


def collisions(paths, key) -> list[tuple[str, str]]:
    """Pairs of different paths that key() maps to one name."""
    seen: dict[str, str] = {}
    pairs = []
    for path in paths:
        other = seen.setdefault(key(path), path)
        if other != path:
            pairs.append((other, path))
    return pairs


def folds_name(directory: str, written: str, looked_up: str) -> bool:
    """Whether the folder finds a file written as one name under another (a probe).
    The probe takes a fresh suffix and is created only if new: a file the folder
    already holds is never overwritten or removed."""
    import secrets

    os.makedirs(directory, exist_ok=True)
    suffix = "-" + secrets.token_hex(8)   # digits and a-f, alike in either case
    probe = os.path.join(directory, written + suffix)
    with open(probe, "xb"):
        pass
    try:
        return os.path.exists(os.path.join(directory, looked_up + suffix))
    finally:
        os.remove(probe)


def case_insensitive(directory: str) -> bool:
    """Whether a folder folds case (probed: it depends on the filesystem, not the OS)."""
    return folds_name(directory, ".NupCaseProbe", ".nupcaseprobe")


def normalization_insensitive(directory: str) -> bool:
    """Whether a folder treats the composed and decomposed Unicode spellings of a
    name as one file (probed)."""
    return folds_name(directory, ".NupFormProbeé", ".NupFormProbe" + unicodedata.normalize("NFD", "é"))


def is_link(path: str) -> bool:
    return os.path.islink(path) or os.path.isjunction(path)


def safe_target(root: str, path: str) -> str:
    """Where an extractor writes a container path under root (SPEC §6.4): never
    through an existing symlink or junction, never a name the host cannot hold."""
    parts = path.split("/")
    if os.name == "nt":
        for part in parts:
            problem = windows_name_problem(part)
            if problem:
                raise NupError(f"{path!r} cannot be written on Windows: {part!r} is {problem}")
    current = root
    for part in parts:
        current = os.path.join(current, part)
        if is_link(current):
            raise NupError(f"refusing to write {path!r} through the link {current!r}")
    return current


def tree_nodes(paths: list[str]) -> list[str]:
    """Every file and every folder the paths make, each once, in order."""
    nodes: dict[str, None] = {}
    for path in paths:
        parts = path.split("/")
        for end in range(1, len(parts)):
            nodes.setdefault("/".join(parts[:end]))
        nodes.setdefault(path)
    return list(nodes)


def check_extract_paths(root: str, paths: list[str]) -> None:
    """Refuse a set of paths the target folder would merge: names that differ only
    in case or in Unicode normalization, where the folder folds them, files and
    folders alike, and a file that is also another path's folder (SPEC §6.4)."""
    files = set(paths)
    for path in paths:
        parts = path.split("/")
        for end in range(1, len(parts)):
            if "/".join(parts[:end]) in files:
                raise NupError(f"{'/'.join(parts[:end])!r} is a file and the folder of {path!r}")
    paths = tree_nodes(paths)
    if not collisions(paths, lambda p: unicodedata.normalize("NFC", p).lower()):
        return  # nothing any folder could merge: no probe
    fold_case, fold_form = case_insensitive(root), normalization_insensitive(root)

    def key(path: str) -> str:
        name = unicodedata.normalize("NFC", path) if fold_form else path
        return name.lower() if fold_case else name

    pairs = collisions(paths, key)
    if pairs:
        a, b = pairs[0]
        raise NupError(
            f"{a!r} and {b!r} are one name to {root!r}, which folds "
            + " and ".join(w for w, on in (("case", fold_case), ("Unicode normalization", fold_form)) if on)
            + f" ({len(pairs)} such pair(s); extract to a folder that tells them apart)"
        )


CONTENT_MARKERS = ("exefs", "romfs")
PROGRAM_DIR = re.compile(r"^program0*([1-9]\d*)$")   # leading zeros too, as program/<index>/ takes them


def is_content_dir(path: str) -> bool:
    return any(os.path.isdir(os.path.join(path, marker)) for marker in CONTENT_MARKERS)


def is_program_dir(parent: str, name: str) -> bool:
    """program<N>/ (N >= 1) beside exefs/ and romfs/ of a flattened version
    folder: another program of the same version, a content dir of its own."""
    return bool(PROGRAM_DIR.match(name)) and is_content_dir(os.path.join(parent, name))


def walk_own_content(root: str):
    """os.walk of a content dir without the program<N>/ folders beside its
    exefs/ and romfs/: another program's content (discover.flattened_programs)."""
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath == root:
            dirnames[:] = [name for name in dirnames if not is_program_dir(root, name)]
        yield dirpath, dirnames, filenames


def walk_content_dir(root: str, scope: str) -> list[SourceFile]:
    sources = []
    images = section_images(root)
    for dirpath, dirnames, filenames in walk_own_content(root):
        for name in dirnames + filenames:
            if is_link(os.path.join(dirpath, name)):
                raise NupError(f"{os.path.join(dirpath, name)!r} is a link; dumps hold plain files (SPEC §6.4)")
        for filename in sorted(filenames):
            if filename.endswith(ARTIFACT_SUFFIXES):
                continue
            if dirpath == root and filename in images:
                continue
            if filename in (META_NAME, DELETED_NAME):
                raise NupError(
                    f"{filename!r} at {dirpath!r} is reserved for the container"
                )
            fs_path = os.path.join(dirpath, filename)
            relative = os.path.relpath(fs_path, root).replace(os.sep, "/")
            container_path = f"{scope}/{relative}"
            validate_container_path(container_path)
            sources.append(SourceFile(container_path, fs_path, os.path.getsize(fs_path)))
    sources.sort(key=lambda source: source.container_path.encode("utf-8"))
    return sources


def section_images(root: str) -> set[str]:
    """Root files that duplicate a section: Yoink's romfs.img beside romfs/."""
    return {
        f"{section}.img" for section in ("exefs", "romfs")
        if os.path.isfile(os.path.join(root, f"{section}.img"))
        and os.path.isdir(os.path.join(root, section))
    }


def hash_source(source: SourceFile) -> tuple[bytes, bytes]:
    """Whole-file SHA-256 and prefix SHA-256 (first 0x200 bytes)."""
    whole = hashlib.sha256()
    with open(source.fs_path, "rb") as handle:
        remaining = source.size
        while remaining:
            chunk = handle.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise NupError(f"{source.fs_path!r} changed while packing")
            whole.update(chunk)
            remaining -= len(chunk)
    with open(source.fs_path, "rb") as handle:
        head = handle.read(PREFIX_SIZE)
    return whole.digest(), hashlib.sha256(head).digest()


def hash_bytes(data: bytes) -> tuple[bytes, bytes]:
    return hashlib.sha256(data).digest(), hashlib.sha256(data[:PREFIX_SIZE]).digest()


def iter_file_chunks(fs_path: str, size: int):
    with open(fs_path, "rb") as handle:
        remaining = size
        while remaining:
            chunk = handle.read(min(READ_CHUNK, remaining))
            if not chunk:
                raise NupError(f"{fs_path!r} changed while writing")
            remaining -= len(chunk)
            yield chunk


def encode_deleted_manifest(paths: list[str]) -> bytes:
    return b"".join(path.encode("utf-8") + b"\n" for path in sorted(paths))


def parse_deleted_manifest(data: bytes) -> list[str]:
    return [line.decode("utf-8") for line in data.split(b"\n") if line]
