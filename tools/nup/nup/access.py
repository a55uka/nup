"""NUP tree access: traversal, metadata accessors, and extraction.

Convenience layer over a parsed NupReader: directory traversal and path
resolution, per-package meta/localized accessors, and subtree extraction.
Functions take the reader as their first argument.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from . import format as F
from . import meta as M
from .read import NodeRef

if TYPE_CHECKING:
    from .read import NupReader, PackageInfo

    from collections.abc import Callable


def find_package(
    r: NupReader,
    kind: int | None = None,
    title_id: int | None = None,
    version: int | None = None,
) -> PackageInfo | None:
    for p in r.packages:
        if kind is not None and p.kind != kind:
            continue
        if title_id is not None and p.title_id != title_id:
            continue
        if version is not None and p.version != version:
            continue
        return p
    return None


def iter_children(r: NupReader, dir_index: int) -> list[NodeRef]:
    _, first, count = r.dirs[dir_index]
    out = []
    for slot in range(first, first + count):
        cid = r.children[slot]
        if cid >= r.dir_count:
            fi = cid - r.dir_count
            out.append(NodeRef(False, fi, r.files[fi][0]))
        else:
            out.append(NodeRef(True, cid, r.dirs[cid][0]))
    return out


def find_child(r: NupReader, dir_index: int, name: bytes) -> NodeRef | None:
    children = iter_children(r, dir_index)
    lo, hi = 0, len(children)
    while lo < hi:
        mid = (lo + hi) // 2
        if children[mid].name < name:
            lo = mid + 1
        else:
            hi = mid
    if lo < len(children) and children[lo].name == name:
        return children[lo]
    return None


def raw_meta_records(r: NupReader, pkg: PackageInfo) -> list[tuple[int, bytes]]:
    """(TLV type, payload) exactly as stored in the package's meta block."""
    block = r._mm[pkg.meta_offset:pkg.meta_offset + pkg.meta_size]
    return [(t, payload) for _pos, t, payload in M.iter_tlvs(block)]


def meta_records(r: NupReader, pkg: PackageInfo) -> list[tuple[int, bytes]]:
    """(TLV type, payload) with SPEC §5 types. Blocks written with the
    shifted IDs (M.is_legacy_block) are read one type up."""
    records = raw_meta_records(r, pkg)
    if pkg.index in r.legacy_meta:
        return [(M.upgrade_type(t), payload) for t, payload in records]
    return records


def _localized(r: NupReader, pkg: PackageInfo, tlv_type: int) -> dict[bytes, bytes]:
    out: dict[bytes, bytes] = {}
    for t, payload in meta_records(r, pkg):
        if t == tlv_type:
            out.update(M.decode_localized(payload))
    return out


def localized_titles(r: NupReader, pkg: PackageInfo) -> dict[bytes, bytes]:
    """BCP-47 tag (lowercase bytes) -> UTF-8 title name. SPEC §5.1, TLV 0x0009."""
    return _localized(r, pkg, F.TLV_LOCALIZED_TITLES)


def localized_icons(r: NupReader, pkg: PackageInfo) -> dict[bytes, bytes]:
    """BCP-47 tag (lowercase bytes) -> image bytes. SPEC §5.1, TLV 0x000A."""
    return _localized(r, pkg, F.TLV_LOCALIZED_ICONS)


def app_meta(r: NupReader, pkg: PackageInfo) -> dict[int, bytes]:
    """TLV type -> payload, preferring the base (or first) package's block."""
    return dict(meta_records(r, pkg))


def build_id(r: NupReader, pkg: PackageInfo) -> bytes | None:
    """32-byte ModuleId from meta TLV 0x0007, or None if absent (SPEC §5).

    Bytes 0x40..0x60 of the package's `main` (NSO0/NRO0 header); only the
    first 0x14 are significant in SDK-built titles."""
    payload = app_meta(r, pkg).get(F.TLV_BUILD_ID)
    if payload is not None and len(payload) != 32:
        raise F.NupError(f"build ID TLV payload is {len(payload)} bytes, expected 32")
    return payload


def resolve_path(r: NupReader, pkg: PackageInfo, relpath: str) -> NodeRef | None:
    """Resolve a '/'-separated path from the package root."""
    cur = NodeRef(True, pkg.root_dir, b"")
    for part in relpath.split("/"):
        if not part:
            continue
        if not cur.is_dir:
            return None
        nxt = find_child(r, cur.index, part.encode("utf-8"))
        if nxt is None:
            return None
        cur = nxt
    return cur


def extract_tree(
    r: NupReader,
    dest: str,
    dir_index: int,
    progress: Callable[[int, NodeRef], None] | None = None,
) -> int:
    """Extract a directory subtree to dest. Returns number of files written."""
    n = 0
    os.makedirs(dest, exist_ok=True)
    stack = [(dir_index, dest)]
    while stack:
        di, dpath = stack.pop()
        os.makedirs(dpath, exist_ok=True)
        for child in iter_children(r, di):
            cpath = os.path.join(dpath, child.name.decode("utf-8", "surrogateescape"))
            if child.is_dir:
                stack.append((child.index, cpath))
            else:
                data = r.read_file(child.index)
                with open(cpath, "wb") as fh:
                    fh.write(data)
                n += 1
                if progress:
                    progress(n, child)
    return n
