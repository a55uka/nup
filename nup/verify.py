"""Integrity verification levels (SPEC §6.3): bind, package, full."""

from dataclasses import dataclass, field
import hashlib

from .errors import NupError, VerificationError
from .layout import align_up
from .reader import NupReader


@dataclass(slots=True)
class VerifyReport:
    level: str
    entries_hashed: int = 0
    bytes_hashed: int = 0
    packages_checked: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "entries_hashed": self.entries_hashed,
            "bytes_hashed": self.bytes_hashed,
            "packages_checked": self.packages_checked,
        }


LEVELS = ("bind", "package", "full")


def verify_container(
    reader: NupReader,
    level: str = "bind",
    package_selector: str | int | None = None,
) -> VerifyReport:
    if level not in LEVELS:
        raise NupError(f"unknown verification level {level!r}")
    reader.check_bind()
    report = VerifyReport(level=level)
    if level == "bind":
        return report
    records = select_packages(reader, package_selector) if level == "package" else list(reader.meta.packages)
    if level == "package" and not records:
        raise NupError(f"no package matches {package_selector!r}")
    for record in records:
        report.packages_checked.append(package_label(reader, record))
        for offset, row in enumerate(record.files):
            entry = reader.entries[record.first_entry_index + offset]
            digest, size = hash_entry(reader, entry)
            if digest != row.sha256:
                raise VerificationError(
                    f"entry {entry.name!r} data hash mismatch in package {package_label(reader, record)}"
                )
            report.entries_hashed += 1
            report.bytes_hashed += size
    if level == "full":
        reader.verify_entry_table_hashes()
        reader.verify_data_coverage()
    return report


def select_packages(reader: NupReader, selector: str | int | None):
    """One selector semantics for every --package flag (issue #26): a scope
    label ('update/458752'), a kind name when unambiguous ('update'), or a
    record index."""
    if selector is None or selector == "all":
        return list(reader.meta.packages)
    text = str(selector)   # an int is a record index, as its digits are
    by_label = [
        record for record in reader.meta.packages
        if package_label(reader, record) == text
    ]
    if by_label:
        return by_label
    by_kind = [
        record for record in reader.meta.packages
        if record.kind.name.lower() == text.lower()
    ]
    if by_kind:
        if len(by_kind) > 1:
            raise NupError(
                f"{text!r} matches {len(by_kind)} packages; use the scope "
                "label or record index"
            )
        return by_kind
    if text.isascii() and text.isdigit() and int(text) < len(reader.meta.packages):   # '²' is a digit too
        return [reader.meta.packages[int(text)]]
    raise NupError(f"no package matches {selector!r}")


def package_label(reader: NupReader, record) -> str:
    from .model import scope_of

    return scope_of(record)


def hash_entry(reader: NupReader, entry) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in reader.iter_entry_chunks(entry):
        digest.update(chunk)
        size += len(chunk)
    return digest.digest(), size


def covered_size(reader: NupReader) -> int:
    return sum(align_up(entry.size) for entry in reader.entries[1:])
