from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path


class UnsafeArchiveError(RuntimeError):
    pass


def _assert_inside(base: Path, candidate: Path) -> None:
    base_resolved = base.resolve()
    candidate_resolved = candidate.resolve()
    if candidate_resolved != base_resolved and base_resolved not in candidate_resolved.parents:
        raise UnsafeArchiveError(f"Archive member escapes target directory: {candidate}")


def safe_extract_zip(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            target = destination / info.filename
            _assert_inside(destination, target)
        zf.extractall(destination)
    return destination


def safe_extract_tar(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                raise UnsafeArchiveError(f"Archive links are not allowed: {member.name}")
            target = destination / member.name
            _assert_inside(destination, target)
        tf.extractall(destination)
    return destination


def safe_extract_archive(archive: Path, destination: Path) -> Path:
    name = archive.name.lower()
    if name.endswith(".zip") or zipfile.is_zipfile(archive):
        return safe_extract_zip(archive, destination)
    if name.endswith((".tar", ".tar.gz", ".tgz")) or tarfile.is_tarfile(archive):
        return safe_extract_tar(archive, destination)
    raise ValueError(f"Unsupported archive format: {archive}")
