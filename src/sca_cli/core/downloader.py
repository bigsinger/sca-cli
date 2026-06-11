from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from sca_cli.core.extractor import safe_extract_archive
from sca_cli.core.paths import AppPaths
from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.core.workspace import Workspace


@dataclass(slots=True)
class PreparedTarget:
    path: Path
    input_type: str
    origin: str
    warnings: list[str] = field(default_factory=list)


def is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def is_git_url(value: str) -> bool:
    lower = value.lower()
    parsed = urlparse(value)
    if lower.endswith(".git"):
        return True
    return parsed.scheme in {"http", "https", "ssh", "git"} and any(
        host in lower for host in ["github.com/", "gitlab.com/", "bitbucket.org/"]
    )


def is_archive(path_or_url: str) -> bool:
    lower = path_or_url.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def prepare_target(
    target: str,
    *,
    paths: AppPaths,
    workspace: Workspace,
    max_download_size_mb: int = 500,
    git_command: str = "git",
) -> PreparedTarget:
    target_path = Path(target).expanduser()
    if target_path.exists() and target_path.is_dir():
        return PreparedTarget(path=target_path.resolve(), input_type="directory", origin=target)
    if target_path.exists() and target_path.is_file() and is_archive(str(target_path)):
        extracted = workspace.extracted / "archive"
        safe_extract_archive(target_path.resolve(), extracted)
        return PreparedTarget(path=extracted, input_type="archive", origin=target)
    if is_git_url(target):
        return _clone_git(target, workspace=workspace, git_command=git_command)
    if is_http_url(target):
        downloaded = _download_url(target, paths=paths, max_download_size_mb=max_download_size_mb)
        extracted = workspace.extracted / "download"
        try:
            safe_extract_archive(downloaded, extracted)
        except ValueError as exc:
            raise ValueError(f"Downloaded URL is not a supported archive: {target}") from exc
        return PreparedTarget(path=extracted, input_type="url-archive", origin=target)
    raise FileNotFoundError(f"Target not found or unsupported: {target}")


def _clone_git(target: str, *, workspace: Workspace, git_command: str) -> PreparedTarget:
    if which(git_command) is None:
        raise RuntimeError("git is required to scan Git URLs. Install git or scan a local archive/directory.")
    destination = workspace.input / "repo"
    result = run_tool([git_command, "clone", "--depth", "1", target, str(destination)], cwd=workspace.input)
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip() or result.stdout.strip()}")
    return PreparedTarget(path=destination, input_type="git", origin=target)


def _download_url(target: str, *, paths: AppPaths, max_download_size_mb: int) -> Path:
    paths.downloads.mkdir(parents=True, exist_ok=True)
    parsed = urlparse(target)
    suffix = "".join(Path(parsed.path).suffixes) or ".bin"
    output = paths.downloads / f"{uuid4().hex}{suffix}"
    max_bytes = max_download_size_mb * 1024 * 1024
    with httpx.stream("GET", target, follow_redirects=True, timeout=60) as response:
        response.raise_for_status()
        length = response.headers.get("content-length")
        if length and int(length) > max_bytes:
            raise RuntimeError(f"Download exceeds maximum size of {max_download_size_mb} MB")
        total = 0
        with output.open("wb") as fh:
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    fh.close()
                    output.unlink(missing_ok=True)
                    raise RuntimeError(f"Download exceeds maximum size of {max_download_size_mb} MB")
                fh.write(chunk)
    return output


def copy_local_archive_to_workspace(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination
