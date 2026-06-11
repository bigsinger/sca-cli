from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sca_cli.core.paths import AppPaths


@dataclass(frozen=True, slots=True)
class Workspace:
    root: Path
    input: Path
    extracted: Path
    sbom: Path
    raw_results: Path
    normalized: Path


def create_workspace(paths: AppPaths, scan_id: str) -> Workspace:
    root = paths.workspaces / scan_id
    workspace = Workspace(
        root=root,
        input=root / "input",
        extracted=root / "extracted",
        sbom=root / "sbom",
        raw_results=root / "raw-results",
        normalized=root / "normalized",
    )
    for path in [
        workspace.root,
        workspace.input,
        workspace.extracted,
        workspace.sbom,
        workspace.raw_results,
        workspace.normalized,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    return workspace
