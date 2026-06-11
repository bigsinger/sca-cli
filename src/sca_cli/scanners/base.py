from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sca_cli.core.paths import AppPaths
from sca_cli.core.project_detect import ProjectProfile
from sca_cli.core.workspace import Workspace


@dataclass(slots=True)
class ScanContext:
    scan_id: str
    target_dir: Path
    workspace: Workspace
    paths: AppPaths
    profile: ProjectProfile
    config: dict[str, Any]
    options: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
