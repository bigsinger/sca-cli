from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppPaths:
    home: Path
    config: Path
    db: Path
    cache: Path
    downloads: Path
    workspaces: Path
    reports: Path
    sbom: Path
    rules: Path
    logs: Path


def default_home() -> Path:
    env_home = os.environ.get("SCA_CLI_HOME")
    if env_home:
        return Path(env_home).expanduser()
    return Path.home() / ".sca-cli"


def build_paths(home: str | Path | None = None) -> AppPaths:
    resolved_home = Path(home).expanduser() if home else default_home()
    return AppPaths(
        home=resolved_home,
        config=resolved_home / "config.yaml",
        db=resolved_home / "sca-cli.db",
        cache=resolved_home / "cache",
        downloads=resolved_home / "downloads",
        workspaces=resolved_home / "workspaces",
        reports=resolved_home / "reports",
        sbom=resolved_home / "sbom",
        rules=resolved_home / "rules",
        logs=resolved_home / "logs",
    )


def ensure_layout(paths: AppPaths) -> None:
    for path in [
        paths.home,
        paths.cache,
        paths.downloads,
        paths.workspaces,
        paths.reports,
        paths.sbom,
        paths.rules,
        paths.logs,
    ]:
        path.mkdir(parents=True, exist_ok=True)
    for child in ["skill", "mcp", "python", "javascript", "malicious-packages", "ai-infra"]:
        (paths.rules / child).mkdir(parents=True, exist_ok=True)
