from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
}


@dataclass(slots=True)
class ProjectProfile:
    project_type: str
    skill_mode: str
    features: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    has_python: bool = False
    has_javascript: bool = False
    has_mcp: bool = False
    has_plugin: bool = False
    has_agent_skill: bool = False
    has_lockfile: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_type": self.project_type,
            "skill_mode": self.skill_mode,
            "features": self.features,
            "manifests": self.manifests,
            "warnings": self.warnings,
            "has_python": self.has_python,
            "has_javascript": self.has_javascript,
            "has_mcp": self.has_mcp,
            "has_plugin": self.has_plugin,
            "has_agent_skill": self.has_agent_skill,
            "has_lockfile": self.has_lockfile,
        }


def iter_project_files(root: Path, *, max_files: int = 10000) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
            if len(files) >= max_files:
                break
    return files


def detect_project(root: Path, *, forced_type: str = "auto", forced_skill_mode: str = "auto") -> ProjectProfile:
    files = iter_project_files(root)
    rels = {path.relative_to(root).as_posix() for path in files}
    basenames = {path.name for path in files}

    has_python = bool(
        basenames
        & {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg"}
    ) or any(path.suffix == ".py" for path in files)
    has_js = bool(basenames & {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}) or any(
        path.suffix in {".js", ".ts", ".mjs", ".cjs"} for path in files
    )
    has_lockfile = bool(basenames & {"poetry.lock", "Pipfile.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"})

    manifests: list[str] = []
    features: list[str] = []

    manifest_names = {
        "mcp.json",
        "ai-plugin.json",
        "skill.json",
        "agent.json",
        "tool.json",
        "tools.json",
        "plugin.yaml",
        "plugin.yml",
        "plugin.json",
        "manifest.yaml",
        "manifest.yml",
        "manifest.json",
        "openapi.yaml",
        "openapi.yml",
        "openapi.json",
        "package.json",
        "pyproject.toml",
    }
    for rel in sorted(rels):
        if Path(rel).name in manifest_names:
            manifests.append(rel)

    has_mcp = "mcp.json" in basenames or _contains_any(files, ["mcp.server", "FastMCP", "MCPServer", "@modelcontextprotocol"])
    has_plugin = bool(basenames & {"ai-plugin.json", "openapi.yaml", "openapi.yml", "openapi.json"}) or "ai-plugin.json" in rels
    has_agent_skill = bool(
        basenames
        & {
            "skill.json",
            "agent.json",
            "tool.json",
            "tools.json",
            "plugin.yaml",
            "plugin.yml",
            "plugin.json",
            "manifest.yaml",
            "manifest.yml",
            "manifest.json",
        }
    ) or any(rel.startswith(("prompts/", "tools/")) for rel in rels)

    if _package_has_mcp_dependency(root / "package.json"):
        has_mcp = True
        features.append("package.json depends on @modelcontextprotocol")
    if _pyproject_has_mcp_dependency(root / "pyproject.toml"):
        has_mcp = True
        features.append("pyproject.toml depends on mcp/modelcontextprotocol")
    if "tools/" in {str(Path(rel).parent).replace("\\", "/") + "/" for rel in rels}:
        features.append("tools directory detected")

    if forced_type != "auto":
        project_type = forced_type
    elif has_python and has_js:
        project_type = "mixed"
    elif has_python:
        project_type = "python"
    elif has_js:
        project_type = "javascript"
    elif has_mcp:
        project_type = "mcp"
    elif has_plugin:
        project_type = "plugin"
    else:
        project_type = "unknown"

    if forced_skill_mode != "auto":
        skill_mode = forced_skill_mode
    elif has_mcp:
        skill_mode = "mcp"
    elif has_plugin:
        skill_mode = "plugin"
    elif has_agent_skill:
        skill_mode = "agent"
    else:
        skill_mode = "auto"

    warnings: list[str] = []
    if (has_python or has_js) and not has_lockfile:
        warnings.append("No Python or JavaScript lockfile detected; dependency confidence is reduced.")

    return ProjectProfile(
        project_type=project_type,
        skill_mode=skill_mode,
        features=features,
        manifests=manifests,
        warnings=warnings,
        has_python=has_python,
        has_javascript=has_js,
        has_mcp=has_mcp,
        has_plugin=has_plugin,
        has_agent_skill=has_agent_skill,
        has_lockfile=has_lockfile,
    )


def _contains_any(files: list[Path], needles: list[str]) -> bool:
    compiled = re.compile("|".join(re.escape(item) for item in needles))
    for path in files:
        if path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".toml"}:
            continue
        try:
            if compiled.search(path.read_text(encoding="utf-8", errors="ignore")):
                return True
        except OSError:
            continue
    return False


def _package_has_mcp_dependency(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    deps: dict[str, Any] = {}
    for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        deps.update(data.get(key) or {})
    return any("@modelcontextprotocol" in name.lower() for name in deps)


def _pyproject_has_mcp_dependency(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return False
    dependencies = list(data.get("project", {}).get("dependencies") or [])
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies") or {}
    dependencies.extend(poetry_deps.keys())
    return any("modelcontextprotocol" in item.lower() or re.match(r"^mcp([<>=!~ ].*)?$", item.lower()) for item in dependencies)
