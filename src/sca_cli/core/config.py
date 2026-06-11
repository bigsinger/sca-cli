from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from sca_cli.core.paths import AppPaths, ensure_layout

DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "home": None,
        "log_level": "INFO",
        "max_download_size_mb": 500,
        "keep_workspace_days": 7,
    },
    "scan": {
        "default_sbom": True,
        "default_rules": True,
        "default_vuln": False,
        "default_report": False,
        "fail_on": "none",
        "offline": False,
    },
    "external_tools": {
        "syft": "syft",
        "grype": "grype",
        "pip_audit": "pip-audit",
        "npm": "npm",
        "git": "git",
    },
    "sync": {
        "enabled_sources": ["osv", "spdx"],
        "nvd_api_key": None,
        "proxy": None,
        "timeout_seconds": 300,
    },
    "rules": {
        "enabled_categories": [
            "skill_metadata",
            "mcp_tool",
            "plugin_manifest",
            "install_script",
            "high_risk_api",
            "malicious_package",
            "openapi_risk",
            "ai_infra_fingerprint",
        ]
    },
    "report": {
        "default_formats": ["html", "md", "json"],
        "company_name": None,
        "logo_path": None,
    },
}


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def write_default_config(paths: AppPaths, *, force: bool = False) -> None:
    ensure_layout(paths)
    if paths.config.exists() and not force:
        return
    paths.config.write_text(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False), encoding="utf-8")


def load_config(paths: AppPaths) -> dict[str, Any]:
    write_default_config(paths, force=False)
    loaded = yaml.safe_load(paths.config.read_text(encoding="utf-8")) or {}
    return deep_merge(DEFAULT_CONFIG, loaded)


def save_config(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
