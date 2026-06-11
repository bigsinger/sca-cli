from __future__ import annotations

import json
from pathlib import Path

from sca_cli.normalize.findings import Finding
from sca_cli.rules.engine import RuleEngine
from sca_cli.rules.loader import load_rules
from sca_cli.scanners.base import ScanContext

DANGEROUS_SCRIPT_NAMES = {"preinstall", "install", "postinstall", "prepare", "prepublish"}
DANGEROUS_COMMAND_MARKERS = [
    "curl ",
    "wget ",
    "powershell",
    "Invoke-WebRequest",
    "iwr ",
    "bash -c",
    "sh -c",
    "node -e",
    "python -c",
    "base64",
    "certutil",
    "nc ",
    "netcat",
]


def scan_install_scripts(context: ScanContext) -> list[Finding]:
    rules = load_rules(context.paths.rules, categories={"install_script"})
    findings = RuleEngine(rules).scan(context.target_dir)
    findings.extend(_scan_package_scripts(context.target_dir))
    return findings


def _scan_package_scripts(root: Path) -> list[Finding]:
    package = root / "package.json"
    if not package.exists():
        return []
    try:
        data = json.loads(package.read_text(encoding="utf-8"))
    except Exception:
        return []
    findings: list[Finding] = []
    scripts = data.get("scripts") or {}
    for name, command in scripts.items():
        if name not in DANGEROUS_SCRIPT_NAMES:
            continue
        severity = "critical" if any(marker.lower() in str(command).lower() for marker in DANGEROUS_COMMAND_MARKERS) else "high"
        findings.append(
            Finding(
                category="install_script",
                severity=severity,
                title=f"package.json {name} lifecycle script",
                description="npm lifecycle scripts can execute during install and are risky for Agent Skill packages.",
                rule_id="JS-INSTALL-001",
                file_path="package.json",
                evidence=f"{name}: {command}",
                remediation="Remove install-time execution or move the behavior behind an explicit user command.",
                source="builtin:package-json",
            )
        )
    return findings
