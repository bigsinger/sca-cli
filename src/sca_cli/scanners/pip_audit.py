from __future__ import annotations

from pathlib import Path

from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.normalize.findings import Finding, normalize_severity
from sca_cli.scanners.base import ScanContext
from sca_cli.utils.json import read_json


def scan_pip_audit(context: ScanContext) -> list[Finding]:
    if not context.profile.has_python:
        return []
    if context.options.get("offline"):
        context.warnings.append("Offline mode enabled. pip-audit scan skipped.")
        return []
    cmd = context.config["external_tools"].get("pip_audit", "pip-audit")
    if which(cmd) is None:
        context.warnings.append("pip-audit not found. Python-specific vulnerability scan skipped.")
        return []

    output = context.workspace.raw_results / "pip-audit.json"
    requirements = _find_requirements(context.target_dir)
    if requirements:
        command = [cmd, "-r", str(requirements), "-f", "json", "-o", str(output)]
    elif (context.target_dir / "pyproject.toml").exists():
        command = [cmd, "--project", str(context.target_dir), "-f", "json", "-o", str(output)]
    else:
        context.warnings.append("No requirements.txt or pyproject.toml found. pip-audit scan skipped.")
        return []

    result = run_tool(command, cwd=context.target_dir)
    if result.returncode not in {0, 1}:
        context.warnings.append(f"pip-audit failed: {result.stderr.strip() or result.stdout.strip()}")
        return []
    try:
        return _parse_pip_audit(read_json(output))
    except Exception as exc:
        context.warnings.append(f"pip-audit JSON parse failed: {exc}")
        return []


def _find_requirements(root: Path) -> Path | None:
    for candidate in [root / "requirements.txt", root / "requirements.lock"]:
        if candidate.exists():
            return candidate
    matches = sorted(root.glob("requirements*.txt"))
    return matches[0] if matches else None


def _parse_pip_audit(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for dep in data.get("dependencies") or []:
        for vuln in dep.get("vulns") or []:
            fix_versions = vuln.get("fix_versions") or []
            aliases = vuln.get("aliases") or []
            vuln_id = vuln.get("id") or (aliases[0] if aliases else None)
            findings.append(
                Finding(
                    category="vulnerability",
                    severity=normalize_severity(vuln.get("severity") or "medium"),
                    title=f"{dep.get('name')} affected by {vuln_id}",
                    description=vuln.get("description") or "",
                    component_name=dep.get("name"),
                    component_version=dep.get("version"),
                    ecosystem="pypi",
                    vuln_id=vuln_id,
                    evidence="pip-audit",
                    remediation=f"Upgrade to {', '.join(fix_versions)}" if fix_versions else None,
                    source="pip-audit",
                    raw=vuln,
                )
            )
    return findings
