from __future__ import annotations

from pathlib import Path

from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.normalize.findings import Finding, normalize_severity
from sca_cli.scanners.base import ScanContext
from sca_cli.utils.json import read_json


def scan_grype(context: ScanContext, sbom_path: Path | None) -> list[Finding]:
    grype_cmd = context.config["external_tools"].get("grype", "grype")
    if which(grype_cmd) is None:
        context.warnings.append("Grype not found. Generic vulnerability scanning skipped.")
        return []
    output = context.workspace.raw_results / "grype.json"
    target = f"sbom:{sbom_path}" if sbom_path and sbom_path.exists() else str(context.target_dir)
    result = run_tool([grype_cmd, target, "-o", "json", "--file", str(output)])
    if result.returncode != 0:
        context.warnings.append(f"Grype scan failed: {result.stderr.strip() or result.stdout.strip()}")
        return []
    try:
        data = read_json(output)
    except Exception as exc:
        context.warnings.append(f"Grype JSON parse failed: {exc}")
        return []
    return _parse_grype(data)


def _parse_grype(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vuln_id = vuln.get("id")
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        findings.append(
            Finding(
                category="vulnerability",
                severity=normalize_severity(vuln.get("severity")),
                title=f"{artifact.get('name') or 'component'} affected by {vuln_id or 'vulnerability'}",
                description=vuln.get("description") or "",
                component_name=artifact.get("name"),
                component_version=artifact.get("version"),
                ecosystem=_ecosystem_from_type(artifact.get("type"), artifact.get("purl")),
                vuln_id=vuln_id,
                evidence=artifact.get("purl") or artifact.get("locations", [{}])[0].get("path"),
                remediation=f"Upgrade to {', '.join(fix_versions)}" if fix_versions else vuln.get("fix", {}).get("state"),
                source="grype",
                raw=match,
            )
        )
    return findings


def _ecosystem_from_type(value: str | None, purl: str | None) -> str | None:
    if purl and purl.startswith("pkg:"):
        return purl.split("/", 1)[0].removeprefix("pkg:")
    if value == "python":
        return "pypi"
    if value in {"npm", "javascript", "node"}:
        return "npm"
    return value
