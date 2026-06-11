from __future__ import annotations

from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.normalize.findings import Finding, normalize_severity
from sca_cli.scanners.base import ScanContext
from sca_cli.utils.json import loads


def scan_npm_audit(context: ScanContext) -> list[Finding]:
    if not context.profile.has_javascript:
        return []
    if context.options.get("offline"):
        context.warnings.append("Offline mode enabled. npm audit scan skipped.")
        return []
    npm_cmd = context.config["external_tools"].get("npm", "npm")
    if which(npm_cmd) is None:
        context.warnings.append("npm not found. JavaScript-specific npm audit skipped.")
        return []
    if not (context.target_dir / "package-lock.json").exists() and not (context.target_dir / "npm-shrinkwrap.json").exists():
        context.warnings.append("No package-lock.json or npm-shrinkwrap.json found. npm audit skipped.")
        return []
    result = run_tool([npm_cmd, "audit", "--json", "--package-lock-only"], cwd=context.target_dir, timeout_seconds=300)
    if result.returncode not in {0, 1}:
        context.warnings.append(f"npm audit failed: {result.stderr.strip() or result.stdout.strip()}")
        return []
    (context.workspace.raw_results / "npm-audit.json").write_text(result.stdout, encoding="utf-8")
    try:
        return _parse_npm_audit(loads(result.stdout))
    except Exception as exc:
        context.warnings.append(f"npm audit JSON parse failed: {exc}")
        return []


def _parse_npm_audit(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    vulnerabilities = data.get("vulnerabilities") or {}
    for name, vuln in vulnerabilities.items():
        via_items = vuln.get("via") or []
        direct_advisories = [item for item in via_items if isinstance(item, dict)]
        if not direct_advisories:
            findings.append(
                Finding(
                    category="vulnerability",
                    severity=normalize_severity(vuln.get("severity")),
                    title=f"{name} has npm advisory",
                    description="npm audit reported a transitive vulnerability.",
                    component_name=name,
                    ecosystem="npm",
                    vuln_id=str(vuln.get("source") or name),
                    evidence="npm audit",
                    remediation=vuln.get("fixAvailable") if isinstance(vuln.get("fixAvailable"), str) else None,
                    source="npm-audit",
                    raw=vuln,
                )
            )
            continue
        for advisory in direct_advisories:
            findings.append(
                Finding(
                    category="vulnerability",
                    severity=normalize_severity(advisory.get("severity") or vuln.get("severity")),
                    title=advisory.get("title") or f"{name} has npm advisory",
                    description=advisory.get("url") or "",
                    component_name=name,
                    ecosystem="npm",
                    vuln_id=str(advisory.get("source") or advisory.get("name") or name),
                    evidence=advisory.get("range"),
                    remediation="Review npm audit fix recommendation.",
                    source="npm-audit",
                    raw=advisory,
                )
            )
    return findings
