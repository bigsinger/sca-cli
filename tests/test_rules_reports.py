from __future__ import annotations

from pathlib import Path

from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.core.project_detect import detect_project
from sca_cli.core.workspace import create_workspace
from sca_cli.normalize.findings import dedupe_findings, summarize_findings
from sca_cli.reports.generator import generate_scan_reports
from sca_cli.scanners.base import ScanContext
from sca_cli.scanners.high_risk_api import scan_high_risk_apis
from sca_cli.scanners.install_script import scan_install_scripts
from sca_cli.scanners.skill_rules import scan_skill_rules
from sca_cli.scanners.syft import generate_sbom


def test_rule_scanners_detect_mcp_command_tool(tmp_path: Path) -> None:
    root = Path("tests/fixtures/mcp_command_tool")
    paths = build_paths(tmp_path / "home")
    ensure_layout(paths)
    workspace = create_workspace(paths, "test-scan")
    profile = detect_project(root)
    context = ScanContext(
        scan_id="test-scan",
        target_dir=root,
        workspace=workspace,
        paths=paths,
        profile=profile,
        config={"external_tools": {"syft": "syft"}},
        options={"project_name": "mcp"},
    )
    findings = dedupe_findings(scan_skill_rules(context) + scan_high_risk_apis(context))
    assert any(item.rule_id == "MCP-TOOL-004" for item in findings)
    assert any(item.rule_id == "SKILL-META-001" for item in findings)
    assert any(item.rule_id == "PY-HIGHAPI-002" for item in findings)


def test_install_script_scanner_detects_postinstall(tmp_path: Path) -> None:
    root = Path("tests/fixtures/js_postinstall_risk")
    paths = build_paths(tmp_path / "home")
    ensure_layout(paths)
    workspace = create_workspace(paths, "test-scan")
    context = ScanContext(
        scan_id="test-scan",
        target_dir=root,
        workspace=workspace,
        paths=paths,
        profile=detect_project(root),
        config={"external_tools": {"syft": "syft"}},
        options={"project_name": "js"},
    )
    findings = scan_install_scripts(context)
    assert any(item.rule_id == "JS-INSTALL-001" for item in findings)


def test_report_generation(tmp_path: Path) -> None:
    root = Path("tests/fixtures/python_safe_skill")
    paths = build_paths(tmp_path / "home")
    ensure_layout(paths)
    workspace = create_workspace(paths, "test-scan")
    context = ScanContext(
        scan_id="test-scan",
        target_dir=root,
        workspace=workspace,
        paths=paths,
        profile=detect_project(root),
        config={"external_tools": {"syft": "__missing_syft__"}},
        options={"project_name": "safe"},
    )
    components, sbom_path, _ = generate_sbom(context)
    summary = summarize_findings(components, [])
    result = {
        "scan_id": "test-scan",
        "target": {"origin": str(root), "prepared_path": str(root), "type": "directory"},
        "project_name": "safe",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "profile": context.profile.to_dict(),
        "options": context.options,
        "warnings": context.warnings,
        "summary": summary,
        "components": [item.to_dict() for item in components],
        "findings": [],
        "sbom": {"path": str(sbom_path)},
        "reports": {},
    }
    reports = generate_scan_reports(result, tmp_path / "reports", ["html", "md", "json"])
    assert Path(reports["html"]).exists()
    assert Path(reports["md"]).exists()
    assert Path(reports["json"]).exists()
