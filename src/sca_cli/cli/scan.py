from __future__ import annotations

import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sca_cli.core.config import load_config
from sca_cli.core.downloader import prepare_target
from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.core.project_detect import detect_project
from sca_cli.core.workspace import create_workspace
from sca_cli.db.repositories import save_scan_result
from sca_cli.db.session import connect, init_db
from sca_cli.normalize.findings import SEVERITY_ORDER, dedupe_findings, summarize_findings
from sca_cli.reports.generator import generate_scan_reports
from sca_cli.scanners.base import ScanContext
from sca_cli.scanners.grype import scan_grype
from sca_cli.scanners.high_risk_api import scan_high_risk_apis
from sca_cli.scanners.install_script import scan_install_scripts
from sca_cli.scanners.license import scan_licenses
from sca_cli.scanners.npm_audit import scan_npm_audit
from sca_cli.scanners.pip_audit import scan_pip_audit
from sca_cli.scanners.skill_rules import scan_skill_rules
from sca_cli.scanners.syft import generate_sbom
from sca_cli.utils.json import dumps, write_json
from sca_cli.utils.time import make_scan_id, utc_now_iso

console = Console()


def scan_command(
    target: str = typer.Argument(..., help="Directory, archive, Git URL, or archive URL to scan."),
    name: str | None = typer.Option(None, "--name", help="Project name for reports."),
    type_: str = typer.Option("auto", "--type", help="auto|python|javascript|mcp|plugin|mixed"),
    skill_mode: str = typer.Option("auto", "--skill-mode", help="agent|mcp|plugin|auto"),
    sbom: bool = typer.Option(True, "--sbom/--no-sbom", help="Generate SBOM."),
    vuln: bool = typer.Option(False, "--vuln", help="Enable vulnerability scanners."),
    rules: bool = typer.Option(True, "--rules/--no-rules", help="Enable built-in and local rule scans."),
    license_scan: bool = typer.Option(False, "--license", help="Enable license policy scan."),
    report: bool = typer.Option(False, "--report", help="Generate scan reports."),
    formats: str = typer.Option("html,md,json", "--format", help="Comma-separated report formats."),
    output: Path | None = typer.Option(None, "--output", help="Report output directory."),
    scanner: str = typer.Option("auto", "--scanner", help="auto|all or comma-separated scanner IDs."),
    fail_on: str = typer.Option("none", "--fail-on", help="critical|high|medium|low|none"),
    offline: bool = typer.Option(False, "--offline", help="Avoid scanners that require network access."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    max_download_size: int = typer.Option(500, "--max-download-size", help="Maximum URL download size in MB."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    started_at = utc_now_iso()
    paths = build_paths(home)
    ensure_layout(paths)
    init_db(paths)
    config = load_config(paths)
    scan_id = make_scan_id()
    workspace = create_workspace(paths, scan_id)
    warnings: list[str] = []
    sbom_path: Path | None = None
    components = []
    findings = []
    report_paths: dict[str, str] = {}
    status = "completed"
    error = None
    project_name = name or _guess_name(target)
    options = {
        "project_name": project_name,
        "type": type_,
        "skill_mode": skill_mode,
        "sbom": sbom,
        "vuln": vuln,
        "rules": rules,
        "license": license_scan,
        "report": report,
        "formats": _parse_csv(formats),
        "scanner": scanner,
        "fail_on": fail_on,
        "offline": offline,
    }

    try:
        prepared = prepare_target(
            target,
            paths=paths,
            workspace=workspace,
            max_download_size_mb=max_download_size,
            git_command=config["external_tools"].get("git", "git"),
        )
        warnings.extend(prepared.warnings)
        profile = detect_project(prepared.path, forced_type=type_, forced_skill_mode=skill_mode)
        warnings.extend(profile.warnings)
        context = ScanContext(
            scan_id=scan_id,
            target_dir=prepared.path,
            workspace=workspace,
            paths=paths,
            profile=profile,
            config=config,
            options=options,
            warnings=warnings,
        )
        enabled = _enabled_scanners(scanner)
        if sbom and _enabled("syft", enabled):
            components, sbom_path, syft_complete = generate_sbom(context)
            options["syft_complete"] = syft_complete
        if rules:
            if _enabled("skill-rules", enabled):
                findings.extend(scan_skill_rules(context))
            if _enabled("install-script-rules", enabled):
                findings.extend(scan_install_scripts(context))
            if _enabled("high-risk-api-rules", enabled):
                findings.extend(scan_high_risk_apis(context))
        if license_scan and _enabled("license", enabled):
            findings.extend(scan_licenses(context))
        if vuln:
            if _enabled("grype", enabled):
                findings.extend(scan_grype(context, sbom_path))
            if _enabled("pip-audit", enabled):
                findings.extend(scan_pip_audit(context))
            if _enabled("npm-audit", enabled):
                findings.extend(scan_npm_audit(context))
        findings = dedupe_findings(findings)
        summary = summarize_findings(components, findings)
        # Enrich SBOM with vulnerability findings so the CycloneDX document
        # becomes a standalone artifact containing both components and vulns.
        if sbom_path and sbom_path.exists():
            from sca_cli.scanners.syft import enrich_sbom_with_vulns  # noqa: PLC0415
            enrich_sbom_with_vulns(sbom_path, findings)
        finished_at = utc_now_iso()
        result = _result_dict(
            scan_id=scan_id,
            target=target,
            prepared_path=prepared.path,
            target_type=prepared.input_type,
            project_name=project_name,
            started_at=started_at,
            finished_at=finished_at,
            profile=profile.to_dict(),
            options=options,
            warnings=context.warnings,
            components=components,
            findings=findings,
            summary=summary,
            sbom_path=sbom_path,
            report_paths=report_paths,
        )
        if report:
            report_dir = output or (paths.reports / scan_id)
            report_paths = generate_scan_reports(result, report_dir, _parse_csv(formats))
            result["reports"] = report_paths
            if sbom_path and sbom_path.exists():
                shutil.copy2(sbom_path, report_dir / "sbom.cyclonedx.json")
                result["sbom"]["report_copy"] = str(report_dir / "sbom.cyclonedx.json")
            if workspace.raw_results.exists():
                raw_report_dir = report_dir / "raw"
                raw_report_dir.mkdir(parents=True, exist_ok=True)
                for raw_file in workspace.raw_results.glob("*"):
                    if raw_file.is_file():
                        shutil.copy2(raw_file, raw_report_dir / raw_file.name)
            if "json" in report_paths:
                write_json(Path(report_paths["json"]), result)
        with connect(paths.db) as connection:
            save_scan_result(
                connection,
                scan_id=scan_id,
                target=target,
                target_type=prepared.input_type,
                project_name=project_name,
                skill_type=profile.skill_mode,
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                options=options,
                summary=summary,
                components=components,
                findings=findings,
                sbom_path=sbom_path,
                report_paths=report_paths,
                error=error,
            )
        _print_scan_result(result, json_output=json_output)
        _fail_if_needed(summary, fail_on)
    except Exception as exc:
        status = "failed"
        error = str(exc)
        finished_at = utc_now_iso()
        summary = {"component_count": len(components), "finding_count": len(findings), "risk_score": 0, "risk_level": "unknown"}
        with connect(paths.db) as connection:
            save_scan_result(
                connection,
                scan_id=scan_id,
                target=target,
                target_type="unknown",
                project_name=project_name,
                skill_type="unknown",
                status=status,
                started_at=started_at,
                finished_at=finished_at,
                options=options,
                summary=summary,
                components=components,
                findings=findings,
                sbom_path=sbom_path,
                report_paths=report_paths,
                error=error,
            )
        if json_output:
            console.print(dumps({"status": status, "scan_id": scan_id, "error": error}))
        else:
            console.print(f"[red]Scan failed[/red]: {error}")
        raise typer.Exit(1) from exc


def _result_dict(**kwargs):
    return {
        "scan_id": kwargs["scan_id"],
        "target": {
            "origin": kwargs["target"],
            "prepared_path": str(kwargs["prepared_path"]),
            "type": kwargs["target_type"],
        },
        "project_name": kwargs["project_name"],
        "started_at": kwargs["started_at"],
        "finished_at": kwargs["finished_at"],
        "profile": kwargs["profile"],
        "options": kwargs["options"],
        "warnings": kwargs["warnings"],
        "summary": kwargs["summary"],
        "components": [component.to_dict() for component in kwargs["components"]],
        "findings": [finding.to_dict() for finding in kwargs["findings"]],
        "sbom": {"path": str(kwargs["sbom_path"]) if kwargs["sbom_path"] else None},
        "reports": kwargs["report_paths"],
    }


def _print_scan_result(result: dict, *, json_output: bool) -> None:
    if json_output:
        console.print(dumps(result))
        return
    summary = result["summary"]
    console.print(f"Scan completed: [bold]{result['project_name']}[/bold]")
    console.print(f"Scan ID: {result['scan_id']}")
    console.print(f"Type: {result['profile']['project_type']} / {result['profile']['skill_mode']}")
    table = Table(title="Summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Components", str(summary["component_count"]))
    table.add_row("Findings", str(summary["finding_count"]))
    table.add_row("Risk", f"{summary['risk_level'].upper()} ({summary['risk_score']})")
    for severity, count in summary["by_severity"].items():
        table.add_row(severity.title(), str(count))
    console.print(table)
    if result["warnings"]:
        console.print("[yellow]Warnings[/yellow]")
        for warning in result["warnings"]:
            console.print(f"  - {warning}")
    if result["reports"]:
        console.print("Reports:")
        for fmt, path in result["reports"].items():
            console.print(f"  {fmt}: {path}")


def _enabled_scanners(scanner: str) -> set[str] | None:
    value = scanner.strip().lower()
    if value in {"auto", "all", ""}:
        return None
    return set(_parse_csv(value))


def _enabled(name: str, enabled: set[str] | None) -> bool:
    return enabled is None or name in enabled


def _parse_csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def _guess_name(target: str) -> str:
    stripped = target.rstrip("/\\")
    name = Path(stripped).name
    return name or "scan-target"


def _fail_if_needed(summary: dict, fail_on: str) -> None:
    normalized = fail_on.lower()
    if normalized == "none":
        return
    threshold = SEVERITY_ORDER.get(normalized)
    if threshold is None:
        return
    for severity, count in summary["by_severity"].items():
        if count and SEVERITY_ORDER[severity] >= threshold:
            raise typer.Exit(2)
