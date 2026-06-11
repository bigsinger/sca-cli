from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import typer
from rich.console import Console

from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.db.session import connect, init_db
from sca_cli.reports.generator import generate_intel_reports
from sca_cli.utils.json import dumps
from sca_cli.utils.time import utc_now_iso

app = typer.Typer(help="Generate local threat intelligence reports.")
console = Console()


@app.command("report")
def report_command(
    range_: str = typer.Option("24h", "--range", help="Time range such as 24h or 7d."),
    from_date: str | None = typer.Option(None, "--from", help="Start date/time."),
    to_date: str | None = typer.Option(None, "--to", help="End date/time."),
    ecosystem: str | None = typer.Option(None, "--ecosystem", help="Comma-separated ecosystem filter."),
    severity: str | None = typer.Option(None, "--severity", help="Comma-separated severity filter."),
    focus: str = typer.Option("agent", "--focus", help="agent|ai|all"),
    formats: str = typer.Option("html,md,json", "--format", help="Comma-separated report formats."),
    output: Path | None = typer.Option(None, "--output", help="Report output directory."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    ensure_layout(paths)
    init_db(paths)
    start, end = _resolve_range(range_, from_date, to_date)
    ecosystems = _parse_csv(ecosystem) if ecosystem else []
    severities = _parse_csv(severity) if severity else []
    with connect(paths.db) as connection:
        vulnerabilities = _query_vulnerabilities(connection, start, end, ecosystems, severities)
    report_id = f"intel-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:8]}"
    summary = _summarize(vulnerabilities)
    result = {
        "report_id": report_id,
        "created_at": utc_now_iso(),
        "range": {"from": start, "to": end},
        "filters": {"ecosystem": ecosystems, "severity": severities, "focus": focus},
        "summary": summary,
        "vulnerabilities": vulnerabilities,
    }
    report_dir = output or (paths.reports / report_id)
    report_paths = generate_intel_reports(result, report_dir, _parse_csv(formats))
    result["reports"] = report_paths
    _save_intel_report(paths.db, result)
    if json_output:
        console.print(dumps(result))
    else:
        console.print("Threat intelligence report generated")
        console.print(f"Range: {start} to {end}")
        console.print(f"Vulnerabilities: {summary['total']}")
        for fmt, path in report_paths.items():
            console.print(f"  {fmt}: {path}")


def _resolve_range(range_: str, from_date: str | None, to_date: str | None) -> tuple[str, str]:
    end_dt = _parse_datetime(to_date) if to_date else datetime.now(timezone.utc)
    if from_date:
        start_dt = _parse_datetime(from_date)
    elif range_.endswith("h"):
        start_dt = end_dt - timedelta(hours=int(range_[:-1]))
    elif range_.endswith("d"):
        start_dt = end_dt - timedelta(days=int(range_[:-1]))
    else:
        start_dt = end_dt - timedelta(hours=24)
    return (
        start_dt.isoformat(timespec="seconds").replace("+00:00", "Z"),
        end_dt.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _query_vulnerabilities(connection: sqlite3.Connection, start: str, end: str, ecosystems: list[str], severities: list[str]) -> list[dict]:
    sql = """
        SELECT DISTINCT v.primary_id, v.title, v.description, v.severity, v.cvss_score,
               v.published_at, v.modified_at, v.source
        FROM vulnerabilities v
        LEFT JOIN affected_packages a ON a.vulnerability_id = v.id
        WHERE COALESCE(v.modified_at, v.published_at, v.updated_at) BETWEEN ? AND ?
    """
    params: list[object] = [start, end]
    if ecosystems:
        sql += f" AND lower(a.ecosystem) IN ({','.join('?' for _ in ecosystems)})"
        params.extend([item.lower() for item in ecosystems])
    if severities:
        sql += f" AND lower(v.severity) IN ({','.join('?' for _ in severities)})"
        params.extend([item.lower() for item in severities])
    sql += " ORDER BY CASE lower(v.severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC, v.modified_at DESC"
    return [dict(row) for row in connection.execute(sql, params).fetchall()]


def _summarize(vulnerabilities: list[dict]) -> dict:
    by_severity = {key: 0 for key in ["critical", "high", "medium", "low", "info"]}
    for vuln in vulnerabilities:
        severity = (vuln.get("severity") or "info").lower()
        by_severity[severity if severity in by_severity else "info"] += 1
    return {"total": len(vulnerabilities), "by_severity": by_severity}


def _save_intel_report(db_path: Path, result: dict) -> None:
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO intel_reports (report_id, range_from, range_to, filters_json, summary_json, path_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["report_id"],
                result["range"]["from"],
                result["range"]["to"],
                dumps(result["filters"]),
                dumps(result["summary"]),
                dumps(result["reports"]),
                result["created_at"],
            ),
        )
        connection.commit()


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]
