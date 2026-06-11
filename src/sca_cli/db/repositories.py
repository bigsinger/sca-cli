from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from sca_cli.normalize.findings import Component, Finding
from sca_cli.utils.json import dumps
from sca_cli.utils.time import utc_now_iso


def save_scan_result(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    target: str,
    target_type: str,
    project_name: str,
    skill_type: str,
    status: str,
    started_at: str,
    finished_at: str,
    options: dict[str, Any],
    summary: dict[str, Any],
    components: list[Component],
    findings: list[Finding],
    sbom_path: Path | None,
    report_paths: dict[str, str],
    error: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO scan_jobs (
          scan_id, target, target_type, project_name, skill_type, status,
          started_at, finished_at, options_json, summary_json, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            target,
            target_type,
            project_name,
            skill_type,
            status,
            started_at,
            finished_at,
            dumps(options),
            dumps(summary),
            error,
        ),
    )
    now = utc_now_iso()
    connection.execute("DELETE FROM scan_components WHERE scan_id = ?", (scan_id,))
    for component in components:
        connection.execute(
            """
            INSERT INTO scan_components (
              scan_id, ecosystem, name, version, purl, type, evidence, source, licenses_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                component.ecosystem,
                component.name,
                component.version,
                component.purl,
                component.type,
                component.evidence,
                component.source,
                dumps(component.licenses),
                now,
            ),
        )
    connection.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
    for finding in findings:
        connection.execute(
            """
            INSERT OR IGNORE INTO scan_findings (
              scan_id, finding_id, category, severity, title, description,
              component_name, component_version, ecosystem, vuln_id, rule_id,
              file_path, line_number, evidence, remediation, source, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding.finding_id,
                finding.category,
                finding.severity,
                finding.title,
                finding.description,
                finding.component_name,
                finding.component_version,
                finding.ecosystem,
                finding.vuln_id,
                finding.rule_id,
                finding.file_path,
                finding.line_number,
                finding.evidence,
                finding.remediation,
                finding.source,
                dumps(finding.raw),
                now,
            ),
        )
    if sbom_path:
        connection.execute("DELETE FROM scan_sboms WHERE scan_id = ?", (scan_id,))
        connection.execute(
            """
            INSERT INTO scan_sboms (scan_id, format, path, component_count, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, "cyclonedx-json", str(sbom_path), len(components), now),
        )
    for fmt, path in report_paths.items():
        connection.execute(
            """
            INSERT INTO reports (scan_id, report_type, format, path, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, "scan", fmt, path, now),
        )
    connection.commit()


def update_source_status(
    connection: sqlite3.Connection,
    *,
    source_name: str,
    status: str,
    record_count: int = 0,
    error: str | None = None,
    full: bool = False,
) -> None:
    now = utc_now_iso()
    full_sync = now if full and status == "ok" else None
    connection.execute(
        """
        UPDATE sources
        SET status = ?,
            record_count = CASE WHEN ? > 0 THEN ? ELSE record_count END,
            last_error = ?,
            last_success_at = CASE WHEN ? = 'ok' THEN ? ELSE last_success_at END,
            last_full_sync_at = COALESCE(?, last_full_sync_at),
            last_incremental_sync_at = CASE WHEN ? = 'ok' AND ? = 0 THEN ? ELSE last_incremental_sync_at END,
            updated_at = ?
        WHERE name = ?
        """,
        (status, record_count, record_count, error, status, now, full_sync, status, int(full), now, now, source_name),
    )
    connection.commit()


def list_sources(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT name, type, url, enabled, status, last_success_at, last_error, record_count FROM sources ORDER BY name"
    ).fetchall()
    return [dict(row) for row in rows]


def db_status(connection: sqlite3.Connection) -> dict[str, Any]:
    tables = {}
    for name in [
        "sources",
        "vulnerabilities",
        "rules",
        "scan_jobs",
        "scan_components",
        "scan_findings",
        "reports",
        "intel_reports",
    ]:
        tables[name] = connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
    return {"tables": tables}
