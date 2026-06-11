from __future__ import annotations

import gzip
import json
import shutil
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import httpx
import typer
import yaml
from rich.console import Console
from rich.table import Table

from sca_cli.core.config import load_config
from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.core.subprocess_runner import run_tool, which
from sca_cli.db.repositories import list_sources, update_source_status
from sca_cli.db.session import connect, init_db
from sca_cli.utils.json import dumps
from sca_cli.utils.time import utc_now_iso

console = Console()

OSV_ZIPS = {
    "pypi": "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm": "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
}
SPDX_LICENSES = "https://spdx.org/licenses/licenses.json"
NVD_MODIFIED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
GHSA_REPO = "https://github.com/github/advisory-database.git"
AIG_REPO = "https://github.com/Tencent/AI-Infra-Guard.git"


def sync_command(
    all_sources: bool = typer.Option(False, "--all", help="Synchronize all configured sources."),
    source: str | None = typer.Option(None, "--source", help="Comma-separated sources."),
    full: bool = typer.Option(False, "--full", help="Force a full refresh where supported."),
    since: str | None = typer.Option(None, "--since", help="Incremental start time hint."),
    offline_export: Path | None = typer.Option(None, "--offline-export", help="Export local DB/rules into a zip bundle."),
    offline_import: Path | None = typer.Option(None, "--offline-import", help="Import a previously exported bundle."),
    no_verify_tls: bool = typer.Option(False, "--no-verify-tls", help="Disable TLS verification for debugging."),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP proxy URL."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    ensure_layout(paths)
    init_db(paths)
    config = load_config(paths)
    results: list[dict[str, Any]] = []

    if offline_export:
        _offline_export(paths.home, offline_export)
        result = {"source": "offline-export", "status": "ok", "path": str(offline_export)}
        _print_results([result], json_output=json_output)
        return
    if offline_import:
        _offline_import(paths.home, offline_import)
        init_db(paths)
        result = {"source": "offline-import", "status": "ok", "path": str(offline_import)}
        _print_results([result], json_output=json_output)
        return

    selected = _select_sources(all_sources, source, config)
    verify = not no_verify_tls
    proxies = proxy or config["sync"].get("proxy")
    timeout = int(config["sync"].get("timeout_seconds") or 60)
    with connect(paths.db) as connection:
        for item in selected:
            started = utc_now_iso()
            try:
                if item == "spdx":
                    count = _sync_spdx(connection, verify=verify, proxy=proxies, timeout=timeout)
                elif item == "osv":
                    count = _sync_osv(connection, paths.cache, verify=verify, proxy=proxies, timeout=timeout)
                elif item == "nvd":
                    count = _sync_nvd(connection, paths.cache, verify=verify, proxy=proxies, timeout=timeout)
                elif item == "ghsa":
                    count = _sync_ghsa(connection, paths.cache, config)
                elif item == "aig":
                    count = _sync_aig(paths.cache, paths.rules, config)
                elif item == "grype-db":
                    count = _sync_grype_db(config)
                else:
                    raise ValueError(f"Unknown source: {item}")
                update_source_status(connection, source_name=item, status="ok", record_count=count, full=full or all_sources)
                _record_sync_run(connection, item, started, "ok", count, None)
                results.append({"source": item, "status": "ok", "records": count})
            except Exception as exc:
                message = str(exc)
                update_source_status(connection, source_name=item, status="failed", error=message, full=full)
                _record_sync_run(connection, item, started, "failed", 0, message)
                results.append({"source": item, "status": "failed", "error": message})
    _print_results(results, json_output=json_output)


def _select_sources(all_sources: bool, source: str | None, config: dict[str, Any]) -> list[str]:
    if all_sources:
        return list(dict.fromkeys(config["sync"].get("enabled_sources", []) + ["grype-db"]))
    if source:
        return [item.strip().lower() for item in source.split(",") if item.strip()]
    return list(config["sync"].get("enabled_sources", []))


def _http_get_bytes(url: str, *, verify: bool, proxy: str | None, timeout: int) -> bytes:
    transport = httpx.HTTPTransport(verify=verify)
    with httpx.Client(transport=transport, proxy=proxy, follow_redirects=True, timeout=timeout) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.content


def _sync_spdx(connection, *, verify: bool, proxy: str | None, timeout: int) -> int:
    data = json.loads(_http_get_bytes(SPDX_LICENSES, verify=verify, proxy=proxy, timeout=timeout).decode("utf-8"))
    now = utc_now_iso()
    count = 0
    for license_item in data.get("licenses") or []:
        connection.execute(
            """
            INSERT OR REPLACE INTO licenses (spdx_id, name, is_osi_approved, raw_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, COALESCE((SELECT created_at FROM licenses WHERE spdx_id = ?), ?), ?)
            """,
            (
                license_item.get("licenseId"),
                license_item.get("name"),
                int(bool(license_item.get("isOsiApproved"))),
                dumps(license_item),
                license_item.get("licenseId"),
                now,
                now,
            ),
        )
        count += 1
    connection.commit()
    return count


def _sync_osv(connection, cache: Path, *, verify: bool, proxy: str | None, timeout: int) -> int:
    cache.mkdir(parents=True, exist_ok=True)
    total = 0
    for ecosystem, url in OSV_ZIPS.items():
        archive = cache / f"osv-{ecosystem}.zip"
        archive.write_bytes(_http_get_bytes(url, verify=verify, proxy=proxy, timeout=timeout))
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                payload = json.loads(zf.read(name).decode("utf-8"))
                _upsert_vulnerability(connection, _normalize_osv(payload, ecosystem))
                total += 1
    connection.commit()
    return total


def _normalize_osv(payload: dict[str, Any], ecosystem_hint: str) -> dict[str, Any]:
    severity = None
    for item in payload.get("severity") or []:
        if item.get("type", "").lower().startswith("cvss"):
            severity = _severity_from_score(_cvss_score(item.get("score")))
            break
    return {
        "primary_id": payload.get("id"),
        "title": payload.get("summary") or payload.get("id"),
        "description": payload.get("details"),
        "severity": severity or "info",
        "published_at": payload.get("published"),
        "modified_at": payload.get("modified"),
        "source": "osv",
        "references_json": dumps(payload.get("references") or []),
        "raw_json": dumps(payload),
        "affected": [
            {
                "ecosystem": (pkg.get("package") or {}).get("ecosystem") or ecosystem_hint,
                "package_name": (pkg.get("package") or {}).get("name"),
                "purl": (pkg.get("package") or {}).get("purl"),
                "fixed_versions": _fixed_versions(pkg),
            }
            for pkg in payload.get("affected") or []
            if (pkg.get("package") or {}).get("name")
        ],
        "aliases": payload.get("aliases") or [],
    }


def _sync_nvd(connection, cache: Path, *, verify: bool, proxy: str | None, timeout: int) -> int:
    data = gzip.decompress(_http_get_bytes(NVD_MODIFIED, verify=verify, proxy=proxy, timeout=timeout))
    payload = json.loads(data.decode("utf-8"))
    total = 0
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        normalized = _normalize_nvd(cve)
        _upsert_vulnerability(connection, normalized)
        total += 1
    connection.commit()
    return total


def _normalize_nvd(cve: dict[str, Any]) -> dict[str, Any]:
    descriptions = cve.get("descriptions") or []
    title = next((item.get("value") for item in descriptions if item.get("lang") == "en"), cve.get("id"))
    score = _nvd_score(cve.get("metrics") or {})
    refs = [ref for group in (cve.get("references") or {}).get("referenceData", []) for ref in [group]]
    return {
        "primary_id": cve.get("id"),
        "title": title[:240] if title else cve.get("id"),
        "description": title,
        "severity": _severity_from_score(score),
        "cvss_score": score,
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
        "source": "nvd",
        "references_json": dumps(refs),
        "raw_json": dumps(cve),
        "affected": [],
        "aliases": [],
    }


def _sync_ghsa(connection, cache: Path, config: dict[str, Any]) -> int:
    git_cmd = config["external_tools"].get("git", "git")
    if which(git_cmd) is None:
        raise RuntimeError("git not found; cannot sync GHSA advisory database")
    repo = cache / "github-advisory-database"
    if repo.exists():
        run_tool([git_cmd, "-C", str(repo), "pull", "--ff-only"], timeout_seconds=600)
    else:
        run_tool([git_cmd, "clone", "--depth", "1", GHSA_REPO, str(repo)], timeout_seconds=900)
    total = 0
    for path in (repo / "advisories" / "github-reviewed").rglob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        _upsert_vulnerability(connection, _normalize_ghsa(payload))
        total += 1
    connection.commit()
    return total


def _normalize_ghsa(payload: dict[str, Any]) -> dict[str, Any]:
    affected = []
    for item in payload.get("affected") or []:
        package = item.get("package") or {}
        affected.append(
            {
                "ecosystem": package.get("ecosystem"),
                "package_name": package.get("name"),
                "purl": None,
                "fixed_versions": [event.get("fixed") for rng in item.get("ranges") or [] for event in rng.get("events") or [] if event.get("fixed")],
            }
        )
    aliases = [identifier.get("value") for identifier in payload.get("identifiers") or [] if identifier.get("value") != payload.get("id")]
    return {
        "primary_id": payload.get("id") or payload.get("ghsa_id"),
        "title": payload.get("summary"),
        "description": payload.get("details") or payload.get("description"),
        "severity": (payload.get("severity") or "info").lower(),
        "published_at": payload.get("published_at"),
        "modified_at": payload.get("updated_at") or payload.get("modified_at"),
        "source": "ghsa",
        "references_json": dumps(payload.get("references") or []),
        "raw_json": dumps(payload),
        "affected": [item for item in affected if item.get("package_name")],
        "aliases": aliases,
    }


def _sync_aig(cache: Path, rules_root: Path, config: dict[str, Any]) -> int:
    git_cmd = config["external_tools"].get("git", "git")
    if which(git_cmd) is None:
        raise RuntimeError("git not found; cannot sync AI-Infra-Guard rules")
    repo = cache / "ai-infra-guard"
    if repo.exists():
        result = run_tool([git_cmd, "-C", str(repo), "pull", "--ff-only"], timeout_seconds=600)
    else:
        result = run_tool([git_cmd, "clone", "--depth", "1", AIG_REPO, str(repo)], timeout_seconds=900)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    imported = 0
    destination = rules_root / "ai-infra"
    destination.mkdir(parents=True, exist_ok=True)
    for subdir in ["data/fingerprints", "data/vuln", "data/mcp"]:
        source_dir = repo / subdir
        if not source_dir.exists():
            continue
        for path in list(source_dir.rglob("*.yaml")) + list(source_dir.rglob("*.yml")) + list(source_dir.rglob("*.json")):
            rel = path.relative_to(source_dir)
            dest = destination / subdir.replace("/", "-") / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix.lower() in {".yaml", ".yml"}:
                yaml.safe_load(path.read_text(encoding="utf-8"))
            elif path.suffix.lower() == ".json":
                json.loads(path.read_text(encoding="utf-8"))
            shutil.copy2(path, dest)
            imported += 1
    return imported


def _sync_grype_db(config: dict[str, Any]) -> int:
    grype_cmd = config["external_tools"].get("grype", "grype")
    if which(grype_cmd) is None:
        raise RuntimeError("grype not found; cannot update Grype DB")
    result = run_tool([grype_cmd, "db", "update"], timeout_seconds=900)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return 1


def _upsert_vulnerability(connection, item: dict[str, Any]) -> None:
    if not item.get("primary_id"):
        return
    now = utc_now_iso()
    connection.execute(
        """
        INSERT OR REPLACE INTO vulnerabilities (
          primary_id, title, description, severity, cvss_score, cvss_vector, cwe,
          published_at, modified_at, source, references_json, remediation, raw_json,
          created_at, updated_at
        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          COALESCE((SELECT created_at FROM vulnerabilities WHERE primary_id = ?), ?), ?
        )
        """,
        (
            item.get("primary_id"),
            item.get("title"),
            item.get("description"),
            item.get("severity"),
            item.get("cvss_score"),
            item.get("cvss_vector"),
            item.get("cwe"),
            item.get("published_at"),
            item.get("modified_at"),
            item.get("source"),
            item.get("references_json"),
            item.get("remediation"),
            item.get("raw_json"),
            item.get("primary_id"),
            now,
            now,
        ),
    )
    vuln_id = connection.execute("SELECT id FROM vulnerabilities WHERE primary_id = ?", (item["primary_id"],)).fetchone()[0]
    old_affected = connection.execute("SELECT id FROM affected_packages WHERE vulnerability_id = ?", (vuln_id,)).fetchall()
    for row in old_affected:
        connection.execute("DELETE FROM affected_ranges WHERE affected_package_id = ?", (row[0],))
    connection.execute("DELETE FROM affected_packages WHERE vulnerability_id = ?", (vuln_id,))
    connection.execute("DELETE FROM vulnerability_aliases WHERE vulnerability_id = ?", (vuln_id,))
    for alias in item.get("aliases") or []:
        connection.execute(
            "INSERT OR IGNORE INTO vulnerability_aliases (vulnerability_id, alias, source) VALUES (?, ?, ?)",
            (vuln_id, alias, item.get("source")),
        )
    for affected in item.get("affected") or []:
        cursor = connection.execute(
            """
            INSERT INTO affected_packages (
              vulnerability_id, ecosystem, package_name, purl, fixed_versions_json, source, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vuln_id,
                str(affected.get("ecosystem") or "").lower(),
                affected.get("package_name"),
                affected.get("purl"),
                dumps(affected.get("fixed_versions") or []),
                item.get("source"),
                now,
                now,
            ),
        )
        connection.execute(
            "INSERT INTO affected_ranges (affected_package_id, fixed, created_at) VALUES (?, ?, ?)",
            (cursor.lastrowid, ",".join(affected.get("fixed_versions") or []), now),
        )


def _fixed_versions(pkg: dict[str, Any]) -> list[str]:
    versions = []
    for rng in pkg.get("ranges") or []:
        for event in rng.get("events") or []:
            if event.get("fixed"):
                versions.append(event["fixed"])
    return versions


def _cvss_score(vector: str | None) -> float | None:
    if not vector:
        return None
    match = None
    import re

    match = re.search(r"/?([0-9]+(?:\\.[0-9]+)?)$", vector)
    if match:
        return float(match.group(1))
    return None


def _nvd_score(metrics: dict[str, Any]) -> float | None:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {}).get("baseScore")
    return None


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _record_sync_run(connection, source: str, started: str, status: str, records: int, error: str | None) -> None:
    connection.execute(
        """
        INSERT INTO sync_runs (source_name, mode, status, started_at, finished_at, records_imported, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (source, "sync", status, started, utc_now_iso(), records, error),
    )
    connection.commit()


def _offline_export(home: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in [home / "sca-cli.db", home / "config.yaml"]:
            if path.exists():
                zf.write(path, path.relative_to(home).as_posix())
        rules_root = home / "rules"
        if rules_root.exists():
            for file in rules_root.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(home).as_posix())


def _offline_import(home: Path, bundle: Path) -> None:
    with TemporaryDirectory() as tmp:
        temp = Path(tmp)
        with zipfile.ZipFile(bundle) as zf:
            for info in zf.infolist():
                target = temp / info.filename
                if temp.resolve() not in target.resolve().parents and target.resolve() != temp.resolve():
                    raise RuntimeError(f"Unsafe offline bundle member: {info.filename}")
            zf.extractall(temp)
        for name in ["sca-cli.db", "config.yaml"]:
            src = temp / name
            if src.exists():
                dst = home / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                if dst.exists():
                    shutil.copy2(dst, dst.with_suffix(dst.suffix + ".bak"))
                shutil.copy2(src, dst)
        rules_src = temp / "rules"
        if rules_src.exists():
            for file in rules_src.rglob("*"):
                if file.is_file():
                    dest = home / file.relative_to(temp)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file, dest)


def _print_results(results: list[dict[str, Any]], *, json_output: bool) -> None:
    if json_output:
        console.print(dumps({"results": results}))
        return
    table = Table(title="sync results")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Records")
    table.add_column("Error")
    for item in results:
        table.add_row(item.get("source", ""), item.get("status", ""), str(item.get("records", "")), item.get("error", ""))
    console.print(table)
