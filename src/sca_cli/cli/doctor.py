from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sca_cli.core.config import load_config
from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.core.subprocess_runner import which
from sca_cli.db.repositories import list_sources
from sca_cli.db.session import connect, init_db
from sca_cli.utils.json import dumps

console = Console()


def doctor_command(
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    ensure_layout(paths)
    init_db(paths)
    config = load_config(paths)
    checks = []
    checks.append(_check("python", sys.version.split()[0], sys.version_info >= (3, 11), "Python 3.11+ required"))
    checks.append(_check("sqlite", sqlite3.sqlite_version, True, "SQLite available"))
    for key, label, required in [
        ("syft", "Syft", False),
        ("grype", "Grype", False),
        ("pip_audit", "pip-audit", False),
        ("npm", "npm", False),
        ("git", "git", False),
    ]:
        command = config["external_tools"].get(key, key)
        found = which(command)
        checks.append(_check(label, found or "not found", found is not None or not required, "optional external scanner"))
    checks.append(_check("data-home", str(paths.home), paths.home.exists(), "data directory exists"))
    checks.append(_check("database", str(paths.db), paths.db.exists(), "database initialized"))
    checks.append(_check("rules-dir", str(paths.rules), paths.rules.exists(), "rules directory exists"))
    with connect(paths.db) as connection:
        sources = list_sources(connection)
    result = {"status": "ok" if all(item["ok"] for item in checks) else "warning", "checks": checks, "sources": sources}
    if json_output:
        console.print(dumps(result))
        return
    table = Table(title="sca-cli doctor")
    table.add_column("Check")
    table.add_column("Value")
    table.add_column("Status")
    table.add_column("Notes")
    for item in checks:
        table.add_row(item["name"], item["value"], "OK" if item["ok"] else "WARN", item["message"])
    console.print(table)


def _check(name: str, value: str, ok: bool, message: str) -> dict[str, object]:
    return {"name": name, "value": value, "ok": ok, "message": message}
