from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.db.repositories import db_status, list_sources
from sca_cli.db.session import connect, init_db
from sca_cli.utils.json import dumps

app = typer.Typer(help="Inspect and maintain local SQLite database.")
console = Console()


@app.command("status")
def status_command(
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    ensure_layout(paths)
    init_db(paths)
    with connect(paths.db) as connection:
        result = {"database": str(paths.db), **db_status(connection), "sources": list_sources(connection)}
    if json_output:
        console.print(dumps(result))
        return
    table = Table(title=f"Database: {paths.db}")
    table.add_column("Table")
    table.add_column("Rows")
    for name, count in result["tables"].items():
        table.add_row(name, str(count))
    console.print(table)


@app.command("reset")
def reset_command(
    force: bool = typer.Option(False, "--force", help="Reset without interactive confirmation."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    if paths.db.exists() and not force:
        confirmed = typer.confirm(f"Delete database {paths.db}?")
        if not confirmed:
            raise typer.Exit(1)
    paths.db.unlink(missing_ok=True)
    init_db(paths)
    result = {"status": "ok", "database": str(paths.db)}
    if json_output:
        console.print(dumps(result))
    else:
        console.print(f"Database reset: {paths.db}")
