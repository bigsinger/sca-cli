from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from sca_cli.core.config import write_default_config
from sca_cli.core.paths import build_paths, ensure_layout
from sca_cli.db.session import init_db
from sca_cli.utils.json import dumps

console = Console()


def init_command(
    force: bool = typer.Option(False, "--force", help="Overwrite config.yaml if it already exists."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    ensure_layout(paths)
    write_default_config(paths, force=force)
    init_db(paths)
    result = {
        "status": "ok",
        "home": str(paths.home),
        "config": str(paths.config),
        "database": str(paths.db),
    }
    if json_output:
        console.print(dumps(result))
    else:
        console.print(f"Initialized sca-cli data directory: [bold]{paths.home}[/bold]")
        console.print(f"Config: {paths.config}")
        console.print(f"Database: {paths.db}")
