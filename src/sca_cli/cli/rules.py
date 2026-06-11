from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from sca_cli.core.paths import build_paths
from sca_cli.rules.loader import load_rules, validate_rule_file
from sca_cli.utils.json import dumps

app = typer.Typer(help="List and validate rule files.")
console = Console()


@app.command("list")
def list_command(
    category: str | None = typer.Option(None, "--category", help="Filter by category."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    categories = {category} if category else None
    rules = load_rules(paths.rules, categories=categories)
    result = [asdict(rule) for rule in rules]
    if json_output:
        console.print(dumps(result))
        return
    table = Table(title="Rules")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Name")
    table.add_column("Source")
    for rule in rules:
        table.add_row(rule.rule_id, rule.severity, rule.category, rule.name, rule.source)
    console.print(table)


@app.command("validate")
def validate_command(
    path: Path | None = typer.Argument(None, help="Rule file or directory. Defaults to local rules directory."),
    home: Path | None = typer.Option(None, "--home", help="Application data directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    paths = build_paths(home)
    root = path or paths.rules
    files = [root] if root.is_file() else list(root.rglob("*.yml")) + list(root.rglob("*.yaml"))
    errors: list[str] = []
    for file in files:
        errors.extend(validate_rule_file(file))
    result = {"status": "ok" if not errors else "failed", "checked": len(files), "errors": errors}
    if json_output:
        console.print(dumps(result))
        return
    if errors:
        for error in errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)
    console.print(f"Validated {len(files)} rule files.")
