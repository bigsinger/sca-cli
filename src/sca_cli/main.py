from __future__ import annotations

import typer

from sca_cli import __version__
from sca_cli.cli.db import app as db_app
from sca_cli.cli.doctor import doctor_command
from sca_cli.cli.init import init_command
from sca_cli.cli.intel import app as intel_app
from sca_cli.cli.rules import app as rules_app
from sca_cli.cli.scan import scan_command
from sca_cli.cli.sync import sync_command

app = typer.Typer(no_args_is_help=True, help="Agent Skill supply-chain security scanner.")
app.command("version")(lambda: typer.echo(__version__))
app.command("init")(init_command)
app.command("doctor")(doctor_command)
app.command("scan")(scan_command)
app.command("sync")(sync_command)
app.add_typer(intel_app, name="intel")
app.add_typer(rules_app, name="rules")
app.add_typer(db_app, name="db")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
