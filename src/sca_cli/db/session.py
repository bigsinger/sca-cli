from __future__ import annotations

import sqlite3
from pathlib import Path

from sca_cli.core.paths import AppPaths, ensure_layout
from sca_cli.db.migrations import initialize_database


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def init_db(paths: AppPaths) -> None:
    ensure_layout(paths)
    with connect(paths.db) as connection:
        initialize_database(connection)
