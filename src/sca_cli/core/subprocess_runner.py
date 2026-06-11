from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


def which(name: str) -> str | None:
    return shutil.which(name)


def run_tool(command: list[str], *, cwd: Path | None = None, timeout_seconds: int = 300) -> ToolResult:
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout_seconds,
        shell=False,
    )
    return ToolResult(
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_seconds=time.monotonic() - started,
    )
