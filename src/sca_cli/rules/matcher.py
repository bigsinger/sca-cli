from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from sca_cli.core.project_detect import SKIP_DIRS
from sca_cli.rules.loader import Rule


def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)


def matches_glob(relative_path: str, patterns: list[str]) -> bool:
    normalized = relative_path.replace("\\", "/")
    basename = Path(normalized).name
    for pattern in patterns:
        variants = [pattern]
        if pattern.startswith("**/"):
            variants.append(pattern[3:])
        for variant in variants:
            if fnmatch.fnmatch(normalized, variant) or fnmatch.fnmatch(basename, variant):
                return True
    return False


def iter_text_files(root: Path, *, max_size_bytes: int = 512 * 1024) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if should_skip(path):
            continue
        if path.is_file() and path.stat().st_size <= max_size_bytes:
            files.append(path)
    return files


def match_rule_on_text(rule: Rule, text: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for pattern in rule.patterns:
            if re.search(pattern, line, flags=re.IGNORECASE):
                hits.append((line_number, line.strip()[:500]))
                break
    return hits
