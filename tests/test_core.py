from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from sca_cli.core.extractor import UnsafeArchiveError, safe_extract_zip
from sca_cli.core.project_detect import detect_project
from sca_cli.scanners.syft import collect_lightweight_components


def test_zip_slip_is_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../evil.py", "print('bad')")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(archive, tmp_path / "out")


def test_detects_python_skill_fixture() -> None:
    root = Path("tests/fixtures/python_safe_skill")
    profile = detect_project(root)
    assert profile.project_type == "python"
    assert profile.skill_mode == "agent"
    assert profile.has_python is True


def test_lightweight_component_parser_reads_requirements() -> None:
    root = Path("tests/fixtures/python_safe_skill")
    components = collect_lightweight_components(root)
    assert any(item.name == "requests" and item.version == "2.31.0" for item in components)
