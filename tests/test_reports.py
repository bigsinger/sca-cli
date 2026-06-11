"""Tests for report generation — JSON, Markdown, and HTML output."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sca_cli.reports.generator import generate_intel_reports, generate_scan_reports


# ── Helpers ──────────────────────────────────────────────────────────

def _sample_result(**overrides: dict) -> dict:
    """Return a minimal valid scan result dict."""
    result = {
        "scan_id": "test-scan-001",
        "target": {
            "origin": "tests/fixtures/python_safe_skill",
            "prepared_path": "/tmp/test",
            "type": "directory",
        },
        "project_name": "test-project",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z",
        "profile": {
            "project_type": "python",
            "skill_mode": "agent",
            "features": [],
            "manifests": [],
            "warnings": [],
            "has_python": True,
            "has_javascript": False,
            "has_mcp": False,
            "has_plugin": False,
            "has_agent_skill": False,
            "has_lockfile": False,
        },
        "options": {"project_name": "test-project", "sbom": False},
        "warnings": ["Test warning"],
        "summary": {
            "component_count": 2,
            "finding_count": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "by_category": {"code_scan": 1},
            "risk_score": 80,
            "risk_level": "high",
        },
        "components": [
            {"ecosystem": "pypi", "name": "requests", "version": "2.31.0", "type": "library"},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.21", "type": "library"},
        ],
        "findings": [
            {
                "category": "code_scan",
                "severity": "high",
                "title": "Dangerous Call",
                "description": "Found dangerous call",
                "component_name": None,
                "component_version": None,
                "ecosystem": None,
                "vuln_id": None,
                "rule_id": "PY-HIGHAPI-001",
                "file_path": "server.py",
                "line_number": 15,
                "evidence": "dangerous_call()",
                "remediation": "Remove dangerous call",
                "source": "rule",
                "raw": {"confidence": "high"},
                "finding_id": "abc123",
            }
        ],
        "sbom": {"path": "/tmp/sbom.json"},
        "reports": {},
    }
    result.update(overrides)
    return result


# ── JSON report ──────────────────────────────────────────────────────

class TestJsonReport:
    """JSON report generation."""

    def test_json_report_created(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["json"])
        assert "json" in paths
        report_path = Path(paths["json"])
        assert report_path.exists()
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "test-scan-001"
        assert data["project_name"] == "test-project"
        assert len(data["components"]) == 2
        assert len(data["findings"]) == 1

    def test_json_report_content(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["json"])
        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        assert data["summary"]["risk_score"] == 80
        assert data["summary"]["risk_level"] == "high"

    def test_json_report_empty_findings(self, tmp_path: Path) -> None:
        result = _sample_result()
        result["findings"] = []
        result["summary"]["finding_count"] = 0
        result["summary"]["by_severity"]["high"] = 0
        result["summary"]["risk_score"] = 0
        result["summary"]["risk_level"] = "low"
        paths = generate_scan_reports(result, tmp_path, ["json"])
        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        assert data["summary"]["finding_count"] == 0
        assert data["summary"]["risk_score"] == 0


# ── Markdown report ──────────────────────────────────────────────────

class TestMarkdownReport:
    """Markdown report generation."""

    def test_md_report_created(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["md"])
        assert "md" in paths
        report_path = Path(paths["md"])
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        # The template uses scan_id and summary info
        assert "test-scan-001" in content
        assert "high" in content.lower()

    def test_md_report_with_markdown_alias(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["markdown"])
        assert "md" in paths
        assert Path(paths["md"]).exists()

    def test_md_report_contains_findings(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["md"])
        content = Path(paths["md"]).read_text(encoding="utf-8")
        assert "Dangerous Call" in content
        assert "high" in content.lower()


# ── HTML report ──────────────────────────────────────────────────────

class TestHtmlReport:
    """HTML report generation."""

    def test_html_report_created(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["html"])
        assert "html" in paths
        report_path = Path(paths["html"])
        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "<html" in content.lower() or "<!doctype html" in content.lower()

    def test_html_report_contains_styles(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["html"])
        content = Path(paths["html"]).read_text(encoding="utf-8")
        # Should contain some CSS (from report.css)
        assert "style" in content.lower() or "css" in content.lower()

    def test_html_report_contains_summary(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["html"])
        content = Path(paths["html"]).read_text(encoding="utf-8")
        assert "test-scan-001" in content
        assert "high" in content.lower()


# ── Multi-format ─────────────────────────────────────────────────────

class TestMultiFormat:
    """Generating multiple report formats at once."""

    def test_generates_all_formats(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, ["json", "md", "html"])
        assert "json" in paths
        assert "md" in paths
        assert "html" in paths
        assert Path(paths["json"]).exists()
        assert Path(paths["md"]).exists()
        assert Path(paths["html"]).exists()

    def test_output_dir_created(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "reports"
        result = _sample_result()
        paths = generate_scan_reports(result, nested, ["json"])
        assert Path(paths["json"]).exists()

    def test_empty_formats_list(self, tmp_path: Path) -> None:
        result = _sample_result()
        paths = generate_scan_reports(result, tmp_path, [])
        assert paths == {}


# ── Intel report ─────────────────────────────────────────────────────

class TestIntelReports:
    """generate_intel_reports — similar to scan reports but different templates."""

    def test_intel_json_created(self, tmp_path: Path) -> None:
        result = {
            "intel_data": [{"key": "value"}],
            "summary": {"items": 1, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
            "range": {"from": "2026-01-01", "to": "2026-01-02"},
        }
        paths = generate_intel_reports(result, tmp_path, ["json"])
        assert "json" in paths
        data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        assert data["intel_data"] == [{"key": "value"}]

    def test_intel_md_created(self, tmp_path: Path) -> None:
        result = {
            "intel_data": [],
            "summary": {"items": 0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
            "range": {"from": "2026-01-01", "to": "2026-01-02"},
        }
        paths = generate_intel_reports(result, tmp_path, ["md"])
        assert "md" in paths
        assert Path(paths["md"]).exists()

    def test_intel_html_created(self, tmp_path: Path) -> None:
        result = {
            "intel_data": [],
            "summary": {"items": 0, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
            "range": {"from": "2026-01-01", "to": "2026-01-02"},
        }
        paths = generate_intel_reports(result, tmp_path, ["html"])
        assert "html" in paths
        assert Path(paths["html"]).exists()


# ── Edge cases ───────────────────────────────────────────────────────

class TestEdgeCases:
    """Error handling and edge cases in report generation."""

    def test_handles_missing_keys_in_result(self, tmp_path: Path) -> None:
        """Should not crash when optional result keys are missing."""
        result = _sample_result()
        result.pop("warnings", None)
        # This should still work — templates handle missing keys gracefully
        paths = generate_scan_reports(result, tmp_path, ["json"])
        assert "json" in paths

    def test_handles_empty_components(self, tmp_path: Path) -> None:
        result = _sample_result()
        result["components"] = []
        result["summary"]["component_count"] = 0
        paths = generate_scan_reports(result, tmp_path, ["json", "md"])
        assert "json" in paths
        assert "md" in paths
