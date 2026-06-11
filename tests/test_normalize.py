"""Tests for findings normalization — dedup, risk scoring, severity ordering."""

from __future__ import annotations

import pytest

from sca_cli.normalize.findings import (
    SEVERITY_ORDER,
    Component,
    Finding,
    calculate_risk_score,
    dedupe_findings,
    highest_severity,
    make_finding_id,
    normalize_severity,
    risk_level,
    summarize_findings,
)


# ── Severity normalization ───────────────────────────────────────────

class TestNormalizeSeverity:
    """normalize_severity — map various inputs to canonical values."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("CRITICAL", "critical"),
            ("HIGH", "high"),
            ("Moderate", "medium"),
            ("moderate", "medium"),
            ("severe", "high"),
            ("Severe", "high"),
            (None, "info"),
            ("unknown", "info"),
            ("", "info"),
        ],
    )
    def test_normalization(self, raw: str | None, expected: str) -> None:
        assert normalize_severity(raw) == expected


class TestHighestSeverity:
    """highest_severity — return the most severe from a list."""

    def test_returns_highest(self) -> None:
        assert highest_severity(["low", "high", "medium"]) == "high"

    def test_empty_list_defaults_to_info(self) -> None:
        assert highest_severity([]) == "info"

    def test_single_value(self) -> None:
        assert highest_severity(["critical"]) == "critical"


# ── Finding creation ─────────────────────────────────────────────────

class TestFindingCreation:
    """Finding dataclass and auto-ID generation."""

    def test_minimal_finding(self) -> None:
        finding = Finding(category="vulnerability", severity="high", title="SQL Injection")
        assert finding.category == "vulnerability"
        assert finding.severity == "high"
        assert finding.finding_id is not None
        assert len(finding.finding_id) == 24

    def test_severity_is_normalized_on_init(self) -> None:
        finding = Finding(category="vuln", severity="CRITICAL", title="Test")
        assert finding.severity == "critical"

    def test_finding_to_dict(self) -> None:
        finding = Finding(
            category="vulnerability",
            severity="high",
            title="Test",
            component_name="requests",
            component_version="2.31.0",
            vuln_id="CVE-2023-1234",
        )
        d = finding.to_dict()
        assert d["category"] == "vulnerability"
        assert d["component_name"] == "requests"
        assert d["vuln_id"] == "CVE-2023-1234"

    def test_make_finding_id_is_stable(self) -> None:
        finding = Finding(category="vuln", severity="low", title="Test")
        id1 = make_finding_id(finding)
        id2 = make_finding_id(finding)
        assert id1 == id2

    def test_make_finding_id_from_dict(self) -> None:
        ident = make_finding_id({"category": "test", "rule": "R-001"})
        assert isinstance(ident, str)
        assert len(ident) == 24


# ── Deduplication ────────────────────────────────────────────────────

class TestDedupeFindings:
    """dedupe_findings — merge findings with the same dedupe_key."""

    def test_exact_duplicates_are_merged(self) -> None:
        f1 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2023-1234",
            component_name="requests",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2023-1234",
        )
        f2 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2023-1234",
            component_name="requests",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2023-1234",
        )
        deduped = dedupe_findings([f1, f2])
        assert len(deduped) == 1

    def test_higher_severity_wins_on_merge(self) -> None:
        low = Finding(
            category="vulnerability",
            severity="low",
            title="CVE-2024-5678",
            component_name="flask",
            component_version="1.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-5678",
        )
        high = Finding(
            category="vulnerability",
            severity="critical",
            title="CVE-2024-5678",
            component_name="flask",
            component_version="1.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-5678",
        )
        deduped = dedupe_findings([low, high])
        assert len(deduped) == 1
        assert deduped[0].severity == "critical"

    def test_different_vuln_ids_are_separate(self) -> None:
        f1 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2024-0001",
            component_name="requests",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-0001",
        )
        f2 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2024-0002",
            component_name="requests",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-0002",
        )
        assert len(dedupe_findings([f1, f2])) == 2

    def test_different_packages_are_separate(self) -> None:
        f1 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2024-0001",
            component_name="requests",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-0001",
        )
        f2 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE-2024-0001",
            component_name="flask",
            component_version="2.31.0",
            ecosystem="pypi",
            vuln_id="CVE-2024-0001",
        )
        assert len(dedupe_findings([f1, f2])) == 2

    def test_rule_findings_dedup_by_rule_id_and_file(self) -> None:
        f1 = Finding(
            category="code_scan",
            severity="high",
            title="Dangerous Call",
            rule_id="RULE-001",
            file_path="src/main.py",
            line_number=10,
            evidence="dangerous()",
        )
        f2 = Finding(
            category="code_scan",
            severity="high",
            title="Dangerous Call",
            rule_id="RULE-001",
            file_path="src/main.py",
            line_number=10,
            evidence="dangerous()",
        )
        assert len(dedupe_findings([f1, f2])) == 1

    def test_rule_findings_different_files_are_separate(self) -> None:
        f1 = Finding(
            category="code_scan",
            severity="high",
            title="Dangerous Call",
            rule_id="RULE-001",
            file_path="src/main.py",
            line_number=10,
        )
        f2 = Finding(
            category="code_scan",
            severity="high",
            title="Dangerous Call",
            rule_id="RULE-001",
            file_path="src/utils.py",
            line_number=10,
        )
        assert len(dedupe_findings([f1, f2])) == 2

    def test_sources_are_merged(self) -> None:
        f1 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE",
            component_name="pkg",
            component_version="1.0",
            ecosystem="pypi",
            vuln_id="CVE-001",
            source="grype",
        )
        f2 = Finding(
            category="vulnerability",
            severity="high",
            title="CVE",
            component_name="pkg",
            component_version="1.0",
            ecosystem="pypi",
            vuln_id="CVE-001",
            source="pip-audit",
        )
        deduped = dedupe_findings([f1, f2])
        assert len(deduped) == 1
        assert "grype" in deduped[0].source
        assert "pip-audit" in deduped[0].source

    def test_empty_list(self) -> None:
        assert dedupe_findings([]) == []

    def test_sorted_by_severity_desc(self) -> None:
        findings = [
            Finding(category="vuln", severity="low", title="Low", component_name="a", component_version="1", ecosystem="pypi", vuln_id="CVE-LOW"),
            Finding(category="vuln", severity="critical", title="Critical", component_name="b", component_version="1", ecosystem="pypi", vuln_id="CVE-CRIT"),
            Finding(category="vuln", severity="high", title="High", component_name="c", component_version="1", ecosystem="pypi", vuln_id="CVE-HIGH"),
        ]
        deduped = dedupe_findings(findings)
        severities = [f.severity for f in deduped]
        assert severities == ["critical", "high", "low"]


# ── Risk score calculation ───────────────────────────────────────────

class TestCalculateRiskScore:
    """calculate_risk_score — compute cumulative risk."""

    def test_no_findings_score_0(self) -> None:
        assert calculate_risk_score([]) == 0

    def test_base_severity_score(self) -> None:
        findings = [Finding(category="vuln", severity="critical", title="Test")]
        assert calculate_risk_score(findings) == 100  # SEVERITY_SCORE["critical"]

    def test_install_script_penalty(self) -> None:
        findings = [Finding(category="install_script", severity="low", title="Script")]
        score = calculate_risk_score(findings)
        assert score >= 20  # base + install_script bonus

    def test_known_rule_id_penalty(self) -> None:
        findings = [
            Finding(
                category="mcp_tool",
                severity="high",
                title="MCP Tool",
                rule_id="MCP-TOOL-004",
            )
        ]
        score = calculate_risk_score(findings)
        # high (80) + MCP-TOOL-004 bonus (25) = 105, capped at 100
        assert score == 100

    def test_prompt_injection_penalty(self) -> None:
        findings = [
            Finding(
                category="code_scan",
                severity="medium",
                title="Prompt Injection Detected",
                evidence="ignore previous instructions",
            )
        ]
        score = calculate_risk_score(findings)
        assert "prompt injection" in findings[0].title.lower()
        assert score >= 50 + 15

    def test_vulnerability_ecosystem_penalty(self) -> None:
        findings = [
            Finding(
                category="vulnerability",
                severity="high",
                title="CVE",
                ecosystem="pypi",
                component_name="x",
                component_version="1",
                vuln_id="CVE-001",
            )
        ]
        score = calculate_risk_score(findings)
        assert score >= 80 + 10  # severity base + ecosystem bonus

    def test_multiple_sources_penalty(self) -> None:
        findings = [
            Finding(
                category="vulnerability",
                severity="high",
                title="CVE",
                ecosystem="pypi",
                component_name="x",
                component_version="1",
                vuln_id="CVE-001",
                source="grype,pip-audit",
            )
        ]
        score = calculate_risk_score(findings)
        assert score >= 80 + 10 + 5  # base + ecosystem + multi-source

    def test_score_capped_at_100(self) -> None:
        many = [
            Finding(
                category="install_script",
                severity="critical",
                title="Bad",
                rule_id="MCP-TOOL-004",
                evidence="ignore previous instructions",
            )
        ]
        score = calculate_risk_score(many)
        assert score <= 100


# ── Risk level ───────────────────────────────────────────────────────

class TestRiskLevel:
    """risk_level — map numeric score to label."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, "low"),
            (15, "low"),
            (30, "low"),
            (31, "medium"),
            (60, "medium"),
            (61, "high"),
            (85, "high"),
            (86, "critical"),
            (100, "critical"),
        ],
    )
    def test_levels(self, score: int, expected: str) -> None:
        assert risk_level(score) == expected


# ── Summarize findings ───────────────────────────────────────────────

class TestSummarizeFindings:
    """summarize_findings — aggregate counts and risk."""

    def test_basic_summary(self) -> None:
        components = [Component(ecosystem="pypi", name="requests", version="2.31.0")]
        findings = [
            Finding(category="vulnerability", severity="critical", title="Bad"),
            Finding(category="code_scan", severity="low", title="Note"),
        ]
        summary = summarize_findings(components, findings)
        assert summary["component_count"] == 1
        assert summary["finding_count"] == 2
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["low"] == 1
        assert summary["by_category"]["vulnerability"] == 1
        assert summary["by_category"]["code_scan"] == 1
        assert isinstance(summary["risk_score"], int)
        assert isinstance(summary["risk_level"], str)

    def test_empty_findings(self) -> None:
        summary = summarize_findings([], [])
        assert summary["finding_count"] == 0
        assert summary["risk_score"] == 0


# ── Component ────────────────────────────────────────────────────────

class TestComponent:
    """Component dataclass."""

    def test_minimal_component(self) -> None:
        c = Component(ecosystem="pypi", name="requests")
        assert c.name == "requests"
        assert c.version is None

    def test_component_to_dict(self) -> None:
        c = Component(ecosystem="npm", name="lodash", version="4.17.21")
        d = c.to_dict()
        assert d["ecosystem"] == "npm"
        assert d["name"] == "lodash"
        assert d["version"] == "4.17.21"


# ── SEVERITY_ORDER ───────────────────────────────────────────────────

class TestSeverityOrder:
    """SEVERITY_ORDER dict correctness."""

    def test_ordering(self) -> None:
        assert SEVERITY_ORDER["info"] < SEVERITY_ORDER["low"]
        assert SEVERITY_ORDER["low"] < SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["medium"] < SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["high"] < SEVERITY_ORDER["critical"]
