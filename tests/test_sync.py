"""Tests for the sync module — source selection and severity conversion."""

from __future__ import annotations

import pytest

from sca_cli.cli.sync import (
    _cvss_score,
    _nvd_score,
    _select_sources,
    _severity_from_score,
)


# ── Source selection ─────────────────────────────────────────────────

class TestSelectSources:
    """_select_sources — determine which data sources to sync."""

    def test_all_sources_includes_enabled_and_grype(self) -> None:
        config = {"sync": {"enabled_sources": ["osv", "spdx"]}}
        selected = _select_sources(all_sources=True, source=None, config=config)
        assert "osv" in selected
        assert "spdx" in selected
        assert "grype-db" in selected

    def test_source_override_returns_parsed_list(self) -> None:
        config = {"sync": {"enabled_sources": ["osv"]}}
        selected = _select_sources(all_sources=False, source="spdx,nvd", config=config)
        assert selected == ["spdx", "nvd"]

    def test_source_override_with_spaces(self) -> None:
        config = {"sync": {"enabled_sources": []}}
        selected = _select_sources(all_sources=False, source=" osv , spdx ", config=config)
        assert selected == ["osv", "spdx"]

    def test_default_returns_enabled_sources(self) -> None:
        config = {"sync": {"enabled_sources": ["osv", "spdx"]}}
        selected = _select_sources(all_sources=False, source=None, config=config)
        assert selected == ["osv", "spdx"]

    def test_empty_enabled_sources(self) -> None:
        config = {"sync": {"enabled_sources": []}}
        selected = _select_sources(all_sources=False, source=None, config=config)
        assert selected == []

    def test_all_sources_with_empty_enabled(self) -> None:
        config = {"sync": {"enabled_sources": []}}
        selected = _select_sources(all_sources=True, source=None, config=config)
        # falls back to just grype-db when enabled_sources is empty
        assert selected == ["grype-db"]

    def test_source_override_preserves_duplicates(self) -> None:
        """_select_sources does NOT deduplicate; duplicates are passed through."""
        config = {"sync": {"enabled_sources": ["osv"]}}
        selected = _select_sources(all_sources=False, source="osv,osv,spdx", config=config)
        assert selected == ["osv", "osv", "spdx"]

    def test_all_sources_deduplicates(self) -> None:
        config = {"sync": {"enabled_sources": ["osv", "spdx", "osv"]}}
        selected = _select_sources(all_sources=True, source=None, config=config)
        # dict.fromkeys preserves order and deduplicates, then adds grype-db
        assert selected[-1] == "grype-db"
        assert "osv" in selected
        assert "spdx" in selected


# ── CVSS score extraction ────────────────────────────────────────────

class TestCvssScore:
    """_cvss_score — extract numeric score from a CVSS vector string."""

    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8", 8.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/7.5", 5.0),
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N/4.4", 4.0),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/0.0", 0.0),
            (None, None),
            ("", None),
            ("not-a-vector", None),
        ],
    )
    def test_extraction(self, vector: str | None, expected: float | None) -> None:
        assert _cvss_score(vector) == expected


# ── NVD score extraction ─────────────────────────────────────────────

class TestNvdScore:
    """_nvd_score — extract baseScore from NVD metrics dict."""

    def test_cvss_v31(self) -> None:
        metrics = {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/..."}}
            ]
        }
        assert _nvd_score(metrics) == 9.8

    def test_cvss_v30(self) -> None:
        metrics = {
            "cvssMetricV30": [
                {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/..."}}
            ]
        }
        assert _nvd_score(metrics) == 7.5

    def test_cvss_v2(self) -> None:
        metrics = {
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/..."}}
            ]
        }
        assert _nvd_score(metrics) == 5.0

    def test_empty_metrics(self) -> None:
        assert _nvd_score({}) is None

    def test_priority_v31_over_v30(self) -> None:
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}],
        }
        assert _nvd_score(metrics) == 9.8

    def test_priority_v30_over_v2(self) -> None:
        metrics = {
            "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        }
        assert _nvd_score(metrics) == 7.5


# ── Severity from score ──────────────────────────────────────────────

class TestSeverityFromScore:
    """_severity_from_score — map CVSS score to severity label."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (None, "info"),
            (0.0, "info"),
            (0.1, "low"),
            (3.9, "low"),
            (4.0, "medium"),
            (6.9, "medium"),
            (7.0, "high"),
            (8.9, "high"),
            (9.0, "critical"),
            (10.0, "critical"),
        ],
    )
    def test_conversion(self, score: float | None, expected: str) -> None:
        assert _severity_from_score(score) == expected
