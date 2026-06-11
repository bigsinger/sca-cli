"""Tests for the rules engine — loading, matching, and scanning."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sca_cli.rules.engine import RuleEngine
from sca_cli.rules.loader import (
    Rule,
    _parse_rules,
    load_builtin_rules,
    load_external_rules,
    load_rules,
    validate_rule_file,
)
from sca_cli.rules.matcher import iter_text_files, match_rule_on_text, matches_glob


# ── Rule data class ──────────────────────────────────────────────────

class TestRuleDataclass:
    """Rule construction and default values."""

    def test_minimal_rule(self) -> None:
        rule = Rule(
            rule_id="TEST-001",
            name="Test Rule",
            category="test",
            severity="high",
            globs=["**/*.py"],
            patterns=["danger"],
        )
        assert rule.rule_id == "TEST-001"
        assert rule.globs == ["**/*.py"]
        assert rule.patterns == ["danger"]
        assert rule.source == "builtin"  # default
        assert rule.confidence == "medium"  # default

    def test_severity_is_lowered_by_parser(self) -> None:
        """_parse_rules lowercases severity, but Rule dataclass itself does not."""
        data = {
            "rules": [
                {
                    "id": "TEST-002",
                    "name": "Case Test",
                    "category": "test",
                    "severity": "HIGH",
                    "globs": [],
                    "patterns": [],
                }
            ]
        }
        rules = _parse_rules(data, source="test")
        assert rules[0].severity == "high"


# ── YAML rule loading ────────────────────────────────────────────────

class TestYamlLoading:
    """loading rules from YAML content and built-in files."""

    def test_parse_rules_from_dict(self) -> None:
        data = {
            "rules": [
                {
                    "id": "CUSTOM-001",
                    "name": "Custom Rule",
                    "category": "security",
                    "severity": "critical",
                    "globs": ["**/*.py"],
                    "patterns": ["eval\\s*\\("],
                    "description": "Detects eval usage",
                    "remediation": "Remove eval",
                }
            ]
        }
        rules = _parse_rules(data, source="test")
        assert len(rules) == 1
        assert rules[0].rule_id == "CUSTOM-001"
        assert rules[0].severity == "critical"
        assert rules[0].patterns == ["eval\\s*\\("]

    def test_parse_rules_empty(self) -> None:
        assert _parse_rules({}, source="empty") == []
        assert _parse_rules({"rules": []}, source="empty") == []

    def test_parse_preserves_metadata(self) -> None:
        data = {
            "rules": [
                {
                    "id": "META-001",
                    "name": "With Metadata",
                    "category": "test",
                    "severity": "low",
                    "globs": ["*"],
                    "patterns": ["foo"],
                    "confidence": "high",
                    "source": "community",
                    "extra_field": "kept",
                }
            ]
        }
        rules = _parse_rules(data, source="meta")
        assert len(rules) == 1
        assert rules[0].confidence == "high"
        assert rules[0].metadata.get("extra_field") == "kept"
        # source param is overwritten by positional arg
        assert rules[0].source == "meta"

    def test_load_builtin_rules_returns_list(self) -> None:
        """Built-in rule files (*.yml) are loaded from sca_cli.rules_builtin."""
        rules = load_builtin_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0
        # Spot-check known rule IDs
        ids = {r.rule_id for r in rules}
        assert "MCP-TOOL-001" in ids
        assert "SKILL-META-001" in ids
        assert "PY-INSTALL-001" in ids
        assert "JS-INSTALL-001" in ids

    def test_load_external_rules_from_yaml(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "my_rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "custom.yml"
        rule_file.write_text(
            yaml.dump({
                "rules": [
                    {
                        "id": "EXT-001",
                        "name": "External Rule",
                        "category": "external",
                        "severity": "medium",
                        "globs": ["**/*.py"],
                        "patterns": ["secret"],
                    }
                ]
            })
        )
        rules = load_external_rules(rules_dir)
        assert len(rules) == 1
        assert rules[0].rule_id == "EXT-001"

    def test_load_external_rules_nonexistent_dir(self) -> None:
        rules = load_external_rules(Path("/nonexistent/path"))
        assert rules == []

    def test_load_rules_combines_builtin_and_external(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ext.yml").write_text(
            yaml.dump({
                "rules": [
                    {
                        "id": "EXT-002",
                        "name": "Extra",
                        "category": "extra",
                        "severity": "low",
                        "globs": ["*"],
                        "patterns": ["test"],
                    }
                ]
            })
        )
        rules = load_rules(rules_dir)
        ids = {r.rule_id for r in rules}
        assert "EXT-002" in ids
        assert "MCP-TOOL-001" in ids  # builtin is still there

    def test_load_rules_filters_by_category(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "cat.yml").write_text(
            yaml.dump({
                "rules": [
                    {
                        "id": "CAT-A",
                        "name": "Category A",
                        "category": "a_rules",
                        "severity": "high",
                        "globs": ["*"],
                        "patterns": ["find"],
                    },
                    {
                        "id": "CAT-B",
                        "name": "Category B",
                        "category": "b_rules",
                        "severity": "low",
                        "globs": ["*"],
                        "patterns": ["skip"],
                    },
                ]
            })
        )
        rules = load_rules(rules_dir, categories={"a_rules"})
        ids = {r.rule_id for r in rules}
        assert "CAT-A" in ids
        assert "CAT-B" not in ids


# ── Rule file validation ─────────────────────────────────────────────

class TestValidateRuleFile:
    """validate_rule_file checks required fields."""

    def test_valid_file_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "valid.yml"
        path.write_text(
            yaml.dump({
                "rules": [
                    {
                        "id": "V-001",
                        "name": "Valid",
                        "category": "test",
                        "severity": "high",
                        "globs": ["*"],
                        "patterns": ["foo"],
                    }
                ]
            })
        )
        assert validate_rule_file(path) == []

    def test_missing_id_is_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yml"
        path.write_text(
            yaml.dump({
                "rules": [
                    {
                        "name": "No ID",
                        "category": "test",
                        "severity": "high",
                        "globs": ["*"],
                        "patterns": ["foo"],
                    }
                ]
            })
        )
        errors = validate_rule_file(path)
        assert len(errors) == 1
        assert "missing id" in errors[0].lower()

    def test_invalid_yaml_returns_parse_error(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.yml"
        path.write_text("rules:\n  - id: broken\n    name: Broken\n    category: test\n    severity: high\n    globs: not_a_list\n    patterns: also_not_a_list\n")
        errors = validate_rule_file(path)
        assert len(errors) >= 1  # globs not a list + patterns not a list

    def test_nonexistent_file(self) -> None:
        errors = validate_rule_file(Path("/nonexistent/rule.yml"))
        assert len(errors) == 1
        assert "YAML parse failed" in errors[0]


# ── Glob matching ────────────────────────────────────────────────────

class TestGlobMatching:
    """matches_glob utility."""

    @pytest.mark.parametrize(
        ("path_str", "patterns", "expected"),
        [
            ("src/main.py", ["**/*.py"], True),
            ("src/main.py", ["*.py"], True),  # basename match fallback via fnmatch
            ("src/main.py", ["**/*.js"], False),
            ("data/file.json", ["**/*.json", "**/*.yaml"], True),
            ("webroot/index.html", ["**/*.html"], True),
            ("some/deep/path/test.py", ["**/test.py"], True),
        ],
    )
    def test_glob_matches(self, path_str: str, patterns: list[str], expected: bool) -> None:
        assert matches_glob(path_str, patterns) is expected


# ── Rule matching on text ────────────────────────────────────────────

class TestMatchRuleOnText:
    """match_rule_on_text — apply regex patterns to file content."""

    def test_simple_pattern_match(self) -> None:
        rule = Rule(
            rule_id="TEST",
            name="Test",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["dangerous"],
        )
        text = "line1\nthis is dangerous\nline3"
        hits = match_rule_on_text(rule, text)
        assert len(hits) == 1
        assert hits[0][0] == 2  # line number
        assert "dangerous" in hits[0][1]

    def test_multiple_matches(self) -> None:
        rule = Rule(
            rule_id="TEST",
            name="Test",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["eval"],
        )
        text = "eval(a)\nsafe\nx = eval(b)"
        hits = match_rule_on_text(rule, text)
        assert len(hits) == 2

    def test_no_match(self) -> None:
        rule = Rule(
            rule_id="TEST",
            name="Test",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["forbidden"],
        )
        text = "everything is fine"
        assert match_rule_on_text(rule, text) == []

    def test_regex_pattern(self) -> None:
        rule = Rule(
            rule_id="TEST",
            name="Regex test",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["secret\\s*="],
        )
        text = "api_secret = 'abc123'"
        hits = match_rule_on_text(rule, text)
        assert len(hits) == 1

    def test_case_insensitive(self) -> None:
        """Pattern matching is case-insensitive via re.IGNORECASE."""
        rule = Rule(
            rule_id="TEST",
            name="Case test",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["DANGER"],
        )
        text = "danger"
        hits = match_rule_on_text(rule, text)
        assert len(hits) == 1

    def test_multiple_patterns_or_logic(self) -> None:
        """At least one pattern must match (break on first per line)."""
        rule = Rule(
            rule_id="TEST",
            name="Multi-pattern",
            category="test",
            severity="high",
            globs=["*"],
            patterns=["pattern_a", "pattern_b"],
        )
        text = "line with pattern_a and pattern_b"
        hits = match_rule_on_text(rule, text)
        assert len(hits) == 1  # only one line, one hit (first pattern)


# ── RuleEngine integration ───────────────────────────────────────────

class TestRuleEngine:
    """RuleEngine.scan — end-to-end scan of a directory."""

    def test_scan_detects_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import os\nresult = eval(user_input)\n")
        rule = Rule(
            rule_id="EVAL-001",
            name="Eval Detected",
            category="code_review",
            severity="high",
            globs=["**/*.py"],
            patterns=["eval\\s*\\("],
        )
        engine = RuleEngine([rule])
        findings = engine.scan(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "EVAL-001"
        assert findings[0].file_path == "app.py"
        assert findings[0].line_number == 2

    def test_scan_skips_glob_mismatch(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text("eval(userInput)")
        rule = Rule(
            rule_id="PY-ONLY",
            name="Python Only",
            category="test",
            severity="medium",
            globs=["**/*.py"],  # only .py files
            patterns=["eval"],
        )
        engine = RuleEngine([rule])
        findings = engine.scan(tmp_path)
        assert len(findings) == 0

    def test_scan_multiple_rules(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("dangerous_call()\nsecret = 'abc'\n")
        rules = [
            Rule("DANGER-001", "Danger Call", "test", "high", ["**/*.py"], ["dangerous"]),
            Rule("SECRET-001", "Secret Found", "test", "medium", ["**/*.py"], ["secret\\s*="]),
        ]
        engine = RuleEngine(rules)
        findings = engine.scan(tmp_path)
        assert len(findings) == 2
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"DANGER-001", "SECRET-001"}

    def test_scan_handles_binary_file_gracefully(self, tmp_path: Path) -> None:
        (tmp_path / "data.bin").write_bytes(bytes(range(256)))
        rule = Rule("BIN", "Bin Test", "test", "low", ["**/*"], ["test"])
        engine = RuleEngine([rule])
        findings = engine.scan(tmp_path)
        # Should not crash; may or may not find a match
        assert isinstance(findings, list)

    def test_iter_text_files_skips_large_and_binary(self, tmp_path: Path) -> None:
        (tmp_path / "small.txt").write_text("hello")
        large = tmp_path / "large.bin"
        large.write_bytes(b"x" * (600 * 1024))  # > 512 KB
        files = iter_text_files(tmp_path)
        names = {f.name for f in files}
        assert "small.txt" in names
        assert "large.bin" not in names
