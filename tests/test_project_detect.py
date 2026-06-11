"""Tests for project detection — detect_project and ProjectProfile."""

from __future__ import annotations

from pathlib import Path

import pytest

from sca_cli.core.project_detect import ProjectProfile, detect_project


FIXTURES = Path("tests/fixtures")


# ── helpers ──────────────────────────────────────────────────────────

def _profile_names() -> list[str]:
    """Return all boolean-flag attribute names on ProjectProfile."""
    return ["has_python", "has_javascript", "has_mcp", "has_plugin", "has_agent_skill", "has_lockfile"]


# ── Python project ───────────────────────────────────────────────────

class TestPythonProject:
    """Projects with requirements.txt, setup.py, pyproject.toml etc."""

    def test_python_safe_skill(self) -> None:
        """python_safe_skill fixture is detected as python + agent."""
        profile = detect_project(FIXTURES / "python_safe_skill")
        assert profile.project_type == "python"
        assert profile.skill_mode == "agent"
        assert profile.has_python is True
        assert profile.has_agent_skill is True  # has skill.json
        assert profile.has_lockfile is False  # no lockfile
        assert "No Python or JavaScript lockfile detected" in " ".join(profile.warnings)

    def test_python_vulnerable_skill(self) -> None:
        """python_vulnerable_skill fixture is detected as python + agent."""
        profile = detect_project(FIXTURES / "python_vulnerable_skill")
        assert profile.project_type == "python"
        assert profile.skill_mode == "agent"
        assert profile.has_python is True
        assert profile.has_agent_skill is True

    def test_python_malicious_setup(self) -> None:
        """python_malicious_setup fixture (setup.py + requirements.txt)."""
        profile = detect_project(FIXTURES / "python_malicious_setup")
        assert profile.project_type == "python"
        assert profile.has_python is True
        assert profile.manifests is not None  # may pick up setup.py as manifest


# ── JavaScript project ───────────────────────────────────────────────

class TestJavaScriptProject:
    """Projects with package.json, lockfiles etc."""

    def test_js_postinstall_risk(self) -> None:
        """js_postinstall_risk fixture."""
        profile = detect_project(FIXTURES / "js_postinstall_risk")
        assert profile.project_type == "javascript"
        assert profile.has_javascript is True
        assert profile.has_lockfile is False

    def test_js_vulnerable_skill(self) -> None:
        """js_vulnerable_skill fixture."""
        profile = detect_project(FIXTURES / "js_vulnerable_skill")
        assert profile.project_type == "javascript"
        assert profile.has_javascript is True

    def test_js_safe_skill(self) -> None:
        """js_safe_skill fixture."""
        profile = detect_project(FIXTURES / "js_safe_skill")
        assert profile.project_type == "javascript"
        assert profile.has_javascript is True


# ── MCP project ──────────────────────────────────────────────────────

class TestMCPProject:
    """Projects with mcp.json or MCP framework dependencies."""

    def test_mcp_command_tool(self) -> None:
        """mcp_command_tool fixture — has mcp.json."""
        profile = detect_project(FIXTURES / "mcp_command_tool")
        assert profile.has_mcp is True
        # mcp takes precedence over other types
        # (server.py alone wouldn't trigger python if mcp.json exists; but server.py *is* .py)
        # With mcp.json present, has_mcp = True
        # project_type depends on other factors; has_mcp may not be the type-determining flag

    def test_mcp_prompt_injection(self) -> None:
        """mcp_prompt_injection fixture."""
        profile = detect_project(FIXTURES / "mcp_prompt_injection")
        assert profile.has_mcp is True
        assert "mcp.json" in " ".join(profile.manifests)


# ── AI Plugin detection ──────────────────────────────────────────────

class TestAIPlugin:
    """Projects with ai-plugin.json or OpenAPI specs."""

    def test_detect_ai_plugin_from_manifest(self, tmp_path: Path) -> None:
        """A directory with ai-plugin.json is detected as plugin."""
        (tmp_path / "ai-plugin.json").write_text('{"name":"test","description":"test"}')
        profile = detect_project(tmp_path)
        assert profile.has_plugin is True
        assert profile.skill_mode == "plugin"

    def test_detect_openapi_yml(self, tmp_path: Path) -> None:
        """openapi.yaml triggers plugin detection."""
        (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\ninfo:\n  title: test\n")
        profile = detect_project(tmp_path)
        assert profile.has_plugin is True
        assert "openapi.yaml" in " ".join(profile.manifests)

    def test_detect_openapi_json(self, tmp_path: Path) -> None:
        """openapi.json triggers plugin detection."""
        (tmp_path / "openapi.json").write_text('{"openapi":"3.0.0"}')
        profile = detect_project(tmp_path)
        assert profile.has_plugin is True


# ── Agent Skill detection ────────────────────────────────────────────

class TestAgentSkill:
    """Projects with skill.json, agent.json, tool.json, etc."""

    @pytest.mark.parametrize(
        "manifest",
        ["skill.json", "agent.json", "tool.json", "tools.json", "plugin.yaml", "plugin.json"],
    )
    def test_detect_skill_from_manifest(self, tmp_path: Path, manifest: str) -> None:
        (tmp_path / manifest).write_text('{"name":"test"}')
        profile = detect_project(tmp_path)
        assert profile.has_agent_skill is True

    def test_detect_skill_from_tools_dir(self, tmp_path: Path) -> None:
        """A tools/ directory triggers agent_skill detection."""
        (tmp_path / "tools").mkdir()
        (tmp_path / "tools" / "my_tool.json").write_text("{}")
        profile = detect_project(tmp_path)
        assert profile.has_agent_skill is True

    def test_detect_skill_from_prompts_dir(self, tmp_path: Path) -> None:
        """A prompts/ directory triggers agent_skill detection."""
        (tmp_path / "prompts").mkdir()
        (tmp_path / "prompts" / "greeting.md").write_text("hello")
        profile = detect_project(tmp_path)
        assert profile.has_agent_skill is True


# ── Mixed project ────────────────────────────────────────────────────

class TestMixedProject:
    """Projects containing both Python and JavaScript files."""

    def test_mixed_python_js_skill(self) -> None:
        """mixed_python_js_skill fixture has both .py files and package.json."""
        profile = detect_project(FIXTURES / "mixed_python_js_skill")
        assert profile.project_type == "mixed"
        assert profile.has_python is True
        assert profile.has_javascript is True

    def test_mixed_detected_via_files(self, tmp_path: Path) -> None:
        """A directory with a .py file and a package.json is mixed."""
        (tmp_path / "script.py").write_text("")
        (tmp_path / "package.json").write_text("{}")
        profile = detect_project(tmp_path)
        assert profile.project_type == "mixed"


# ── Edge cases ───────────────────────────────────────────────────────

class TestEdgeCases:
    """Unknown projects, forced types, empty directories."""

    def test_empty_directory_is_unknown(self, tmp_path: Path) -> None:
        profile = detect_project(tmp_path)
        assert profile.project_type == "unknown"
        assert profile.skill_mode == "auto"

    def test_forced_project_type(self, tmp_path: Path) -> None:
        """force project_type via forced_type parameter."""
        profile = detect_project(tmp_path, forced_type="python")
        assert profile.project_type == "python"

    def test_forced_skill_mode(self, tmp_path: Path) -> None:
        """force skill_mode via forced_skill_mode parameter."""
        profile = detect_project(tmp_path, forced_skill_mode="mcp")
        assert profile.skill_mode == "mcp"

    def test_lockfile_detected(self, tmp_path: Path) -> None:
        """A directory with package-lock.json triggers has_lockfile."""
        (tmp_path / "package-lock.json").write_text("{}")
        profile = detect_project(tmp_path)
        assert profile.has_lockfile is True

    def test_no_lockfile_warning(self, tmp_path: Path) -> None:
        """Python project without lockfile gets a warning."""
        (tmp_path / "requirements.txt").write_text("requests")
        profile = detect_project(tmp_path)
        assert len(profile.warnings) > 0
        assert "lockfile" in profile.warnings[0].lower()

    def test_skip_dirs_are_ignored(self, tmp_path: Path) -> None:
        """node_modules, .git, __pycache__ are skipped."""
        (tmp_path / ".git" / "config").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "index.js").mkdir(parents=True)
        (tmp_path / "__pycache__" / "foo.pyc").mkdir(parents=True)
        (tmp_path / "valid.py").write_text("")
        profile = detect_project(tmp_path)
        # Only valid.py should be seen
        assert profile.has_python is True
        # But .js files in node_modules should NOT trigger js detection
        assert profile.has_javascript is False

    def test_project_profile_to_dict(self, tmp_path: Path) -> None:
        """ProjectProfile.to_dict returns expected keys."""
        (tmp_path / "requirements.txt").write_text("requests")
        profile = detect_project(tmp_path)
        d = profile.to_dict()
        assert isinstance(d, dict)
        assert d["project_type"] == "python"
        assert "has_python" in d
        assert "has_javascript" in d
        assert "features" in d
        assert "manifests" in d
        assert "warnings" in d
        assert "skill_mode" in d
