from __future__ import annotations

from sca_cli.rules.engine import RuleEngine
from sca_cli.rules.loader import load_rules
from sca_cli.scanners.base import ScanContext


def scan_skill_rules(context: ScanContext):
    categories = {"skill_metadata", "mcp_tool", "plugin_manifest", "openapi_risk"}
    rules = load_rules(context.paths.rules, categories=categories)
    return RuleEngine(rules).scan(context.target_dir)
