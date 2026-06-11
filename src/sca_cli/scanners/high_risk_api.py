from __future__ import annotations

from sca_cli.rules.engine import RuleEngine
from sca_cli.rules.loader import load_rules
from sca_cli.scanners.base import ScanContext


def scan_high_risk_apis(context: ScanContext):
    rules = load_rules(context.paths.rules, categories={"high_risk_api"})
    return RuleEngine(rules).scan(context.target_dir)
