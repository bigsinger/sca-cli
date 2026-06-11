from __future__ import annotations

from pathlib import Path

from sca_cli.normalize.findings import Finding
from sca_cli.rules.loader import Rule
from sca_cli.rules.matcher import iter_text_files, match_rule_on_text, matches_glob


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_text_files(root):
            relative = path.relative_to(root).as_posix()
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for rule in self.rules:
                if not matches_glob(relative, rule.globs):
                    continue
                for line_number, evidence in match_rule_on_text(rule, text):
                    findings.append(
                        Finding(
                            category=rule.category,
                            severity=rule.severity,
                            title=rule.name,
                            description=rule.description,
                            rule_id=rule.rule_id,
                            file_path=relative,
                            line_number=line_number,
                            evidence=evidence,
                            remediation=rule.remediation,
                            source=rule.source,
                            raw={"confidence": rule.confidence},
                        )
                    )
        return findings
