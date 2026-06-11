from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Rule:
    rule_id: str
    name: str
    category: str
    severity: str
    globs: list[str]
    patterns: list[str]
    description: str = ""
    remediation: str = ""
    source: str = "builtin"
    confidence: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)


def load_builtin_rules() -> list[Rule]:
    rules_root = resources.files("sca_cli").joinpath("rules_builtin")
    rules: list[Rule] = []
    for resource in rules_root.rglob("*.yml"):
        with resource.open("r", encoding="utf-8") as fh:
            rules.extend(_parse_rules(yaml.safe_load(fh) or {}, source=f"builtin:{resource.name}"))
    return rules


def load_external_rules(root: Path) -> list[Rule]:
    if not root.exists():
        return []
    rules: list[Rule] = []
    for path in root.rglob("*.yml"):
        try:
            rules.extend(_parse_rules(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, source=str(path)))
        except Exception:
            continue
    for path in root.rglob("*.yaml"):
        try:
            rules.extend(_parse_rules(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, source=str(path)))
        except Exception:
            continue
    return rules


def load_rules(root: Path | None = None, *, categories: set[str] | None = None) -> list[Rule]:
    rules = load_builtin_rules()
    if root is not None:
        rules.extend(load_external_rules(root))
    if categories:
        rules = [rule for rule in rules if rule.category in categories]
    return rules


def validate_rule_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return [f"{path}: YAML parse failed: {exc}"]
    for index, item in enumerate(data.get("rules") or []):
        prefix = f"{path}: rule[{index}]"
        for key in ["id", "name", "category", "severity", "globs", "patterns"]:
            if key not in item:
                errors.append(f"{prefix}: missing {key}")
        if "patterns" in item and not isinstance(item["patterns"], list):
            errors.append(f"{prefix}: patterns must be a list")
        if "globs" in item and not isinstance(item["globs"], list):
            errors.append(f"{prefix}: globs must be a list")
    return errors


def _parse_rules(data: dict[str, Any], *, source: str) -> list[Rule]:
    parsed: list[Rule] = []
    for item in data.get("rules") or []:
        parsed.append(
            Rule(
                rule_id=str(item["id"]),
                name=str(item["name"]),
                category=str(item["category"]),
                severity=str(item["severity"]).lower(),
                globs=[str(value) for value in item.get("globs") or ["**/*"]],
                patterns=[str(value) for value in item.get("patterns") or []],
                description=str(item.get("description") or ""),
                remediation=str(item.get("remediation") or ""),
                source=source,
                confidence=str(item.get("confidence") or "medium"),
                metadata={key: value for key, value in item.items() if key not in {"id", "name", "category", "severity", "globs", "patterns"}},
            )
        )
    return parsed
