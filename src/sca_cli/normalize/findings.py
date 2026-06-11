from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from sca_cli.utils.hashing import stable_hash

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_SCORE = {
    "info": 5,
    "low": 20,
    "medium": 50,
    "high": 80,
    "critical": 100,
}


def normalize_severity(value: str | None) -> str:
    normalized = (value or "info").strip().lower()
    if normalized in SEVERITY_ORDER:
        return normalized
    if normalized in {"moderate"}:
        return "medium"
    if normalized in {"severe"}:
        return "high"
    return "info"


def highest_severity(values: list[str]) -> str:
    if not values:
        return "info"
    return max((normalize_severity(v) for v in values), key=lambda item: SEVERITY_ORDER[item])


@dataclass(slots=True)
class Component:
    ecosystem: str
    name: str
    version: str | None = None
    purl: str | None = None
    type: str = "library"
    evidence: str | None = None
    source: str = "built-in"
    licenses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    category: str
    severity: str
    title: str
    description: str = ""
    component_name: str | None = None
    component_version: str | None = None
    ecosystem: str | None = None
    vuln_id: str | None = None
    rule_id: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    evidence: str | None = None
    remediation: str | None = None
    source: str = "rule"
    raw: dict[str, Any] = field(default_factory=dict)
    finding_id: str | None = None

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        if self.finding_id is None:
            self.finding_id = make_finding_id(self)

    def dedupe_key(self) -> tuple[Any, ...]:
        if self.category == "vulnerability":
            return (
                self.category,
                (self.ecosystem or "").lower(),
                (self.component_name or "").lower(),
                self.component_version or "",
                (self.vuln_id or self.title).upper(),
            )
        return (
            self.category,
            self.rule_id or self.title,
            self.file_path or "",
            self.line_number or 0,
            stable_hash(self.evidence or "", length=12),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_finding_id(finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, Finding):
        payload = {
            "category": finding.category,
            "component": finding.component_name,
            "version": finding.component_version,
            "vuln": finding.vuln_id,
            "rule": finding.rule_id,
            "file": finding.file_path,
            "line": finding.line_number,
            "evidence": finding.evidence,
        }
    else:
        payload = finding
    return stable_hash(payload, length=24)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple[Any, ...], Finding] = {}
    for finding in findings:
        key = finding.dedupe_key()
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.severity]:
            existing.severity = finding.severity
        if finding.source not in existing.source.split(","):
            existing.source = ",".join(sorted(set(existing.source.split(",") + [finding.source])))
        if finding.description and finding.description not in existing.description:
            existing.description = (existing.description + "\n" + finding.description).strip()
        if finding.remediation and not existing.remediation:
            existing.remediation = finding.remediation
    return sorted(
        merged.values(),
        key=lambda item: (SEVERITY_ORDER[item.severity], item.category, item.title),
        reverse=True,
    )


def summarize_findings(components: list[Component], findings: list[Finding]) -> dict[str, Any]:
    by_severity = {key: 0 for key in ["critical", "high", "medium", "low", "info"]}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    score = calculate_risk_score(findings)
    return {
        "component_count": len(components),
        "finding_count": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "risk_score": score,
        "risk_level": risk_level(score),
    }


def calculate_risk_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        score = max(score, SEVERITY_SCORE[finding.severity])
        evidence = (finding.evidence or "").lower()
        title = finding.title.lower()
        if finding.category == "install_script":
            score += 20
        if finding.rule_id in {"MCP-TOOL-004", "JS-INSTALL-001", "PY-INSTALL-001"}:
            score += 25
        if "ignore previous" in evidence or "prompt injection" in title:
            score += 15
        if finding.category == "vulnerability" and finding.ecosystem in {"pypi", "npm"}:
            score += 10
        if "," in finding.source:
            score += 5
    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 86:
        return "critical"
    if score >= 61:
        return "high"
    if score >= 31:
        return "medium"
    return "low"
