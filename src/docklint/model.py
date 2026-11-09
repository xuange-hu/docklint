"""Core data model. Dependency-free on purpose."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Display order: most severe first.
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
# Comparison order: most severe gets the HIGHEST rank. Keeping these two tables
# apart matters — collapsing them makes `--fail-on high` compare critical(0) >=
# high(1) and never fire, which is the quietest possible way to ship a gate that
# does nothing.
SEVERITY_RANK = {s: len(SEVERITIES) - 1 - i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


@dataclass(frozen=True)
class Rule:
    """One check. ``group`` drives the ``--ignore-group`` filter.

    ``pass_no`` records which sweep found the problem: 1 = Dockerfile alone,
    2 = compose alone, 3 = a relation between files. The pass number is part of
    the contract because the third pass is the reason this tool exists.
    """

    id: str
    title: str
    severity: str
    group: str
    why: str
    fix: str
    pass_no: int = 1
    cwe: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "group": self.group,
            "pass": self.pass_no,
            "why": self.why,
            "fix": self.fix,
            "cwe": self.cwe,
        }


@dataclass
class Finding:
    """A single hit, carrying enough context to be re-checked by hand."""

    rule: Rule
    path: str
    line: int
    snippet: str
    detail: str
    # Structural coordinates, empty when not applicable.
    stage: str = ""
    service: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ruleId": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "group": self.rule.group,
            "pass": self.rule.pass_no,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "detail": self.detail,
            "stage": self.stage,
            "service": self.service,
        }

    def one_line(self) -> str:
        return f"{self.path}:{self.line}: {self.rule.id} {self.rule.severity} {self.detail}"


@dataclass
class ScanResult:
    """Everything one ``scan`` produced."""

    root: str
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.rule.severity, 9), f.path, f.line, f.rule.id),
        )

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.rule.severity] = out.get(f.rule.severity, 0) + 1
        return out

    def worst(self) -> str | None:
        found = [f.rule.severity for f in self.findings]
        if not found:
            return None
        return min(found, key=lambda s: SEVERITY_ORDER.get(s, 9))

    def risk_score(self) -> int:
        """0-100, capped. A single high finding already means 'look at me'."""
        raw = sum(SEVERITY_WEIGHT.get(f.rule.severity, 0) for f in self.findings)
        return min(100, raw)

    def rules_hit(self) -> list[str]:
        seen: list[str] = []
        for f in self.sorted_findings():
            if f.rule.id not in seen:
                seen.append(f.rule.id)
        return seen

    def gate(self, fail_on: str | None) -> bool:
        """True when the exit code should be non-zero."""
        if not fail_on or fail_on == "none":
            return False
        threshold = SEVERITY_RANK.get(fail_on, 99)
        return any(SEVERITY_RANK.get(f.rule.severity, -1) >= threshold for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files": self.files,
            "counts": self.counts(),
            "worst": self.worst(),
            "risk": self.risk_score(),
            "rules_hit": self.rules_hit(),
            "findings": [f.as_dict() for f in self.sorted_findings()],
        }
