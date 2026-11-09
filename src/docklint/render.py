"""Output: evidence-first text, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any

from .model import SEVERITY_ORDER, ScanResult

__all__ = ["render_text", "render_json", "build_sarif", "SEV_COLOR"]

SEV_COLOR = {
    "critical": "\x1b[1;35m",
    "high": "\x1b[1;31m",
    "medium": "\x1b[33m",
    "low": "\x1b[36m",
    "info": "\x1b[2m",
}
RESET = "\x1b[0m"
BOLD = "\x1b[1m"


def _paint(text: str, color: bool, code: str) -> str:
    return f"{code}{text}{RESET}" if color else text


def render_text(result: ScanResult, color: bool = False, version: str = "") -> str:
    lines: list[str] = []
    header = "docklint"
    if version:
        header += f" {version}"
    lines.append(f"{_paint(header, color, BOLD)}  {result.root}")
    if result.files:
        lines.append(f"scanned {len(result.files)} file(s): {', '.join(result.files)}")
    else:
        lines.append("scanned 0 files — no Dockerfile or compose file found")

    by_path: dict[str, list] = {}
    for f in result.sorted_findings():
        by_path.setdefault(f.path, []).append(f)

    for path in sorted(by_path):
        lines.append("")
        lines.append(_paint(path, color, BOLD))
        for f in by_path[path]:
            color_code = SEV_COLOR.get(f.rule.severity, "")
            head = f"  {f.line:>4}  {_paint(f.rule.id, color, color_code)}  {f.rule.severity:<8} {f.rule.group}"
            lines.append(head)
            if f.snippet:
                lines.append(f"        | {f.snippet}")
            lines.append(f"        -> {f.detail}")
            lines.append(f"        fix: {f.rule.fix}")

    counts = result.counts()
    if result.findings:
        parts = [f"{counts[s]} {s}" for s in sorted(counts, key=lambda s: SEVERITY_ORDER[s]) if counts[s]]
        worst = result.worst() or "none"
        lines.append("")
        lines.append(f"summary: {', '.join(parts)}  worst={worst}  risk={result.risk_score()}/100")
    else:
        lines.append("")
        lines.append("summary: clean — no findings")
    if result.skipped:
        lines.append("")
        for note in result.skipped:
            lines.append(f"note: {note}")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2, ensure_ascii=False)


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}


def build_sarif(result: ScanResult) -> dict[str, Any]:
    """SARIF 2.1.0, so findings land in GitHub code scanning with no glue."""
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in result.sorted_findings():
        rid = f.rule.id
        if rid not in rules_seen:
            rules_seen[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.rule.title},
                "fullDescription": {"text": f"{f.rule.why}\n\nFix: {f.rule.fix}"},
                "help": {
                    "text": f"{f.rule.why}\n\nRemediation: {f.rule.fix}",
                    "markdown": f"**{f.rule.title}**\n\n{f.rule.why}\n\n**Fix:** {f.rule.fix}",
                },
                "properties": {
                    "tags": ["security", "container", f.rule.group, f"pass{f.rule.pass_no}"],
                    "security-severity": _SCORE.get(f.rule.severity, "0.0"),
                },
                "defaultConfiguration": {"level": _LEVEL.get(f.rule.severity, "note")},
            }
        results.append(
            {
                "ruleId": rid,
                "level": _LEVEL.get(f.rule.severity, "note"),
                "message": {"text": f.detail},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, f.line), "snippet": {"text": f.snippet}},
                        }
                    }
                ],
                "properties": {
                    "severity": f.rule.severity,
                    "pass": f.rule.pass_no,
                    "stage": f.stage,
                    "service": f.service,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "docklint",
                        "informationUri": "https://github.com/xuange-hu/docklint",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
                "properties": {"risk": result.risk_score(), "counts": result.counts()},
            }
        ],
    }
