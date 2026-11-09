"""The demo is the coverage contract: if a rule stops firing, this fails."""

from __future__ import annotations

import re

from docklint.demo import FILES, materialize
from docklint.engine import scan
from docklint.model import SEVERITIES
from docklint.rules import RULES, all_rules, groups


def test_demo_trips_every_rule(tmp_path):
    root = materialize(tmp_path)
    hit = set(scan(root).rules_hit())
    assert sorted(set(RULES) - hit) == [], "every rule must have a trigger in the demo"
    assert sorted(hit - set(RULES)) == []


def test_demo_findings_are_evidence_complete(tmp_path):
    root = materialize(tmp_path)
    for finding in scan(root).findings:
        assert finding.path, finding
        assert finding.line > 0, finding
        assert finding.snippet, f"{finding.rule.id} has no source snippet"
        assert finding.detail


def test_rule_ids_are_unique_and_well_formed():
    ids = [r.id for r in all_rules()]
    assert len(ids) == len(set(ids))
    for rule in all_rules():
        assert re.fullmatch(r"D(RL|RC|RX)\d{3}", rule.id), rule.id


def test_every_rule_documents_why_and_fix():
    for rule in all_rules():
        assert rule.severity in SEVERITIES, rule.id
        assert rule.pass_no in (1, 2, 3), rule.id
        assert len(rule.why) > 40, f"{rule.id}: why is too thin to be useful"
        assert len(rule.fix) > 15, f"{rule.id}: fix must be actionable"
        assert rule.group in groups()


def test_pass_numbers_match_the_rule_prefix():
    for rule in all_rules():
        expected = {"DRL": 1, "DRC": 2, "DRX": 3}[rule.id[:3]]
        assert rule.pass_no == expected, rule.id


def test_demo_contains_the_cross_file_fixtures():
    assert ".dockerignore" in FILES
    assert "docker-compose.yml" in FILES
    assert "Dockerfile" in FILES
    assert ".git/HEAD" in FILES, "DRX005 needs a real .git directory in the context"


def test_materialize_is_idempotent(tmp_path):
    first = materialize(tmp_path)
    second = materialize(tmp_path)
    assert first == second
    assert (tmp_path / "Dockerfile").read_text(encoding="utf-8") == FILES["Dockerfile"]


def test_readme_documents_every_rule():
    from pathlib import Path

    readme = Path(__file__).resolve().parent.parent / "README.md"
    text = readme.read_text(encoding="utf-8")
    missing = [r.id for r in all_rules() if r.id not in text]
    assert missing == [], f"README does not mention: {missing}"


def test_repo_self_scan_is_clean():
    """Dogfood: this repository's own Dockerfile must come back clean.

    A bug in a rule that only fires on the repo's own build is the most
    embarrassing possible regression, and the cheapest to catch.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    result = scan(root)
    assert result.findings == [], [f.one_line() for f in result.sorted_findings()]
