"""CLI contract: exit codes, formats, filters, and the demo subcommand."""

from __future__ import annotations

import json

from docklint.cli import main

BAD_DF = "FROM ubuntu\nCOPY id_rsa /app/id_rsa\nCMD python app.py\n"


def test_scan_clean_project_exits_zero(project, capsys):
    project(dockerfile="FROM python:3.12-slim\nUSER 10001\nCMD [\"python\"]\n")
    code = main(["scan", str(project(dockerfile=None) or ".")])
    assert code == 0
    assert "clean" in capsys.readouterr().out


def test_scan_fails_on_high_by_default(project):
    root = project(dockerfile=BAD_DF)
    assert main(["scan", str(root)]) == 1


def test_fail_on_none_never_fails(project):
    root = project(dockerfile=BAD_DF)
    assert main(["scan", str(root), "--fail-on", "none"]) == 0


def test_fail_on_critical_ignores_high(project):
    # BAD_DF has highs but no critical.
    root = project(dockerfile=BAD_DF)
    assert main(["scan", str(root), "--fail-on", "critical"]) == 0


def test_json_format_is_valid_json(project, capsys):
    root = project(dockerfile=BAD_DF)
    main(["scan", str(root), "--format", "json", "--fail-on", "none"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["high"] >= 1
    assert payload["findings"]


def test_sarif_format_has_the_right_shape(project, capsys):
    root = project(dockerfile=BAD_DF)
    main(["scan", str(root), "--format", "sarif", "--fail-on", "none"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "docklint"
    assert payload["runs"][0]["results"]


def test_output_flag_writes_a_file(project, tmp_path, capsys):
    root = project(dockerfile=BAD_DF)
    target = tmp_path / "report.json"
    main(["scan", str(root), "--format", "json", "--fail-on", "none", "-o", str(target)])
    assert json.loads(target.read_text(encoding="utf-8"))["findings"]
    assert capsys.readouterr().out == ""


def test_ignore_suppresses_one_rule(project, capsys):
    root = project(dockerfile=BAD_DF)
    main(["scan", str(root), "--ignore", "DRL006", "--fail-on", "none", "--format", "json"])
    ids = {f["ruleId"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "DRL006" not in ids


def test_ignore_group_suppresses_a_whole_group(project, capsys):
    root = project(dockerfile=BAD_DF)
    main(["scan", str(root), "--ignore-group", "secrets", "--fail-on", "none", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert "secrets" not in {f["group"] for f in payload["findings"]}


def test_min_severity_hides_low_findings(project, capsys):
    root = project(dockerfile="FROM python:3.12-slim\nUSER 10001\nEXPOSE 80\nCMD [\"x\"]\n")
    main(["scan", str(root), "--min-severity", "high", "--fail-on", "none", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


def test_missing_path_exits_two(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "nope")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_rules_lists_every_rule(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "DRL001" in out and "DRC001" in out and "DRX001" in out


def test_rules_json_and_pass_filter(capsys):
    main(["rules", "--json", "--pass", "3"])
    payload = json.loads(capsys.readouterr().out)
    assert payload and all(r["pass"] == 3 for r in payload)


def test_rules_group_filter(capsys):
    main(["rules", "--json", "--group", "privilege"])
    payload = json.loads(capsys.readouterr().out)
    assert payload and all(r["group"] == "privilege" for r in payload)


def test_demo_runs_and_finds_everything(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "critical" in out and "DRX004" in out


def test_demo_keep_writes_the_fixture(tmp_path, capsys):
    target = tmp_path / "fixture"
    main(["demo", "--keep", str(target)])
    assert (target / "Dockerfile").is_file()
    assert (target / "docker-compose.yml").is_file()


def test_scan_single_file_target(project):
    root = project(dockerfile=BAD_DF)
    assert main(["scan", str(root / "Dockerfile")]) == 1
