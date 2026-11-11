"""MCP surface: names, manifest parity, and the two structural tools.

The module itself must import without `mcp` installed (it is an optional extra),
so the guard is on `build_server()` only — see test_packaging.py for the static
check that keeps it that way.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from docklint import mcp_server

pytest.importorskip("mcp")

BAD_DF = "FROM ubuntu\nCOPY id_rsa /app/id_rsa\nCMD python app.py\n"


def test_manifest_matches_declared_tool_names():
    names = [t["name"] for t in mcp_server.tool_manifest()]
    assert names == list(mcp_server.TOOLS)


def test_every_tool_has_a_description():
    for tool in mcp_server.tool_manifest():
        assert tool["description"].strip(), tool["name"]


def test_server_registers_exactly_the_manifest():
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == set(mcp_server.TOOLS)


def test_scan_tool_returns_json_with_evidence(project):
    root = project(dockerfile=BAD_DF)
    payload = json.loads(mcp_server.docklint_scan(str(root)))
    assert payload["counts"]["high"] >= 1
    assert payload["findings"][0]["path"].startswith("Dockerfile")
    assert payload["summary"]


def test_scan_tool_on_missing_path_is_a_clean_error(tmp_path):
    payload = json.loads(mcp_server.docklint_scan(str(tmp_path / "absent")))
    assert "error" in payload


def test_scan_tool_truncates_and_says_so(project):
    root = project(dockerfile=BAD_DF)
    payload = json.loads(mcp_server.docklint_scan(str(root), max_findings=1))
    assert len(payload["findings"]) == 1
    assert payload["truncatedFindings"] is True


def test_scan_tool_honours_ignore_rules(project):
    root = project(dockerfile=BAD_DF)
    payload = json.loads(mcp_server.docklint_scan(str(root), ignore_rules="DRL006"))
    assert "DRL006" not in payload["rules_hit"]


def test_explain_returns_the_fix():
    payload = json.loads(mcp_server.docklint_explain("DRX004"))
    assert payload["pass"] == 3
    assert "Fix" in payload["narrative"]


def test_explain_unknown_rule_lists_known_ids():
    payload = json.loads(mcp_server.docklint_explain("NOPE"))
    assert "DRL001" in payload["known"]


def test_rules_tool_filters_by_pass():
    payload = json.loads(mcp_server.docklint_rules(pass_no=3))
    assert payload["count"] == len([r for r in payload["rules"]])
    assert all(r["pass"] == 3 for r in payload["rules"])


def test_sarif_tool(project):
    root = project(dockerfile=BAD_DF)
    payload = json.loads(mcp_server.docklint_sarif(str(root)))
    assert payload["version"] == "2.1.0"


def test_dockerfile_tool_summarises_stages(tmp_path):
    path = tmp_path / "Dockerfile"
    path.write_text(
        "FROM python:3.12-slim AS build\nRUN echo x\nFROM python:3.12-slim\nUSER 10001\nEXPOSE 8080\n",
        encoding="utf-8",
    )
    payload = json.loads(mcp_server.docklint_dockerfile(str(path)))
    assert payload["finalStage"] == "stage-1"
    assert payload["stages"][0]["alias"] == "build"
    assert payload["stages"][1]["user"] == "10001"
    assert payload["stages"][1]["expose"] == ["8080"]


def test_compose_tool_summarises_services(tmp_path):
    path = tmp_path / "docker-compose.yml"
    path.write_text(
        "services:\n  web:\n    build: .\n    ports:\n      - \"127.0.0.1:8080:80\"\n",
        encoding="utf-8",
    )
    payload = json.loads(mcp_server.docklint_compose(str(path)))
    service = payload["services"][0]
    assert service["name"] == "web"
    assert service["ports"][0]["target"] == "80"
    assert service["build"] == [".", "Dockerfile"]


def test_missing_file_tools_return_errors(tmp_path):
    assert "error" in json.loads(mcp_server.docklint_dockerfile(str(tmp_path / "nope")))
    assert "error" in json.loads(mcp_server.docklint_compose(str(tmp_path / "nope")))


def test_demo_tool_covers_every_rule():
    payload = json.loads(mcp_server.docklint_demo())
    assert len(payload["rules_hit"]) == 38


def test_every_served_tool_has_a_description():
    """FastMCP serves an empty description when the registered function has no
    docstring - an unidentified tool is an uncallable tool."""
    import asyncio

    server = mcp_server.build_server()
    for t in asyncio.run(server.list_tools()):
        assert (t.description or "").strip(), f"{t.name} has no description"
