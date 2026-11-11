"""MCP surface — optional extra, imported only when the ``mcp`` package exists.

The module stays importable without `mcp`: the ImportError is deferred to
``build_server()``, so `docklint --version` never needs the optional dependency.

Tool names are given explicitly (`@mcp.tool(name=...)`) because the decorator
otherwise registers the wrapper's function name, and a tool called
`docklint_scan_tool` is a worse prompt target than `docklint_scan`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .compose import parse_compose
from .demo import materialize
from .dockfile import parse_copy_args, parse_dockerfile
from .engine import scan
from .model import SEVERITY_RANK
from .render import build_sarif, render_text
from .rules import RULES, all_rules, by_id

TOOLS = (
    "docklint_scan",
    "docklint_explain",
    "docklint_rules",
    "docklint_sarif",
    "docklint_dockerfile",
    "docklint_compose",
    "docklint_demo",
)


def _scan(path: str, min_severity: str, ignore_rules: str, ignore_groups: str, fail_on: str):
    return scan(
        path,
        ignore_rules={r.strip() for r in ignore_rules.split(",") if r.strip()},
        ignore_groups={g.strip() for g in ignore_groups.split(",") if g.strip()},
        min_severity=min_severity if min_severity in SEVERITY_RANK else None,
        severity_rank=SEVERITY_RANK,
    )


def docklint_scan(
    path: str = ".",
    min_severity: str = "info",
    ignore_rules: str = "",
    ignore_groups: str = "",
    fail_on: str = "none",
    max_findings: int = 80,
) -> str:
    """Scan Dockerfiles, compose files and .dockerignore for security problems.

    Three passes: the Dockerfile alone, the compose file alone, then the
    relations between them (an ignored COPY source, a compose `user: root` over
    an image that dropped privileges, a secret baked in and mounted over).
    Returns JSON with per-finding file:line evidence.
    """
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}", "tool": "docklint"}, ensure_ascii=False)
    result = _scan(path, min_severity, ignore_rules, ignore_groups, fail_on)
    payload: dict[str, Any] = result.as_dict()
    payload["summary"] = render_text(result)
    payload["wouldFail"] = result.gate(fail_on)
    total = len(result.findings)
    payload["findings"] = payload["findings"][: max(1, int(max_findings))]
    payload["truncatedFindings"] = total > max_findings
    return json.dumps(payload, indent=2, ensure_ascii=False)


def docklint_explain(rule_id: str) -> str:
    """Explain one rule: what the pattern is, why it matters, and how to fix it."""
    rule = by_id(rule_id)
    if rule is None:
        return json.dumps(
            {"error": f"unknown rule {rule_id}", "known": sorted(RULES)},
            ensure_ascii=False,
        )
    return json.dumps(
        {**rule.as_dict(), "narrative": f"{rule.why}\n\nFix: {rule.fix}"},
        indent=2,
        ensure_ascii=False,
    )


def docklint_rules(group: str = "", pass_no: int = 0) -> str:
    """List rules, filterable by group and by pass number (1=Dockerfile, 2=compose, 3=cross-file)."""
    items = [r for r in all_rules() if not group or r.group == group]
    if pass_no:
        items = [r for r in items if r.pass_no == pass_no]
    return json.dumps(
        {"count": len(items), "rules": [r.as_dict() for r in items]},
        indent=2,
        ensure_ascii=False,
    )


def docklint_sarif(path: str = ".") -> str:
    """Scan and return SARIF 2.1.0, ready for GitHub code scanning."""
    if not os.path.exists(path):
        return json.dumps({"error": f"path not found: {path}"}, ensure_ascii=False)
    result = _scan(path, "info", "", "", "none")
    return json.dumps(build_sarif(result), indent=2, ensure_ascii=False)


def docklint_dockerfile(path: str = "Dockerfile") -> str:
    """Summarise a Dockerfile structurally: stages, base images, USER, ports, COPY sources.

    Useful before editing: it answers "which stage is final, does it drop
    privileges, what does it copy and from where" without reading the file.
    """
    if not os.path.isfile(path):
        return json.dumps({"error": f"file not found: {path}"}, ensure_ascii=False)
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    df = parse_dockerfile(text, os.path.basename(path))
    stages = []
    for st in df.stages:
        copies = []
        for instr in st.instructions:
            if instr.name in ("COPY", "ADD"):
                flags, parts = parse_copy_args(instr.args)
                copies.append(
                    {
                        "instruction": instr.name,
                        "line": instr.line,
                        "from": flags.get("from", ""),
                        "sources": parts[:-1] if len(parts) > 1 else parts,
                        "dest": parts[-1] if len(parts) > 1 else "",
                    }
                )
        stages.append(
            {
                "index": st.index,
                "alias": st.alias,
                "image": st.image,
                "line": st.line,
                "instructions": [i.name for i in st.instructions],
                "user": next(
                    (i.args.strip() for i in reversed(st.instructions) if i.name == "USER"), ""
                ),
                "expose": [
                    tok
                    for i in st.instructions
                    if i.name == "EXPOSE"
                    for tok in i.args.split()
                ],
                "healthcheck": any(i.name == "HEALTHCHECK" for i in st.instructions),
                "copies": copies,
            }
        )
    return json.dumps(
        {
            "path": path,
            "escape": df.escape,
            "syntax": df.syntax,
            "finalStage": df.final_stage().label if df.final_stage() else None,
            "stages": stages,
            "parseErrors": df.errors,
        },
        indent=2,
        ensure_ascii=False,
    )


def docklint_compose(path: str = "docker-compose.yml") -> str:
    """Summarise a compose file: services, images, published ports, mounts, environment keys."""
    if not os.path.isfile(path):
        return json.dumps({"error": f"file not found: {path}"}, ensure_ascii=False)
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    compose = parse_compose(text, os.path.basename(path))
    services = []
    for name in compose.service_names():
        svc = compose.service(name)
        services.append(
            {
                "name": name,
                "image": str(svc.get("image") or "") if svc else "",
                "build": compose.build_spec(name),
                "ports": [
                    {
                        "host_ip": p.host_ip,
                        "published": p.published,
                        "target": p.target,
                        "protocol": p.protocol,
                        "line": p.line,
                    }
                    for p in compose.ports(name)
                ],
                "mounts": [
                    {"type": m.type, "source": m.source, "target": m.target, "ro": m.read_only}
                    for m in compose.mounts(name)
                ],
                "envKeys": sorted(compose.environment(name)),
                "privileged": bool(svc.get("privileged")) if svc else False,
                "networkMode": str(svc.get("network_mode") or "") if svc else "",
                "user": str(svc.get("user") or "") if svc else "",
            }
        )
    return json.dumps(
        {
            "path": path,
            "services": services,
            "errors": compose.errors,
            "notes": compose.notes,
        },
        indent=2,
        ensure_ascii=False,
    )


def docklint_demo() -> str:
    """Scan a built-in broken project that trips all rules — one call proves the tool works."""
    tmp = tempfile.TemporaryDirectory(prefix="docklint-demo-mcp-")
    try:
        root = materialize(tmp.name)
        result = scan(root)
        payload = result.as_dict()
        payload["summary"] = render_text(result)
        payload["demoPath"] = str(root)
        return json.dumps(payload, indent=2, ensure_ascii=False)
    finally:
        tmp.cleanup()


def build_server():
    """Construct the MCP server. Requires the optional `mcp` extra."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="docklint")

    def _scan_tool(
        path: str = ".",
        min_severity: str = "info",
        ignore_rules: str = "",
        ignore_groups: str = "",
        fail_on: str = "none",
        max_findings: int = 80,
    ) -> str:
        return docklint_scan(path, min_severity, ignore_rules, ignore_groups, fail_on, max_findings)

    def _explain_tool(rule_id: str) -> str:
        return docklint_explain(rule_id)

    def _rules_tool(group: str = "", pass_no: int = 0) -> str:
        return docklint_rules(group, pass_no)

    def _sarif_tool(path: str = ".") -> str:
        return docklint_sarif(path)

    def _dockerfile_tool(path: str = "Dockerfile") -> str:
        return docklint_dockerfile(path)

    def _compose_tool(path: str = "docker-compose.yml") -> str:
        return docklint_compose(path)

    def _demo_tool() -> str:
        return docklint_demo()

    # FastMCP reads fn.__doc__ at registration time, so copy the underlying
    # docstring onto each wrapper *before* mcp.tool() runs - the manifest
    # promises these descriptions and an empty one is useless to an agent.
    for name, wrapper, fn in (
        ("docklint_scan", _scan_tool, docklint_scan),
        ("docklint_explain", _explain_tool, docklint_explain),
        ("docklint_rules", _rules_tool, docklint_rules),
        ("docklint_sarif", _sarif_tool, docklint_sarif),
        ("docklint_dockerfile", _dockerfile_tool, docklint_dockerfile),
        ("docklint_compose", _compose_tool, docklint_compose),
        ("docklint_demo", _demo_tool, docklint_demo),
    ):
        wrapper.__doc__ = fn.__doc__
        mcp.tool(name=name)(wrapper)

    return mcp


def tool_manifest() -> list[dict[str, str]]:
    return [
        {"name": "docklint_scan", "description": docklint_scan.__doc__ or ""},
        {"name": "docklint_explain", "description": docklint_explain.__doc__ or ""},
        {"name": "docklint_rules", "description": docklint_rules.__doc__ or ""},
        {"name": "docklint_sarif", "description": docklint_sarif.__doc__ or ""},
        {"name": "docklint_dockerfile", "description": docklint_dockerfile.__doc__ or ""},
        {"name": "docklint_compose", "description": docklint_compose.__doc__ or ""},
        {"name": "docklint_demo", "description": docklint_demo.__doc__ or ""},
    ]


def main() -> None:
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
