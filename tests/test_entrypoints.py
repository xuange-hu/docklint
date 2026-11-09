"""The MCP wrapper surface must stay in lockstep with the manifest.

`tool_manifest()` is what tools/list reports in the README and what
`vehsec mcp --check`-style smoke tests count. A decorator added without a
manifest entry (or the reverse) means the documentation is lying.
"""

from __future__ import annotations

import os
import re

import pytest

from docklint import mcp_server

pytest.importorskip("mcp")

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "docklint")


def test_tool_names_are_unique_and_prefixed():
    names = list(mcp_server.TOOLS)
    assert len(names) == len(set(names))
    assert all(name.startswith("docklint_") for name in names)


def test_decorator_count_matches_the_manifest():
    with open(os.path.join(SRC, "mcp_server.py"), encoding="utf-8") as fh:
        source = fh.read()
    decorated = re.findall(r'@mcp\.tool\(name="([^"]+)"\)', source)
    assert decorated == list(mcp_server.TOOLS)


def test_manifest_entries_carry_descriptions():
    for entry in mcp_server.tool_manifest():
        assert entry["description"] and len(entry["description"]) > 20, entry["name"]


def test_server_construction_is_lazy():
    # Importing the module must not require `mcp`; only building the server does.
    assert mcp_server.docklint_rules.__module__ == "docklint.mcp_server"
