"""Packaging contract: what `pip install docklint` promises.

The failure this guards against is specific and has shipped in this family
before: a console script whose module imports an optional dependency at module
scope works in CI (which installs `.[all]`) and dies on a user's machine with
ModuleNotFoundError.
"""

from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _pytoml  # noqa: E402

import docklint  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src", "docklint")

STDLIB = {
    "__future__",
    "argparse",
    "ast",
    "dataclasses",
    "json",
    "os",
    "pathlib",
    "re",
    "sys",
    "tempfile",
    "typing",
}


def _pyproject() -> dict:
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        return _pytoml.loads(fh.read())


def test_version_matches_pyproject():
    assert docklint.__version__ == _pyproject()["project"]["version"]


def test_core_has_no_runtime_dependencies():
    # Zero dependencies is the product claim: the audit has to run inside the
    # image build it is auditing, where pip is often unavailable.
    assert _pyproject()["project"]["dependencies"] == []


def test_mcp_is_an_optional_extra():
    extras = _pyproject()["project"]["optional-dependencies"]
    assert any(dep.startswith("mcp") for dep in extras["mcp"])


def test_console_scripts_resolve():
    scripts = _pyproject()["project"]["scripts"]
    assert scripts["docklint"] == "docklint.cli:main"
    assert scripts["docklint-mcp"] == "docklint.mcp_server:main"
    import docklint.cli
    import docklint.mcp_server

    assert callable(docklint.cli.main)
    assert callable(docklint.mcp_server.main)


def test_module_level_imports_are_stdlib_only():
    offenders: list[str] = []
    for name in sorted(os.listdir(SRC)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(SRC, name)
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in STDLIB:
                        offenders.append(f"{name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                root = (node.module or "").split(".")[0]
                if root not in STDLIB:
                    offenders.append(f"{name}: from {node.module}")
    assert not offenders, offenders


def test_mcp_import_is_deferred_into_build_server():
    path = os.path.join(SRC, "mcp_server.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    import_line = source.index("from mcp.server.fastmcp import FastMCP")
    function_line = source.index("def build_server")
    assert function_line < import_line, "the mcp import must live inside build_server()"


def test_package_data_declares_py_typed():
    assert os.path.isfile(os.path.join(SRC, "py.typed"))
    assert "py.typed" in _pyproject()["tool"]["setuptools"]["package-data"]["docklint"]
