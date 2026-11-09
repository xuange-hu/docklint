"""Test scaffolding: every test builds a throwaway project on disk.

Scanning takes a path, so the fixtures are real directories. Keeping them real
(rather than mocking the filesystem) is deliberate: the cross-file pass depends
on what is *actually* on disk next to the Dockerfile, and a mock would let a
broken DRX001 keep passing forever.
"""

import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from docklint.engine import scan  # noqa: E402


@pytest.fixture
def project(tmp_path):
    """Factory: ``project(dockerfile=..., compose=..., ignore=..., extra={...})``."""

    def _make(dockerfile=None, compose=None, ignore=None, extra=None, dockerfile_name="Dockerfile"):
        if dockerfile is not None:
            (tmp_path / dockerfile_name).write_text(dockerfile, encoding="utf-8", newline="\n")
        if compose is not None:
            (tmp_path / "docker-compose.yml").write_text(compose, encoding="utf-8", newline="\n")
        if ignore is not None:
            (tmp_path / ".dockerignore").write_text(ignore, encoding="utf-8", newline="\n")
        for name, content in (extra or {}).items():
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        return tmp_path

    return _make


@pytest.fixture
def hits(project):
    """Factory: build a project and return the set of rule ids that fired."""

    def _hits(**kwargs):
        root = project(**kwargs)
        return {f.rule.id for f in scan(root).findings}

    return _hits
