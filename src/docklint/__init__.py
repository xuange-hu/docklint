"""docklint — security auditor for Dockerfiles, compose files and .dockerignore."""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__", "scan", "RULES"]

from .engine import scan  # noqa: E402
from .rules import RULES  # noqa: E402
