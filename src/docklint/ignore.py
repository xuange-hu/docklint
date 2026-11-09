"""``.dockerignore`` matcher.

This exists for one cross-file rule — "the Dockerfile copies a path that
``.dockerignore`` excludes, so the build will fail with a confusing
``not found``" — plus the reverse, "nothing excludes ``.git``, so the whole
history can end up in a layer". Both need real matching, not ``str.startswith``.

Semantics implemented (Docker's, as documented):
  * one pattern per line, ``#`` comments, blank lines ignored
  * ``!`` prefix re-includes a path excluded by an earlier pattern
  * later patterns win (last match decides)
  * ``*`` does not cross ``/``, ``**`` does
  * a pattern without ``/`` matches at any depth
  * a directory pattern excludes everything below it
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["DockerIgnore", "pattern_to_regex"]


def _translate(component: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(component):
        ch = component[i]
        if ch == "*":
            if component[i : i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            end = component.find("]", i + 1)
            if end == -1:
                out.append(re.escape(ch))
            else:
                body = component[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end + 1
                continue
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def pattern_to_regex(pattern: str) -> str:
    """Compile one dockerignore pattern into a regex source string.

    A pattern with no ``/`` is anchored at every depth, which is why ``*.md``
    excludes ``docs/a.md``. That is the documented behaviour and the single
    most common source of "why is my file missing" confusion.
    """
    text = pattern.strip().strip("/")
    if not text:
        return r"(?!)"  # never matches
    if text == "**":
        return ".*"
    prefix = ""
    # A leading `**/` means "zero or more directories", so it has to match a
    # path at the context root as well. `(?:.*/)?` does that; `.*/` would
    # require at least one separator and break the `**/*.log` case.
    while text.startswith("**/"):
        prefix += "(?:.*/)?"
        text = text[3:]
    parts = text.split("/")
    body = ""
    for i, part in enumerate(parts):
        if part == "**":
            if body and not body.endswith("/"):
                body += "/"
            body += "(?:.*/)?"
            continue
        # `**` already ends in its own separator, so the next component must not
        # prepend another one (`a/**/b` -> `a/(?:.*/)?b`).
        if body and not body.endswith("/") and parts[i - 1] != "**":
            body += "/"
        body += _translate(part)
    if prefix:
        return prefix + body + r"(?:/.*)?"
    if "/" not in text:
        return rf"(?:.*/)?{body}(?:/.*)?"
    return rf"{body}(?:/.*)?"


@dataclass
class DockerIgnore:
    patterns: list[tuple[str, bool]] = field(default_factory=list)  # (pattern, negated)
    source: str = ""

    @classmethod
    def empty(cls) -> DockerIgnore:
        return cls()

    @classmethod
    def parse(cls, text: str, source: str = ".dockerignore") -> DockerIgnore:
        patterns: list[tuple[str, bool]] = []
        for raw in text.replace("\r\n", "\n").split("\n"):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:].strip()
            if not line:
                continue
            patterns.append((line, negated))
        return cls(patterns=patterns, source=source)

    @property
    def is_empty(self) -> bool:
        return not self.patterns

    def matches(self, relpath: str) -> bool:
        """True when ``relpath`` ends up excluded."""
        path = relpath.replace("\\", "/")
        # lstrip("./") would eat the leading dot of `.env` — the charset form of
        # this call strips *characters*, not a prefix. Strip the prefix only.
        while path.startswith("./"):
            path = path[2:]
        path = path.lstrip("/")
        if not path:
            return False
        excluded = False
        for pattern, negated in self.patterns:
            if re.fullmatch(pattern_to_regex(pattern), path):
                excluded = not negated
        return excluded

    def covers_dir(self, name: str) -> bool:
        """True when a top-level entry like ``.git`` is excluded."""
        return self.matches(name) or self.matches(name + "/x")
