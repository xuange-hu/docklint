"""A hand-written Dockerfile reader that keeps line numbers.

Every other Dockerfile parser in this space answers "what does this file mean".
This one answers "where exactly did it say that", because a finding without a
line number is an opinion. That constraint shapes the whole design: no
normalisation that loses the source, no rewriting of continuations that
discards the original offset.

Supported: parser directives, comments, line continuations with a configurable
escape character, heredocs (``RUN <<EOF`` / ``COPY <<'EOF'``), JSON and shell
forms of CMD/ENTRYPOINT, multi-stage ``FROM ... AS name``, and the flags of
COPY/ADD (``--from``/``--chown``/``--chmod``/``--link``).

Not supported on purpose: variable expansion. ``COPY $SRC /app`` is reported as
an unresolved source rather than guessed at, and the cross-file rules skip it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

__all__ = [
    "Dockerfile",
    "Instruction",
    "Stage",
    "Heredoc",
    "parse_dockerfile",
    "parse_copy_args",
    "shell_split",
    "is_json_form",
]

_HEREDOC_RE = re.compile(r"<<(-?)(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z]+)\s*=\s*(\S+)\s*$")

# Docker accepts any casing for instructions, so the name is upper-cased before
# this check. Membership in the known set (rather than a regex) is what lets a
# stray prose line be reported instead of parsed as an instruction called THIS.
KNOWN_INSTRUCTIONS = {
    "ADD",
    "ARG",
    "CMD",
    "COPY",
    "ENTRYPOINT",
    "ENV",
    "EXPOSE",
    "FROM",
    "HEALTHCHECK",
    "LABEL",
    "MAINTAINER",
    "ONBUILD",
    "RUN",
    "SHELL",
    "STOPSIGNAL",
    "USER",
    "VOLUME",
    "WORKDIR",
}


@dataclass
class Heredoc:
    """An inline document fed to RUN/COPY via ``<<WORD``."""

    word: str
    body: str
    start_line: int
    end_line: int


@dataclass
class Instruction:
    name: str
    args: str
    line: int
    end_line: int
    raw: str
    heredocs: list[Heredoc] = field(default_factory=list)

    def flags(self) -> dict[str, str]:
        """Leading ``--flag=value`` / ``--flag`` tokens, in order."""
        out: dict[str, str] = {}
        for tok in self.args.split():
            if not tok.startswith("--"):
                break
            body = tok[2:]
            if "=" in body:
                k, v = body.split("=", 1)
                out[k.lower()] = v
            else:
                out[body.lower()] = ""
        return out

    def without_flags(self) -> str:
        rest = self.args
        while rest.startswith("--"):
            parts = rest.split(None, 1)
            rest = parts[1] if len(parts) > 1 else ""
        return rest


@dataclass
class Stage:
    index: int
    image: str
    alias: str
    line: int
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.alias or f"stage-{self.index}"


@dataclass
class Dockerfile:
    path: str
    text: str
    lines: list[str]
    preamble: list[Instruction] = field(default_factory=list)
    stages: list[Stage] = field(default_factory=list)
    escape: str = "\\"
    syntax: str = ""
    errors: list[str] = field(default_factory=list)

    # -- convenient views -------------------------------------------------
    def instructions(self) -> list[Instruction]:
        out = list(self.preamble)
        for st in self.stages:
            out.extend(st.instructions)
        return out

    def stage_of_line(self, line: int) -> str:
        current = ""
        for st in self.stages:
            if st.line <= line:
                current = st.label
        return current

    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None

    def stage_aliases(self) -> dict[str, Stage]:
        return {st.alias.lower(): st for st in self.stages if st.alias}

    def snippet(self, line: int, width: int = 0) -> str:
        """Original source line, used as evidence in every finding."""
        if 1 <= line <= len(self.lines):
            raw = self.lines[line - 1].strip()
            if width and len(raw) > width:
                return raw[: width - 1] + "\u2026"
            return raw
        return ""


def shell_split(text: str) -> list[str]:
    """Whitespace split that respects quotes.

    ``COPY "a b.txt" /dst`` must yield two tokens, not three; the naive split
    turns a legal filename with a space into a phantom source that the
    .dockerignore cross-check then reports as missing.
    """
    out: list[str] = []
    cur: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur.append(ch)
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def is_json_form(args: str) -> bool:
    """True for ``["exe","arg"]``. Used to tell exec form from shell form."""
    text = args.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return False
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(value, list)


def parse_copy_args(args: str) -> tuple[dict[str, str], list[str]]:
    """Return (flags, [src..., dest]) for COPY/ADD.

    Handles both ``COPY --from=build a b c /dst`` and the JSON array form.
    An empty list means the instruction is malformed; callers treat that as
    "nothing to check" rather than inventing a finding.
    """
    flags: dict[str, str] = {}
    rest = args.strip()
    while rest.startswith("--"):
        parts = rest.split(None, 1)
        tok = parts[0]
        body = tok[2:]
        if "=" in body:
            k, v = body.split("=", 1)
            flags[k.lower()] = v
        else:
            flags[body.lower()] = ""
        rest = parts[1] if len(parts) > 1 else ""
    if rest.strip().startswith("["):
        try:
            values = json.loads(rest.strip())
        except json.JSONDecodeError:
            values = None
        if isinstance(values, list) and all(isinstance(v, str) for v in values):
            return flags, [str(v) for v in values]
    return flags, shell_split(rest)


def parse_dockerfile(text: str, path: str = "Dockerfile") -> Dockerfile:
    """Parse ``text`` into a Dockerfile with per-instruction line numbers."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    df = Dockerfile(path=path, text=text, lines=lines)

    # Parser directives are only legal in the leading comment block.
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        m = _DIRECTIVE_RE.match(stripped)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2)
        if key == "escape" and value in ("\\", "`"):
            df.escape = value
        elif key == "syntax":
            df.syntax = value

    escape = df.escape
    i = 0
    current_stage: Stage | None = None
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        start = i
        parts: list[str] = [raw.strip()]
        j = i
        # Join continuations. Docker continues when the escape character is the
        # last non-space character of the physical line, and blank/comment lines
        # inside a continuation are dropped without ending it. `j` walks the
        # physical lines, so the heredoc scanner below starts at the right spot.
        while parts[-1].rstrip().endswith(escape):
            parts[-1] = parts[-1].rstrip()[: -len(escape)].rstrip()
            j += 1
            while j < len(lines) and (
                not lines[j].strip() or lines[j].strip().startswith("#")
            ):
                j += 1
            if j >= len(lines):
                break
            parts.append(lines[j].strip())
        joined = " ".join(p for p in parts if p)
        end = j
        i = j + 1

        if not joined:
            continue
        head, _, args = joined.partition(" ")
        name = head.upper()
        if name not in KNOWN_INSTRUCTIONS:
            df.errors.append(f"line {start + 1}: not an instruction: {joined[:60]!r}")
            continue

        instr = Instruction(
            name=name,
            args=args.strip(),
            line=start + 1,
            end_line=end + 1,
            raw=joined,
        )

        # Heredocs: consume the body so the delimiter lines are not parsed as
        # instructions. Without this, a `RUN <<EOF` block containing `FROM` on
        # its own line invents a stage that does not exist.
        if name in ("RUN", "COPY", "ADD"):
            for m in _HEREDOC_RE.finditer(instr.args):
                dash, word = m.group(1) == "-", m.group(3)
                body: list[str] = []
                body_start = i + 1
                while i < len(lines):
                    candidate = lines[i]
                    if candidate.strip() == word or (dash and candidate.strip().lstrip("\t") == word):
                        break
                    body.append(candidate)
                    i += 1
                body_end = i
                i += 1  # step over the delimiter
                instr.heredocs.append(
                    Heredoc(word=word, body="\n".join(body), start_line=body_start, end_line=body_end)
                )
                instr.end_line = body_end + 1

        if name == "FROM":
            image, alias = _parse_from(instr.args)
            current_stage = Stage(
                index=len(df.stages), image=image, alias=alias, line=instr.line
            )
            df.stages.append(current_stage)
            # FROM can also carry --platform; keep the flags out of the image
            # name so `:latest` detection does not read `--platform=...` as a tag.
            continue

        if current_stage is None:
            df.preamble.append(instr)
        else:
            current_stage.instructions.append(instr)

    return df


def _parse_from(args: str) -> tuple[str, str]:
    tokens = args.split()
    while tokens and tokens[0].startswith("--"):
        tokens.pop(0)
    if not tokens:
        return "", ""
    image = tokens[0]
    alias = ""
    if len(tokens) >= 3 and tokens[1].lower() == "as":
        alias = tokens[2]
    return image, alias


def image_tag(image: str) -> str:
    """Return the tag of ``image`` or "" when it has none.

    Digest pins count as pinned and are reported as ``@sha256:...``; the caller
    only needs to know whether a floating tag is in use.
    """
    if "@" in image:
        return ""  # digest-pinned, no floating tag
    name = image
    if "/" in name:
        last = name.rsplit("/", 1)[1]
        if ":" in last:
            return last.rsplit(":", 1)[1]
        return ""
    if ":" in name:
        return name.rsplit(":", 1)[1]
    return ""
