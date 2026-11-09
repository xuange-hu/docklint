"""A miniature indentation-based YAML reader, for compose files only.

Adapted from the reader in `xuange-hu/civet`, trimmed to what compose files
use. Why not PyYAML: the whole point of this tool is to run in a slim build
container with no network, and compose files only need a narrow subset. Keeping
the reader in-house also means every scalar carries the 1-based line number it
came from, which is what turns a finding into evidence.

Supported subset:
  * block mappings and block sequences, arbitrarily nested
  * plain, single- and double-quoted scalars
  * block scalars ``|`` ``|-`` ``>`` ``>-``
  * flat flow collections ``[a, b]`` and ``{a: b}``
  * comments, blank lines, ``---`` markers

Deliberately unsupported: anchors, aliases, merge keys, multi-document
streams, tabs for indentation. Anchors matter in compose files (``x-common: &x``
is idiomatic), so ``loads`` reports them instead of silently merging: the
caller sees ``Compose.notes`` and the scan still runs on the literal values.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["L", "M", "S", "YamlError", "loads"]


class YamlError(ValueError):
    """Raised when a file is not valid in the supported subset."""


class S(str):
    """A scalar that remembers its source line."""

    line: int

    def __new__(cls, value: str = "", line: int = 0):  # returns an S instance
        obj = super().__new__(cls, value)
        obj.line = line
        return obj


class M(dict):
    """A mapping that remembers the line of every key."""

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.klines: dict[str, int] = {}

    def kline(self, key: str) -> int:
        return self.klines.get(key, self.line)


class L(list):
    """A sequence that remembers the line of every element."""

    def __init__(self, line: int = 0) -> None:
        super().__init__()
        self.line = line
        self.ilines: dict[int, int] = {}

    def iline(self, index: int) -> int:
        return self.ilines.get(index, self.line)


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "/": "/"}


def _unescape(text: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            out.append(_ESCAPES.get(text[i + 1], text[i + 1]))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _split_key(content: str) -> tuple[str, str] | None:
    """Split ``key: rest`` at the first structural colon (quote-aware)."""
    quote: str | None = None
    for idx, ch in enumerate(content):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            continue
        if ch == ":" and (idx + 1 == len(content) or content[idx + 1] in " \t"):
            return content[:idx].strip(), content[idx + 1 :].strip()
    return None


def _strip_comment(text: str) -> str:
    """Drop a trailing ``# comment`` from a plain scalar (quote-aware)."""
    quote: str | None = None
    out: list[str] = []
    for i, ch in enumerate(text):
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or text[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        inner = text[1:-1]
        return _unescape(inner) if text[0] == '"' else inner.replace("''", "'")
    return text


def _flow_scalar(token: str) -> Any:
    token = token.strip()
    if token in ("", "~", "null", "Null", "NULL"):
        return None
    if token in ("true", "True", "TRUE", "yes", "on"):
        return True
    if token in ("false", "False", "FALSE", "no", "off"):
        return False
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return _unquote(token)
    if token.startswith(("[", "{")):
        return _flow(token)
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _split_flow(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    cur: list[str] = []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts]


def _flow(text: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        out = L()
        for i, part in enumerate(_split_flow(text[1:-1])):
            out.append(_flow_scalar(part))
            out.ilines[i] = 0
        return out
    if text.startswith("{") and text.endswith("}"):
        out = M()
        for part in _split_flow(text[1:-1]):
            kv = _split_key(part)
            if kv is None:
                continue
            key, rest = kv
            key = _unquote(key)
            value = _flow_scalar(rest) if rest else None
            if isinstance(value, str) and not isinstance(value, S):
                value = S(value)
            out[key] = value
            out.klines[key] = 0
        return out
    # Not a balanced flow collection: hand the raw text back. Recursing into
    # _flow_scalar here loops forever on inputs like "[unclosed".
    return S(text)


class _Parser:
    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        self.i = 0

    def _skip_noise(self) -> None:
        while self.i < len(self.lines):
            s = self.lines[self.i].strip()
            if not s or s.startswith("#") or s in ("---", "..."):
                self.i += 1
                continue
            break

    def _cur(self) -> tuple[int, str] | None:
        self._skip_noise()
        if self.i >= len(self.lines):
            return None
        raw = self.lines[self.i]
        indent = len(raw) - len(raw.lstrip(" \t"))
        return indent, raw.strip()

    def _lineno(self) -> int:
        return self.i + 1

    def _indent_of(self, raw: str) -> int:
        return len(raw) - len(raw.lstrip(" \t"))

    def parse_document(self) -> Any:
        node = self.parse_node(0)
        return node if node is not None else M()

    def parse_node(self, indent: int) -> Any:
        cur = self._cur()
        if cur is None:
            return None
        ind, content = cur
        if ind < indent:
            return None
        if content == "-" or content.startswith("- "):
            return self.parse_seq(ind)
        if _split_key(content) is not None:
            return self.parse_map(ind)
        self.i += 1
        return S(_unquote(content), self._lineno() - 1)

    def parse_map(self, indent: int) -> M:
        out = M()
        first = True
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind, content = cur
            if ind < indent:
                break
            if ind > indent and first:
                break
            if content == "-" or content.startswith("- "):
                break
            kv = _split_key(content)
            if kv is None:
                raise YamlError(f"line {self._lineno()}: expected 'key: value', got {content!r}")
            key_raw, rest = kv
            rest = _strip_comment(rest)
            key = _unquote(key_raw)
            line = self._lineno()
            self.i += 1
            if rest.startswith(("|", ">")) and rest[:2].rstrip("+-") in ("|", ">"):
                out[key] = S(self._block_scalar(rest, indent), line)
            elif rest:
                out[key] = self._value(rest, line)
            else:
                child = self._child(indent, allow_indentless=True)
                out[key] = child if child is not None else None
            out.klines[key] = line
            out.line = out.line or line
            first = False
        return out

    def parse_seq(self, indent: int) -> L:
        out = L()
        idx = 0
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind, content = cur
            if ind != indent or not (content == "-" or content.startswith("- ")):
                break
            rest = _strip_comment(content[1:])
            offset = len(rest) - len(rest.lstrip(" \t"))
            child_indent = indent + 1 + offset
            line = self._lineno()
            self.i += 1
            item: Any
            if not rest.strip():
                item = self._child(indent)
            elif rest.strip().startswith(("{", "[")):
                item = self._value(rest.strip(), line)
                out.append(item)
                out.ilines[idx] = line
                out.line = out.line or line
                idx += 1
                continue
            else:
                kv = _split_key(rest.strip())
                if kv is not None:
                    self.lines[self.i - 1] = " " * child_indent + rest.strip()
                    self.i -= 1
                    item = self.parse_map(child_indent)
                else:
                    item = self._value(rest.strip(), line)
                    out.append(item)
                    out.ilines[idx] = line
                    out.line = out.line or line
                    idx += 1
                    continue
            out.append(item)
            out.ilines[idx] = line
            out.line = out.line or line
            idx += 1
        return out

    def _child(self, parent_indent: int, allow_indentless: bool = False) -> Any:
        """Parse the block nested under a ``key:`` line.

        YAML allows a block sequence to sit at the *same* indentation as the key
        that owns it ("indentless sequence"):

            build:
              args:
              - NODE_ENV=development
              context: backend

        Requiring a deeper indent here silently truncated the mapping at `args:`
        — which real compose files do constantly, and which made `context:` and
        `dockerfile:` invisible. Only mapping keys may claim an indentless
        sequence: inside a sequence item it would be the next item, not a child.
        """
        cur = self._cur()
        if cur is None:
            return None
        ind, content = cur
        indentless = (
            allow_indentless
            and ind == parent_indent
            and (content == "-" or content.startswith("- "))
        )
        if ind <= parent_indent and not indentless:
            return None
        if content == "-" or content.startswith("- "):
            return self.parse_seq(ind)
        if _split_key(content) is not None:
            return self.parse_map(ind)
        parts: list[str] = []
        while True:
            cur = self._cur()
            if cur is None:
                break
            ind2, content2 = cur
            if ind2 <= parent_indent:
                break
            parts.append(content2)
            self.i += 1
        return S(" ".join(parts), self._lineno())

    def _value(self, rest: str, line: int) -> Any:
        rest = _strip_comment(rest).strip()
        if rest.startswith(("[", "{")):
            buf = rest
            while buf.count("[") != buf.count("]") or buf.count("{") != buf.count("}"):
                self._skip_noise()
                if self.i >= len(self.lines):
                    break
                buf += " " + self.lines[self.i].strip()
                self.i += 1
            return _flow(buf)
        if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in "\"'":
            return S(_unquote(rest), line)
        value = _flow_scalar(rest)
        return value if not isinstance(value, str) else S(value, line)

    def _block_scalar(self, marker: str, parent_indent: int) -> str:
        style = marker[0]
        chomp = ""
        if len(marker) > 1 and marker[1] in "+-":
            chomp = marker[1]
        base: int | None = None
        for raw in self.lines[self.i :]:
            if not raw.strip():
                continue
            base = len(raw) - len(raw.lstrip(" \t"))
            break
        if base is None or base <= parent_indent:
            return ""
        body: list[str] = []
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if not raw.strip():
                body.append("")
                self.i += 1
                continue
            if self._indent_of(raw) < base:
                break
            body.append(raw[base:])
            self.i += 1
        while body and not body[-1]:
            body.pop()
        text = "\n".join(body) if style == "|" else " ".join(body)
        if chomp != "-":
            text += "\n"
        return text


_ANCHOR_RE = re.compile(r":\s*&[A-Za-z0-9_-]|^\s*&[A-Za-z0-9_-]")


def loads(text: str) -> Any:
    """Parse the first document of ``text`` into S/M/L structures."""
    text = text.replace("\t", "  ").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return M()
    return _Parser(text).parse_document()


def uses_anchors(text: str) -> bool:
    """True when the file relies on YAML anchors we cannot follow."""
    return bool(_ANCHOR_RE.search(text.replace("\r\n", "\n")))
