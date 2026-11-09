"""Shared lexical patterns.

Kept in one place so a Dockerfile rule and a compose rule cannot drift apart on
what "looks like a credential". The two lists have different jobs: paths are
about *where a file lives*, names are about *what a variable is called*.
"""

from __future__ import annotations

import re

__all__ = [
    "SECRET_PATH_RE",
    "SECRET_NAME_RE",
    "VAR_RE",
    "ENV_EXAMPLE_RE",
    "is_secret_path",
    "is_secret_name",
    "has_variable",
    "rm_rf_variable",
    "pipes_to_shell",
]

# Directories and file names that carry credentials. `\.env` matches `.env` and
# `.env.local`; `.env.example` is explicitly excluded because committing it is
# the recommended practice.
SECRET_PATH_RE = re.compile(
    r"(^|/)("
    r"\.ssh|\.aws|\.gnupg|\.docker/config\.json|\.kube/config|\.netrc|\.npmrc|\.pypirc"
    r"|id_rsa|id_dsa|id_ecdsa|id_ed25519"
    r"|credentials|secrets?\.(ya?ml|json|txt)"
    r"|\.env(\.[A-Za-z0-9_-]+)?"
    r")(/|$)",
    re.IGNORECASE,
)
SECRET_EXT_RE = re.compile(r"\.(pem|key|pfx|p12|jks|keystore|ppk)$", re.IGNORECASE)
ENV_EXAMPLE_RE = re.compile(r"\.(example|sample|template|dist)$", re.IGNORECASE)

SECRET_NAME_RE = re.compile(
    r"(password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key"
    r"|private[_-]?key|credential|auth[_-]?key|client[_-]?secret|signing[_-]?key)",
    re.IGNORECASE,
)

VAR_RE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")


def is_secret_path(path: str) -> bool:
    """True for paths that conventionally hold credentials."""
    text = path.replace("\\", "/")
    if ENV_EXAMPLE_RE.search(text):
        return False
    return bool(SECRET_PATH_RE.search(text) or SECRET_EXT_RE.search(text))


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME_RE.search(name))


def has_variable(text: str) -> bool:
    return bool(VAR_RE.search(text))


def pipes_to_shell(text: str) -> bool:
    """`curl ... | sh` and its many spellings."""
    return bool(
        re.search(
            r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?([a-z]*sh|python[0-9.]*|perl|ruby)\b",
            text,
            re.IGNORECASE,
        )
    )


def rm_rf_variable(text: str) -> str:
    """Return the offending argument of ``rm -rf $VAR`` or "" when safe.

    The dangerous shape is specifically a *variable* as the target. A literal
    path — including `/var/lib/apt/lists/*` — is not this bug, and flagging it
    would train users to ignore the rule.
    """
    for match in re.finditer(r"\brm\s+([^&|;\n]*)", text):
        chunk = match.group(1)
        tokens = chunk.split()
        flags = [t for t in tokens if t.startswith("-")]
        if not flags:
            continue
        letters = "".join(f.lstrip("-") for f in flags).lower()
        if "r" not in letters or "f" not in letters:
            continue
        args = [t for t in tokens if not t.startswith("-")]
        if not args:
            continue
        arg = args[0].strip("\"'")
        if arg.startswith("$") or arg.startswith('"$'):
            return arg
    return ""
