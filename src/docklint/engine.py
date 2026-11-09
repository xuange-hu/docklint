"""Discovery and orchestration: three passes, one result."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .checks_compose import check_compose
from .checks_cross import ComposeDoc, DockerfileDoc, check_cross
from .checks_dockerfile import check_dockerfile
from .compose import COMPOSE_FILENAMES, parse_compose
from .dockfile import parse_dockerfile
from .ignore import DockerIgnore
from .model import Finding, ScanResult

__all__ = ["scan", "discover"]

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".tox",
    "site-packages",
}
_IGNORE_FILE = ".dockerignore"


@dataclass
class Discovery:
    root: Path
    dockerfiles: list[Path] = field(default_factory=list)
    composes: list[Path] = field(default_factory=list)

    def files(self) -> list[Path]:
        return sorted(set(self.dockerfiles) | set(self.composes))


def _is_compose(name: str) -> bool:
    lower = name.lower()
    return lower in COMPOSE_FILENAMES or (
        lower.startswith(("docker-compose", "compose.")) and lower.endswith((".yml", ".yaml"))
    )


def _is_dockerfile(name: str) -> bool:
    lower = name.lower()
    return (
        lower == "dockerfile"
        or lower.startswith("dockerfile.")
        or lower.endswith(".dockerfile")
        or lower.startswith("dockerfile-")
    )


def discover(path: Path | str) -> Discovery:
    """Find Dockerfiles and compose files under ``path``."""
    target = Path(path)
    if target.is_file():
        name = target.name.lower()
        disc = Discovery(root=target.parent)
        if _is_dockerfile(target.name):
            disc.dockerfiles.append(target)
        elif _is_compose(name):
            disc.composes.append(target)
        return disc

    disc = Discovery(root=target)
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in sorted(filenames):
            full = Path(dirpath) / filename
            lower = filename.lower()
            if _is_dockerfile(filename):
                disc.dockerfiles.append(full)
            elif lower in COMPOSE_FILENAMES:
                disc.composes.append(full)
    return disc


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _read(path: Path) -> str:
    # Dockerfiles are UTF-8 by convention; a stray byte must not abort a scan.
    return path.read_text(encoding="utf-8", errors="replace")


def scan(
    path: Path | str,
    *,
    ignore_rules: set[str] | None = None,
    ignore_groups: set[str] | None = None,
    min_severity: str | None = None,
    severity_rank: dict[str, int] | None = None,
) -> ScanResult:
    """Run all three passes over ``path``."""
    disc = discover(path)
    root = disc.root
    result = ScanResult(root=str(root))

    docs: list[DockerfileDoc] = []
    for file_path in disc.dockerfiles:
        display = _rel(file_path, root)
        try:
            df = parse_dockerfile(_read(file_path), display)
        except OSError as exc:
            result.skipped.append(f"{display}: {exc}")
            continue
        context = file_path.parent
        ignore_path = context / _IGNORE_FILE
        ignore = (
            DockerIgnore.parse(_read(ignore_path), _rel(ignore_path, root))
            if ignore_path.is_file()
            else DockerIgnore.empty()
        )
        docs.append(DockerfileDoc(df=df, context=context, ignore=ignore))
        result.files.append(display)
        for err in df.errors:
            result.skipped.append(f"{display}: {err}")

    cdocs: list[ComposeDoc] = []
    for file_path in disc.composes:
        display = _rel(file_path, root)
        try:
            compose = parse_compose(_read(file_path), display)
        except OSError as exc:
            result.skipped.append(f"{display}: {exc}")
            continue
        cdocs.append(ComposeDoc(compose=compose, base=file_path.parent))
        result.files.append(display)
        for err in compose.errors:
            result.skipped.append(f"{display}: {err}")
        result.skipped.extend(f"{display}: {note}" for note in compose.notes)

    findings: list[Finding] = []
    for doc in docs:
        findings.extend(check_dockerfile(doc.df, doc.context))
    for cdoc in cdocs:
        findings.extend(check_compose(cdoc.compose, cdoc.base))
    findings.extend(check_cross(docs, cdocs))

    findings = _dedupe(findings)
    findings = _filter(findings, ignore_rules or set(), ignore_groups or set(), min_severity, severity_rank)
    result.findings = findings
    result.files = sorted(set(result.files))
    return result


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per (rule, path, line, detail).

    Two passes legitimately agree — a secret COPYed in is both DRL006 and, when
    compose mounts the same path, part of a DRX004. Identical findings are not:
    the second pass over a multi-stage file used to double-report DRL003.
    """
    seen: set[tuple[str, str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule.id, f.path, f.line, f.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _filter(
    findings: list[Finding],
    ignore_rules: set[str],
    ignore_groups: set[str],
    min_severity: str | None,
    severity_rank: dict[str, int] | None,
) -> list[Finding]:
    ignore_rules = {r.upper() for r in ignore_rules}
    out: list[Finding] = []
    for f in findings:
        if f.rule.id in ignore_rules or f.rule.group in ignore_groups:
            continue
        if (
            min_severity
            and severity_rank
            and severity_rank.get(f.rule.severity, -1) < severity_rank.get(min_severity, 0)
        ):
            continue
        out.append(f)
    return out
