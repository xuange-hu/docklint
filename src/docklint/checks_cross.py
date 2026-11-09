"""Pass 3: relations between the Dockerfile, the compose file and .dockerignore.

This pass is the product. A Dockerfile-only linter can see `COPY app/ /app`;
only a reader that also knows .dockerignore can see that `app/` is ignored and
the build will fail. Same for "the image drops to USER 10001, then compose sets
`user: root`" — two correct files, one broken deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .compose import Compose
from .dockfile import Dockerfile, parse_copy_args
from .ignore import DockerIgnore
from .model import Finding
from .patterns import has_variable, is_secret_path
from .rules import RULES

__all__ = ["DockerfileDoc", "ComposeDoc", "check_cross"]

_URL_PREFIXES = ("http://", "https://", "git://", "git@")


@dataclass
class DockerfileDoc:
    df: Dockerfile
    context: Path
    ignore: DockerIgnore


@dataclass
class ComposeDoc:
    compose: Compose
    base: Path


def _f(rule_id: str, path: str, line: int, snippet: str, detail: str, **kw) -> Finding:
    return Finding(
        rule=RULES[rule_id],
        path=path,
        line=line,
        snippet=snippet,
        detail=detail,
        **kw,
    )


def check_cross(docs: list[DockerfileDoc], composes: list[ComposeDoc]) -> list[Finding]:
    out: list[Finding] = []
    for doc in docs:
        out.extend(_check_ignore(doc))
        out.extend(_check_context_git(doc))
    for cdoc in composes:
        siblings = [c for c in composes if c.base == cdoc.base]
        out.extend(_check_build_target(cdoc))
        out.extend(_check_port_collisions(cdoc, siblings))
        out.extend(_check_user_override(cdoc, docs))
        out.extend(_check_baked_secret(cdoc, docs))
    return out


def _check_ignore(doc: DockerfileDoc) -> list[Finding]:
    """DRX001 — COPY of a path .dockerignore removes from the context."""
    out: list[Finding] = []
    ignore = doc.ignore
    for instr in doc.df.instructions():
        if instr.name not in ("COPY", "ADD"):
            continue
        flags, parts = parse_copy_args(instr.args)
        if "from" in flags or not parts:
            continue
        for src in parts[:-1] or parts:
            if src.startswith(_URL_PREFIXES) or has_variable(src) or src in (".", "./"):
                continue
            if ignore.matches(src):
                out.append(
                    _f(
                        "DRX001",
                        doc.df.path,
                        instr.line,
                        doc.df.snippet(instr.line, 120),
                        f"`{src}` is excluded by {ignore.source}, so COPY cannot find it",
                        stage=doc.df.stage_of_line(instr.line),
                    )
                )
                break
    return out


def _check_context_git(doc: DockerfileDoc) -> list[Finding]:
    """DRX005 — a `COPY . .` with .git still inside the context."""
    copies_all = False
    first_line = 0
    for instr in doc.df.instructions():
        if instr.name not in ("COPY", "ADD"):
            continue
        flags, parts = parse_copy_args(instr.args)
        if "from" in flags or not parts:
            continue
        if parts[0] in (".", "./"):
            copies_all = True
            first_line = instr.line
            break
    if not copies_all:
        return []
    git_dir = doc.context / ".git"
    if not git_dir.exists() or not git_dir.is_dir():
        return []
    if doc.ignore.covers_dir(".git"):
        return []
    where = doc.ignore.source if not doc.ignore.is_empty else "no .dockerignore"
    return [
        _f(
            "DRX005",
            doc.df.path,
            first_line,
            doc.df.snippet(first_line, 120),
            f"`COPY .` includes .git ({where} does not exclude it)",
            stage=doc.df.stage_of_line(first_line),
        )
    ]


def _check_build_target(cdoc: ComposeDoc) -> list[Finding]:
    """DRX002 — compose points at a Dockerfile that is not on disk."""
    out: list[Finding] = []
    compose = cdoc.compose
    for name in compose.service_names():
        spec = compose.build_spec(name)
        if spec is None:
            continue
        context, dockerfile = spec
        ctx_dir = (cdoc.base / context).resolve()
        target = (ctx_dir / dockerfile).resolve()
        if not target.is_file():
            svc = compose.service(name)
            line = 0
            if svc is not None and isinstance(svc.get("build"), dict) and hasattr(svc.get("build"), "kline"):
                line = svc.get("build").kline("dockerfile")
            if not line:
                line = svc.kline("build") if svc is not None else 0
            out.append(
                _f(
                    "DRX002",
                    compose.path,
                    line,
                    _snippet(compose, line),
                    f"service `{name}` builds `{context}/{dockerfile}`, which is missing",
                    service=name,
                )
            )
    return out


def _resolve_dockerfile(cdoc: ComposeDoc, docs: list[DockerfileDoc], name: str) -> DockerfileDoc | None:
    spec = cdoc.compose.build_spec(name)
    if spec is None:
        return None
    context, dockerfile = spec
    target = (cdoc.base / context / dockerfile).resolve()
    for doc in docs:
        if (doc.context / Path(doc.df.path).name).resolve() == target:
            return doc
        if Path(doc.df.path).resolve() == target:
            return doc
    return None


def _check_port_collisions(cdoc: ComposeDoc, siblings: list[ComposeDoc]) -> list[Finding]:
    """DRX003 — two services publishing the same host port.

    Only compose files in the same directory can collide: compose merges base
    and override files by directory, and two different projects on one host are
    expected to reuse 8080. Checking the merged view is what makes this a pass-3
    rule rather than a per-file one.

    Note on what this rule deliberately does *not* check: whether a published
    port appears in `EXPOSE`. Real repositories publish ports the Dockerfile
    never EXPOSEs all the time (gunicorn on 8000 over an image that EXPOSEs
    5000), and EXPOSE has no runtime effect. Flagging that was noise, so the
    rule was replaced after a corpus run.
    """
    out: list[Finding] = []
    seen: dict[tuple[str, str, str], tuple[str, str]] = {}
    for other in siblings:
        for name in other.compose.service_names():
            for port in other.compose.ports(name):
                if not port.published:
                    continue
                key = (port.host_ip or "0.0.0.0", port.published, port.protocol)
                previous = seen.get(key)
                if previous is None:
                    seen[key] = (name, other.compose.path)
                    continue
                prev_service, prev_path = previous
                if prev_service == name and prev_path == other.compose.path:
                    continue
                out.append(
                    _f(
                        "DRX003",
                        other.compose.path,
                        port.line,
                        _snippet(other.compose, port.line),
                        f"host port {port.published} is already published by "
                        f"`{prev_service}` in {prev_path}",
                        service=name,
                    )
                )
    return out


def _check_user_override(cdoc: ComposeDoc, docs: list[DockerfileDoc]) -> list[Finding]:
    """DRX006 — compose sets user: root over an image that dropped privileges."""
    out: list[Finding] = []
    compose = cdoc.compose
    for name in compose.service_names():
        svc = compose.service(name)
        if svc is None:
            continue
        value = str(svc.get("user") or "").strip().lower()
        if value not in ("root", "0", "0:0"):
            continue
        doc = _resolve_dockerfile(cdoc, docs, name)
        if doc is None:
            continue
        final = doc.df.final_stage()
        if final is None:
            continue
        users = [i for i in final.instructions if i.name == "USER"]
        if not users:
            continue
        last = users[-1].args.strip().lower()
        if last in ("root", "0", "0:0"):
            continue
        out.append(
            _f(
                "DRX006",
                compose.path,
                svc.kline("user") or svc.line,
                _snippet(compose, svc.kline("user") or svc.line),
                f"service `{name}` runs as root, overriding `USER {users[-1].args.strip()}` "
                f"in {doc.df.path}",
                service=name,
            )
        )
    return out


def _check_baked_secret(cdoc: ComposeDoc, docs: list[DockerfileDoc]) -> list[Finding]:
    """DRX004 — a credential COPYed into the image and mounted over at runtime."""
    out: list[Finding] = []
    compose = cdoc.compose
    for name in compose.service_names():
        doc = _resolve_dockerfile(cdoc, docs, name)
        if doc is None:
            continue
        mounts = [m for m in compose.mounts(name) if m.target]
        if not mounts:
            continue
        for instr in doc.df.instructions():
            if instr.name not in ("COPY", "ADD"):
                continue
            flags, parts = parse_copy_args(instr.args)
            if "from" in flags or len(parts) < 2:
                continue
            dest = parts[-1].rstrip("/")
            secret_srcs = [
                s for s in parts[:-1] if is_secret_path(s) and not has_variable(s)
            ]
            if not secret_srcs:
                continue
            for mount in mounts:
                target = mount.target.rstrip("/")
                if target == dest or target.startswith(dest + "/") or dest == "/" + target.lstrip("/"):
                    out.append(
                        _f(
                            "DRX004",
                            doc.df.path,
                            instr.line,
                            doc.df.snippet(instr.line, 120),
                            f"`{secret_srcs[0]}` is baked into the image and replaced at runtime "
                            f"by the mount on `{mount.target}`",
                            stage=doc.df.stage_of_line(instr.line),
                            service=name,
                        )
                    )
                    break
    return out


def _snippet(compose: Compose, line: int) -> str:
    raw = compose.text.splitlines()
    if 1 <= line <= len(raw):
        return raw[line - 1].strip()[:120]
    return ""
