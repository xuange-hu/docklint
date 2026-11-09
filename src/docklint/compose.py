"""Compose-file model: services, ports, mounts, environment — with line numbers.

The reader gives back plain ``S``/``M``/``L`` nodes. This module turns the two
shapes that compose writes in many different ways (ports and volumes) into one
normalised record each, so the rules never have to care whether the author
wrote ``"8080:80"``, ``"127.0.0.1:8080:80"`` or the long ``{target: 80}`` form.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .yamlread import L, M, S, YamlError, loads, uses_anchors

__all__ = [
    "Compose",
    "Port",
    "Mount",
    "parse_compose",
    "parse_port",
    "parse_mount",
    "service_env",
    "as_mapping",
    "as_list",
]

COMPOSE_FILENAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
)


@dataclass
class Port:
    """One published port, normalised."""

    raw: str
    line: int
    host_ip: str = ""
    published: str = ""
    target: str = ""
    protocol: str = "tcp"

    @property
    def publishes_all_interfaces(self) -> bool:
        """A port with no host IP is bound on 0.0.0.0 by default."""
        return self.host_ip in ("", "0.0.0.0", "::", "[::]")


@dataclass
class Mount:
    """One volume entry, normalised."""

    raw: str
    line: int
    type: str = "volume"
    source: str = ""
    target: str = ""
    read_only: bool = False


@dataclass
class Compose:
    path: str
    root: M
    text: str = ""
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def services(self) -> dict[str, Any]:
        raw = self.root.get("services")
        return dict(raw) if isinstance(raw, dict) else {}

    def service(self, name: str) -> M | None:
        value = self.services.get(name)
        return value if isinstance(value, M) else None

    def service_names(self) -> list[str]:
        return list(self.services.keys())

    def service_line(self, name: str) -> int:
        """The line where ``name:`` is declared under ``services:``.

        Needed as an evidence anchor when a rule fires on a *missing* key — a
        finding about an absent `security_opt` must point at the service, not at
        whatever key happened to come first in the mapping.
        """
        services = self.root.get("services")
        if isinstance(services, M) and name in services:
            return services.kline(name)
        return 0

    def ports(self, name: str) -> list[Port]:
        svc = self.service(name)
        if not svc:
            return []
        return [parse_port(item, svc.line) for item in as_list(svc.get("ports"), svc)]

    def mounts(self, name: str) -> list[Mount]:
        svc = self.service(name)
        if not svc:
            return []
        return [parse_mount(item, svc.line) for item in as_list(svc.get("volumes"), svc)]

    def environment(self, name: str) -> dict[str, tuple[str, int]]:
        svc = self.service(name)
        if not svc:
            return {}
        return service_env(svc)

    def build_spec(self, name: str) -> tuple[str, str] | None:
        """(context, dockerfile) for a service that builds, else None."""
        svc = self.service(name)
        if not svc or "build" not in svc:
            return None
        build = svc.get("build")
        if isinstance(build, M):
            context = str(build.get("context") or ".")
            dockerfile = str(build.get("dockerfile") or "Dockerfile")
            return context, dockerfile
        if build is None:
            return ".", "Dockerfile"
        return str(build), "Dockerfile"


def as_list(value: Any, parent: M | None = None) -> list[Any]:
    """Coerce a node to a list, keeping empty/absent distinct from one item."""
    if isinstance(value, L):
        return list(value)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def parse_port(item: Any, default_line: int = 0) -> Port:
    """Normalise any compose port form."""
    if isinstance(item, dict):
        line = (item.kline("target") if isinstance(item, M) else 0) or default_line
        return Port(
            raw=_render_map(item),
            line=line,
            host_ip=str(item.get("host_ip") or ""),
            published=str(item.get("published") or ""),
            target=str(item.get("target") or ""),
            protocol=str(item.get("protocol") or "tcp"),
        )
    if isinstance(item, int):
        return Port(raw=str(item), line=default_line, target=str(item))
    text = str(item if not isinstance(item, S) else item)
    line = getattr(item, "line", 0) or default_line
    protocol = "tcp"
    body = text
    if "/" in body:
        body, protocol = body.rsplit("/", 1)
    parts = body.split(":")
    host_ip = published = ""
    if len(parts) == 1:
        target = parts[0]
    elif len(parts) == 2:
        published, target = parts
    else:
        host_ip = ":".join(parts[:-2])
        published, target = parts[-2], parts[-1]
    return Port(
        raw=text,
        line=line,
        host_ip=host_ip,
        published=published,
        target=target,
        protocol=protocol,
    )


def parse_mount(item: Any, default_line: int = 0) -> Mount:
    """Normalise short and long volume syntax.

    Short syntax ``src:dst:ro`` is ambiguous on Windows-style paths, but compose
    files in the wild use POSIX paths; splitting from the right keeps
    ``C:\\data`` intact poorly on purpose — a path that starts with a drive
    letter is treated as one token and never mangled into a bogus target.
    """
    if isinstance(item, dict):
        line = (item.kline("target") if isinstance(item, M) else 0) or default_line
        source = str(item.get("source") or "")
        target = str(item.get("target") or "")
        kind = str(item.get("type") or ("bind" if source.startswith(("/", ".")) else "volume"))
        read_only = bool(item.get("read_only"))
        return Mount(
            raw=_render_map(item),
            line=line,
            type=kind,
            source=source,
            target=target,
            read_only=read_only,
        )
    text = str(item)
    line = getattr(item, "line", 0) or default_line
    parts = text.split(":")
    read_only = False
    if len(parts) >= 3 and parts[-1] in ("ro", "rw", "z", "Z", "cached", "delegated", "consistent"):
        read_only = parts[-1] == "ro"
        parts = parts[:-1]
    if len(parts) == 1:
        return Mount(raw=text, line=line, type="volume", target=parts[0])
    source = ":".join(parts[:-1])
    target = parts[-1]
    kind = "bind" if source.startswith(("/", ".", "~")) else "volume"
    return Mount(raw=text, line=line, type=kind, source=source, target=target, read_only=read_only)


def service_env(svc: M) -> dict[str, tuple[str, int]]:
    """Environment as ``{name: (value, line)}``.

    Both compose forms are accepted: a mapping and a list of ``K=V`` strings.
    A bare name in list form (``- PASSWORD``) means "inherit from the host",
    which is recorded with an empty value so the rules can tell "declared with
    no literal" from "declared with a literal secret".
    """
    env = svc.get("environment")
    out: dict[str, tuple[str, int]] = {}
    if isinstance(env, M):
        for key, value in env.items():
            line = env.kline(key)
            out[str(key)] = ("" if value is None else str(value), line)
    elif isinstance(env, L):
        for idx, item in enumerate(env):
            line = env.iline(idx)
            text = str(item)
            if "=" in text:
                key, value = text.split("=", 1)
                out[key.strip()] = (value, line)
            else:
                out[text.strip()] = ("", line)
    return out


def _render_map(node: M) -> str:
    parts = []
    for key in ("host_ip", "published", "target", "source", "type"):
        if key in node and node[key] not in (None, ""):
            parts.append(f"{key}: {node[key]}")
    return ", ".join(parts) if parts else str(node)


def parse_compose(text: str, path: str = "docker-compose.yml") -> Compose:
    """Parse a compose file, never raising: errors land in ``Compose.errors``."""
    errors: list[str] = []
    notes: list[str] = []
    try:
        root = loads(text)
    except YamlError as exc:
        return Compose(path=path, root=M(), text=text, errors=[str(exc)])
    if not isinstance(root, M):
        return Compose(
            path=path,
            root=M(),
            text=text,
            errors=[f"{path}: top level is {type(root).__name__}, expected a mapping"],
        )
    if uses_anchors(text):
        notes.append(
            "file uses YAML anchors/aliases; values are read literally and merged keys are not expanded"
        )
    compose = Compose(path=path, root=root, text=text, errors=errors, notes=notes)
    services = compose.root.get("services")
    if services is not None and not isinstance(services, dict):
        compose.errors.append(f"{path}: 'services' is not a mapping")
    return compose
