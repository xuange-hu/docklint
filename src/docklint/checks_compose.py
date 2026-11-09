"""Pass 2: every check that needs only the compose file."""

from __future__ import annotations

from pathlib import Path

from .compose import Compose, Mount, Port
from .model import Finding
from .patterns import is_secret_name
from .rules import RULES

__all__ = ["check_compose"]

_DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "DAC_READ_SEARCH",
    "DAC_OVERRIDE",
    "ALL",
}
_SENSITIVE_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/lib/docker",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev",
)


def _f(rule_id: str, compose: Compose, line: int, detail: str, service: str) -> Finding:
    return Finding(
        rule=RULES[rule_id],
        path=compose.path,
        line=line,
        snippet=_snippet(compose, line),
        detail=detail,
        service=service,
    )


def _snippet(compose: Compose, line: int) -> str:
    raw = compose.text.splitlines()
    if 1 <= line <= len(raw):
        text = raw[line - 1].strip()
        return text[:120]
    return ""


def check_compose(compose: Compose, base_dir: Path | None = None) -> list[Finding]:
    out: list[Finding] = []
    base = base_dir or Path(".")
    for name in compose.service_names():
        svc = compose.service(name)
        if svc is None:
            continue
        out.extend(_check_service(compose, name, svc))
        for mount in compose.mounts(name):
            out.extend(_check_mount(compose, name, mount))
        for port in compose.ports(name):
            out.extend(_check_port(compose, name, port))
        out.extend(_check_env(compose, name, svc))
        out.extend(_check_image(compose, name, svc))
        out.extend(_check_env_file(compose, name, svc, base))
        if "read_only" not in svc or not svc.get("read_only"):
            out.append(
                _f(
                    "DRC010",
                    compose,
                    svc.kline("read_only") or compose.service_line(name) or svc.line,
                    f"service `{name}` has a writable root filesystem",
                    name,
                )
            )
        if "restart" not in svc:
            out.append(
                _f(
                    "DRC011",
                    compose,
                    compose.service_line(name) or svc.line,
                    f"service `{name}` has no restart policy",
                    name,
                )
            )
    return out


def _check_service(compose: Compose, name: str, svc) -> list[Finding]:
    out: list[Finding] = []
    if svc.get("privileged") is True:
        out.append(
            _f(
                "DRC001",
                compose,
                svc.kline("privileged") or svc.line,
                f"service `{name}` is privileged: all capabilities and host devices",
                name,
            )
        )
    if str(svc.get("network_mode") or "").lower() == "host":
        out.append(
            _f(
                "DRC002",
                compose,
                svc.kline("network_mode") or svc.line,
                f"service `{name}` uses the host network namespace",
                name,
            )
        )
    for key in ("pid", "ipc", "uts", "userns_mode"):
        value = str(svc.get(key) or "").lower()
        if value == "host":
            out.append(
                _f(
                    "DRC003",
                    compose,
                    svc.kline(key) or svc.line,
                    f"service `{name}` sets {key}: host, sharing a host namespace",
                    name,
                )
            )

    caps = svc.get("cap_add")
    if isinstance(caps, (list, tuple)):
        bad = [str(c).upper() for c in caps if str(c).upper() in _DANGEROUS_CAPS]
        if bad:
            out.append(
                _f(
                    "DRC005",
                    compose,
                    svc.kline("cap_add") or svc.line,
                    f"service `{name}` adds {', '.join(bad)}, which defeats containment",
                    name,
                )
            )

    opts = svc.get("security_opt")
    joined = " ".join(str(o) for o in opts) if isinstance(opts, (list, tuple)) else str(opts or "")
    if "no-new-privileges" not in joined:
        out.append(
            _f(
                "DRC006",
                compose,
                svc.kline("security_opt") or compose.service_line(name) or svc.line,
                f"service `{name}` does not set no-new-privileges",
                name,
            )
        )
    return out


def _check_mount(compose: Compose, name: str, mount: Mount) -> list[Finding]:
    source = mount.source.replace("\\", "/")
    if not source:
        return []
    if "docker.sock" in source:
        return [
            _f(
                "DRC004",
                compose,
                mount.line,
                f"service `{name}` mounts the Docker socket; that is root on the host",
                name,
            )
        ]
    for sensitive in _SENSITIVE_HOST_PATHS:
        if source == sensitive or source.startswith(sensitive + "/"):
            return [
                _f(
                    "DRC004",
                    compose,
                    mount.line,
                    f"service `{name}` bind-mounts host path `{source}`",
                    name,
                )
            ]
    if source.startswith("~/"):
        return [
            _f(
                "DRC004",
                compose,
                mount.line,
                f"service `{name}` bind-mounts a home directory path `{source}`",
                name,
            )
        ]
    return []


def _check_port(compose: Compose, name: str, port: Port) -> list[Finding]:
    if not port.published or not port.publishes_all_interfaces:
        return []
    return [
        _f(
            "DRC008",
            compose,
            port.line,
            f"service `{name}` publishes {port.published} on every interface (0.0.0.0)",
            name,
        )
    ]


def _check_env(compose: Compose, name: str, svc) -> list[Finding]:
    out: list[Finding] = []
    env = compose.environment(name)
    for key, (value, line) in env.items():
        if not value or value.startswith(("${", "$")):
            continue
        # Docker's `*_FILE` convention means "the value is a path to a secret",
        # which is the *correct* way to do it. `MYSQL_ROOT_PASSWORD_FILE=
        # /run/secrets/db-password` tripped this rule on half of a real corpus.
        if key.upper().endswith("_FILE"):
            continue
        if "/" in value or value.startswith("."):
            continue
        if is_secret_name(key):
            out.append(
                _f(
                    "DRC007",
                    compose,
                    line or svc.line,
                    f"service `{name}` sets {key} to a literal value",
                    name,
                )
            )
            break
    return out


def _check_image(compose: Compose, name: str, svc) -> list[Finding]:
    image = svc.get("image")
    if not image:
        return []
    text = str(image)
    if "@" in text:
        return []
    tag = ""
    last = text.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
    if tag.lower() == "latest":
        detail = f"service `{name}` uses `{text}` (:latest)"
    elif not tag:
        detail = f"service `{name}` uses `{text}` with no tag, which means :latest"
    else:
        return []
    return [_f("DRC009", compose, svc.kline("image") or svc.line, detail, name)]


def _check_env_file(compose: Compose, name: str, svc, base: Path) -> list[Finding]:
    raw = svc.get("env_file")
    if raw is None:
        return []
    entries = raw if isinstance(raw, (list, tuple)) else [raw]
    out: list[Finding] = []
    for entry in entries:
        if hasattr(entry, "get"):  # long form: {path: x, required: false}
            required = entry.get("required", True)
            path_value = entry.get("path")
        else:
            required = True
            path_value = entry
        if path_value is None or not required:
            continue
        target = base / str(path_value)
        if not target.exists():
            line = svc.kline("env_file") or svc.line
            out.append(
                _f(
                    "DRC012",
                    compose,
                    line,
                    f"service `{name}` reads env_file `{path_value}`, which does not exist",
                    name,
                )
            )
            break
    return out
