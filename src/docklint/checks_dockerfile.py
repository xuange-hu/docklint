"""Pass 1: every check that needs only the Dockerfile."""

from __future__ import annotations

import re
from pathlib import Path

from .dockfile import Dockerfile, Instruction, image_tag, is_json_form, parse_copy_args
from .model import Finding
from .patterns import has_variable, is_secret_name, is_secret_path, pipes_to_shell, rm_rf_variable
from .rules import RULES

__all__ = ["check_dockerfile"]

_URL_RE = re.compile(r"^(https?|git|ssh)://|^git@", re.IGNORECASE)
_STAGE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
_PRIVILEGED_USER = {"", "root", "0", "0:0", "root:root", "0:root", "root:0"}


def _finding(rule_id: str, df: Dockerfile, line: int, detail: str, stage: str = "") -> Finding:
    return Finding(
        rule=RULES[rule_id],
        path=df.path,
        line=line,
        snippet=df.snippet(line, 120),
        detail=detail,
        stage=stage or df.stage_of_line(line),
    )


def check_dockerfile(df: Dockerfile, context: Path | None = None) -> list[Finding]:
    out: list[Finding] = []
    out.extend(_check_stages(df))
    for instr in df.instructions():
        stage = df.stage_of_line(instr.line)
        out.extend(_check_instruction(df, instr, stage, context))
    out.extend(_check_final_stage(df))
    return out


def _check_stages(df: Dockerfile) -> list[Finding]:
    out: list[Finding] = []
    aliases = {st.alias.lower() for st in df.stages if st.alias}
    for st in df.stages:
        image = st.image
        if not image or image.startswith("--"):
            continue
        if image.lower() in aliases:
            # `FROM builder` re-uses a stage; nothing to pin.
            continue
        if image.lower() == "scratch":
            continue
        tag = image_tag(image)
        if "@" in image:
            continue
        if not tag:
            out.append(
                _finding(
                    "DRL001",
                    df,
                    st.line,
                    f"base image `{image}` has no tag, so it resolves to :latest",
                    stage=st.label,
                )
            )
        elif tag.lower() == "latest":
            out.append(
                _finding(
                    "DRL002",
                    df,
                    st.line,
                    f"base image `{image}` is pinned to :latest",
                    stage=st.label,
                )
            )
    return out


def _check_instruction(
    df: Dockerfile, instr: Instruction, stage: str, context: Path | None = None
) -> list[Finding]:
    out: list[Finding] = []
    name = instr.name

    if name == "USER":
        final = df.final_stage()
        # A builder stage that runs as root is normal — `apt-get install` needs
        # it. Only the runtime stage's USER decides what the deployed container
        # gets, so flagging the builder would be noise that teaches users to
        # ignore the rule.
        if final is not None and stage == final.label:
            value = instr.args.strip().lower()
            if value in _PRIVILEGED_USER:
                out.append(
                    _finding(
                        "DRL003", df, instr.line, f"final USER is `{instr.args.strip()}`", stage
                    )
                )

    if name in ("COPY", "ADD"):
        out.extend(_check_copy(df, instr, stage, context))

    if name == "RUN":
        out.extend(_check_run(df, instr, stage))

    if name == "ENV":
        for key, value in _env_pairs(instr.args):
            if is_secret_name(key) and value and not value.startswith("$"):
                out.append(
                    _finding(
                        "DRL012",
                        df,
                        instr.line,
                        f"ENV {key} holds a literal value that will be visible in the image config",
                        stage,
                    )
                )
                break
            if is_secret_name(key) and value.startswith("$"):
                # `ENV TOKEN=$TOKEN` still resolves to a literal at build time.
                out.append(
                    _finding(
                        "DRL012",
                        df,
                        instr.line,
                        f"ENV {key} is expanded at build time and recorded in the image",
                        stage,
                    )
                )
                break

    if name == "ARG":
        for key, value in _env_pairs(instr.args, arg_style=True):
            if is_secret_name(key):
                where = "with a value" if value else "with no default"
                out.append(
                    _finding(
                        "DRL013",
                        df,
                        instr.line,
                        f"ARG {key} {where}; build args are visible in `docker history`",
                        stage,
                    )
                )
                break

    if name == "EXPOSE":
        for token in instr.args.split():
            port = token.split("/", 1)[0]
            if port.isdigit() and int(port) < 1024:
                out.append(
                    _finding(
                        "DRL015",
                        df,
                        instr.line,
                        f"EXPOSE {token} needs CAP_NET_BIND_SERVICE",
                        stage,
                    )
                )
                break

    if name == "ONBUILD":
        out.append(
            _finding(
                "DRL016",
                df,
                instr.line,
                f"ONBUILD {instr.args.split(' ')[0] if instr.args else ''} runs inside every child build, invisibly",
                stage,
            )
        )

    if name == "CMD" and instr.args and not is_json_form(instr.args):
        out.append(
            _finding("DRL018", df, instr.line, "CMD is written in shell form", stage)
        )
    if name == "ENTRYPOINT" and instr.args and not is_json_form(instr.args):
        out.append(
            _finding("DRL019", df, instr.line, "ENTRYPOINT is written in shell form", stage)
        )
    return out


def _check_copy(
    df: Dockerfile, instr: Instruction, stage: str, context: Path | None = None
) -> list[Finding]:
    out: list[Finding] = []
    flags, parts = parse_copy_args(instr.args)
    if not parts:
        return out
    sources = parts[:-1] or parts

    if instr.name == "ADD":
        urls = [s for s in sources if _URL_RE.match(s)]
        if urls:
            out.append(
                _finding(
                    "DRL005",
                    df,
                    instr.line,
                    f"ADD fetches {urls[0]} at build time with no integrity check",
                    stage,
                )
            )
        else:
            out.append(
                _finding(
                    "DRL004",
                    df,
                    instr.line,
                    "ADD is used; it also extracts archives, so the build is not a plain copy",
                    stage,
                )
            )

    if "from" in flags:
        ref = flags["from"]
        aliases = {st.alias.lower() for st in df.stages if st.alias}
        image_like = "/" in ref or ":" in ref or "@" in ref
        if ref.isdigit() or ref.lower() in aliases or image_like:
            pass
        elif _STAGE_NAME_RE.match(ref):
            out.append(
                _finding(
                    "DRL020",
                    df,
                    instr.line,
                    f"COPY --from={ref} names no stage in this file",
                    stage,
                )
            )
        return out

    for src in sources:
        if _URL_RE.match(src) or has_variable(src):
            continue
        if is_secret_path(src) and _holds_credentials(context, src):
            out.append(
                _finding(
                    "DRL006",
                    df,
                    instr.line,
                    f"{instr.name} copies credential path `{src}` into an image layer",
                    stage,
                )
            )
            break
    return out


def _check_run(df: Dockerfile, instr: Instruction, stage: str) -> list[Finding]:
    out: list[Finding] = []
    text = instr.args
    body = text + ("\n" + "\n".join(h.body for h in instr.heredocs) if instr.heredocs else "")

    if re.search(r"\bsudo\b", body):
        out.append(_finding("DRL007", df, instr.line, "RUN invokes sudo", stage))

    if pipes_to_shell(body):
        out.append(
            _finding(
                "DRL008",
                df,
                instr.line,
                "a downloaded script is piped directly into an interpreter",
                stage,
            )
        )

    bad_rm = rm_rf_variable(body)
    if bad_rm:
        out.append(
            _finding(
                "DRL017",
                df,
                instr.line,
                f"`rm -rf {bad_rm}` deletes `/` when the variable is empty or unset",
                stage,
            )
        )

    installs = re.findall(r"apt-get\s+install|apt\s+install", body)
    if installs and "--no-install-recommends" not in body:
        out.append(
            _finding(
                "DRL009",
                df,
                instr.line,
                "apt-get install pulls recommended packages as well",
                stage,
            )
        )

    if re.search(r"\bapt(-get)?\s+update\b", body) and "rm -rf /var/lib/apt/lists" not in body:
        out.append(
            _finding(
                "DRL010",
                df,
                instr.line,
                "apt indexes are written but not removed in the same RUN",
                stage,
            )
        )

    if re.search(r"\bpip3?\s+install\b", body) and "--no-cache-dir" not in body:
        out.append(
            _finding(
                "DRL011",
                df,
                instr.line,
                "pip keeps its wheel cache inside the image layer",
                stage,
            )
        )
    return out


def _check_final_stage(df: Dockerfile) -> list[Finding]:
    out: list[Finding] = []
    final = df.final_stage()
    if final is None:
        return out
    names = [i.name for i in final.instructions]
    users = [i for i in final.instructions if i.name == "USER"]
    if not users:
        out.append(
            _finding(
                "DRL003",
                df,
                final.line,
                f"stage `{final.label}` never declares USER, so the entrypoint runs as uid 0",
                stage=final.label,
            )
        )
    if "HEALTHCHECK" not in names and (
        "EXPOSE" in names or "CMD" in names or "ENTRYPOINT" in names
    ):
        line = final.instructions[-1].line if final.instructions else final.line
        out.append(
            _finding(
                "DRL014",
                df,
                line,
                f"stage `{final.label}` serves traffic but declares no HEALTHCHECK",
                stage=final.label,
            )
        )
    return out


def _env_pairs(args: str, arg_style: bool = False) -> list[tuple[str, str]]:
    """Parse ``K=V K2=V2`` (ENV) and ``K[=V]`` (ARG) into pairs."""
    text = args.strip()
    if not text:
        return []
    if "=" not in text.split()[0]:
        # `ENV KEY value with spaces` legacy form.
        head, _, rest = text.partition(" ")
        return [(head, rest.strip())]
    pairs: list[tuple[str, str]] = []
    for token in _split_quoted(text):
        key, sep, value = token.partition("=")
        pairs.append((key.strip(), value.strip() if sep else ""))
    return pairs


def _split_quoted(text: str) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
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


_TOKEN_RE = re.compile(
    r"(_authToken|_auth|password|passwd|token|secret|api[_-]?key)", re.IGNORECASE
)


def _holds_credentials(context: Path | None, src: str) -> bool:
    """Does the copied file actually hold a credential?

    `.npmrc` is on the credential list by convention, and the convention is
    half wrong: most `.npmrc` files in the wild only set `registry=`. When the
    file is readable in the build context, open it and look for something that
    is actually a credential. Unreadable (directory, glob, missing file) keeps
    the conservative answer: flag it.
    """
    if context is None:
        return True
    candidate = context / src
    try:
        if not candidate.is_file():
            return True
        if candidate.stat().st_size > 256 * 1024:
            return True
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return bool(_TOKEN_RE.search(text))
