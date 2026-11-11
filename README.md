# docklint

[![CI](https://github.com/xuange-hu/docklint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/docklint/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-199%20passing-brightgreen)](https://github.com/xuange-hu/docklint/tree/main/tests)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/xuange-hu/docklint/blob/main/pyproject.toml)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/docklint/blob/main/pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**A container build auditor that reads three files at once.**

Most Dockerfile linters read one file. The expensive mistakes live in the gap
between three: the Dockerfile, `docker-compose.yml`, and `.dockerignore`.

```console
$ docklint scan .
Dockerfile
   6  DRL008  high     supply-chain
        | RUN curl -fsSL https://example.com/install.sh | sh
        -> a downloaded script is piped directly into an interpreter
        fix: Download, verify a checksum or signature, then execute the local file.
  10  DRL006  high     secrets
        | COPY id_rsa /app/id_rsa
        -> COPY copies credential path `id_rsa` into an image layer
  11  DRX001  high     build-integrity
        | COPY data/fixture.json /app/fixture.json
        -> `data/fixture.json` is excluded by .dockerignore, so COPY cannot find it

docker-compose.yml
  15  DRX006  high     privilege
        | user: root
        -> service `api` runs as root, overriding `USER 10001` in Dockerfile.service

summary: 2 critical, 16 high, 8 medium, 17 low, 10 info  worst=critical  risk=100/100
```

Zero dependencies. No network. Python 3.10+. 38 rules, three passes, SARIF out.

```console
# the path that works today (PyPI publishing is pending)
uvx --from "git+https://github.com/xuange-hu/docklint" docklint demo
uvx --from "git+https://github.com/xuange-hu/docklint" docklint scan .
```

---

## Contents

- [Why three passes](#why-three-passes)
- [Quick start](#quick-start)
- [GitHub Actions](#github-actions)
- [MCP server (Claude Code / Cursor / Cline)](#mcp-server-claude-code--cursor--cline)
- [Rules](#rules)
  - [Pass 1 — the Dockerfile (20)](#pass-1--the-dockerfile-20)
  - [Pass 2 — the compose file (12)](#pass-2--the-compose-file-12)
  - [Pass 3 — relations (6)](#pass-3--relations-6)
- [Design notes](#design-notes)
- [Development](#development)
- [License](#license)

## Why three passes

| Pass | Reads | Answers |
|---|---|---|
| 1 | `Dockerfile` | What goes into the image? |
| 2 | `docker-compose.yml` | What does the deployment grant? |
| 3 | all three files | Do they agree? |

Pass 3 is the point. Three examples that pass 1 and pass 2 both call clean:

**The COPY that cannot work.**
```dockerfile
COPY data/fixture.json /app/         # Dockerfile: legal
```
```gitignore
data/                                 # .dockerignore: excludes it
```
The build fails with `COPY failed: file not found` *after* the base image pull.
Neither file is wrong on its own. → `DRX001`

**The privilege drop that gets undone.**
```dockerfile
USER 10001                            # image is correct
```
```yaml
user: root                            # compose overrides it
```
Reviewers read the Dockerfile. The deployment runs as uid 0. → `DRX006`

**The secret that is in the layer forever.**
```dockerfile
COPY id_rsa /app/id_rsa               # baked in
```
```yaml
volumes: ["./id_rsa:/app/id_rsa:ro"]  # mount hides it at runtime
```
The mount makes the baked copy invisible — which is why nobody notices it is
still pullable from the registry. → `DRX004`

## Quick start

```console
$ git clone https://github.com/xuange-hu/docklint && cd docklint
$ pip install -e .
$ docklint demo                # a deliberately broken project, all 38 rules
$ docklint scan path/to/project
```

Exit codes: `0` clean or below the gate, `1` gate triggered, `2` usage error.

```console
$ docklint scan . --fail-on high            # default gate
$ docklint scan . --format json -o out.json
$ docklint scan . --format sarif -o docklint.sarif
$ docklint scan . --ignore DRL011 --ignore-group hygiene
$ docklint rules --pass 3                   # what only the cross-file pass sees
```

## GitHub Actions

```yaml
- name: Audit container build files
  run: |
    pip install "git+https://github.com/xuange-hu/docklint"
    docklint scan . --fail-on high --format sarif -o docklint.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: docklint.sarif
```

## MCP server (Claude Code / Cursor / Cline)

```json
{
  "mcpServers": {
    "docklint": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/xuange-hu/docklint[mcp]", "docklint-mcp"]
    }
  }
}
```

7 tools: `docklint_scan`, `docklint_explain`, `docklint_rules`, `docklint_sarif`,
`docklint_dockerfile` (stage/COPY/USER summary), `docklint_compose` (service
graph), `docklint_demo`.

## Rules

### Pass 1 — the Dockerfile (20)

| ID | Sev | Catches |
|---|---|---|
| DRL001 | medium | `FROM` with no tag, silently meaning `:latest` |
| DRL002 | low | `FROM ...:latest` |
| DRL003 | high | runtime stage never drops root (no `USER`, or `USER root`) |
| DRL004 | low | `ADD` where `COPY` was meant (ADD also extracts archives) |
| DRL005 | high | `ADD https://...` — unverified download at build time |
| DRL006 | high | `COPY`/`ADD` of `id_rsa`, `.ssh`, `.env`, `*.pem`, `credentials` |
| DRL007 | medium | `sudo` inside `RUN` |
| DRL008 | high | `curl ... \| sh` — remote script executed as root |
| DRL009 | low | `apt-get install` without `--no-install-recommends` |
| DRL010 | low | apt indexes not removed in the same `RUN` |
| DRL011 | low | `pip install` without `--no-cache-dir` |
| DRL012 | high | `ENV PASSWORD=...` — readable via `docker inspect` |
| DRL013 | high | `ARG SECRET=...` — visible in `docker history` |
| DRL014 | low | no `HEALTHCHECK` on a stage that publishes a port |
| DRL015 | low | `EXPOSE` below 1024 |
| DRL016 | medium | `ONBUILD` — invisible instructions in every child image |
| DRL017 | high | `rm -rf $VAR/` — becomes `rm -rf /` when `VAR` is empty |
| DRL018 | low | `CMD` in shell form (app is not PID 1, no SIGTERM) |
| DRL019 | medium | `ENTRYPOINT` in shell form |
| DRL020 | high | `COPY --from=<stage>` naming a stage that does not exist |

### Pass 2 — the compose file (12)

| ID | Sev | Catches |
|---|---|---|
| DRC001 | critical | `privileged: true` |
| DRC002 | high | `network_mode: host` |
| DRC003 | high | `pid/ipc/uts: host` |
| DRC004 | critical | bind mount of `/var/run/docker.sock`, `/etc`, `/root`, `/proc`, `/sys`, `/dev` |
| DRC005 | high | `cap_add: SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `ALL`, ... |
| DRC006 | low | `no-new-privileges` not set |
| DRC007 | high | literal secret in `environment` |
| DRC008 | medium | port published on `0.0.0.0` instead of loopback |
| DRC009 | low | floating image tag |
| DRC010 | info | writable root filesystem |
| DRC011 | info | no restart policy |
| DRC012 | medium | `env_file` pointing at a file that does not exist |

### Pass 3 — relations (6)

| ID | Sev | Catches |
|---|---|---|
| DRX001 | high | `COPY` source excluded by `.dockerignore` (build fails) |
| DRX002 | high | compose `build.dockerfile` missing on disk |
| DRX003 | high | two services (or a base + override file) publish the same host port |
| DRX004 | high | credential baked into a layer *and* mounted over at runtime |
| DRX005 | medium | `COPY .` with `.git` still in the build context |
| DRX006 | high | compose `user: root` over an image that dropped privileges |

`docklint rules` prints the same table with the full rationale and remediation.

## Design notes

**Not the same job as [layerlint](https://github.com/xuange-hu/layerlint).**
layerlint models what each layer adds — a `RUN rm -rf` cannot delete what an
earlier layer wrote. docklint never simulates layers; it reads three files and
reports where they contradict each other. Different question, different tool.


**Evidence, not opinions.** Every finding carries `path:line` and the original
source line. A finding you cannot re-check by hand is a rumour.

**Hand-written parsers, on purpose.** The Dockerfile reader keeps line numbers
across continuations and heredocs (a `FROM` inside `RUN <<EOF` must not invent a
stage). The compose reader is a YAML subset with per-scalar line numbers; anchors
are reported rather than silently mis-expanded.

**Severity is a claim about consequence, not style.** `critical` means host
compromise (docker socket, privileged). `info` means "you may have a reason" —
`read_only` and `restart` are informational because a writable filesystem or a
one-shot job is often correct.

**Validated against a corpus, and changed because of it.** A scan of
`docker/awesome-compose` (74 files) surfaced two things: an *indentless YAML
sequence* (`args:` followed by `- item` at the same indent) silently truncated
compose mappings, and a rule that flagged "published port not in `EXPOSE`" fired
on most real services for no reason — `EXPOSE` has no runtime effect. The parser
was fixed, and that rule was replaced with host-port collision detection, which
is a real `port is already allocated` failure. Both decisions are pinned by tests.

**Validated against a corpus, and changed because of it.** A scan of
`docker/awesome-compose` (74 files) surfaced two things: an *indentless YAML
sequence* (`args:` followed by `- item` at the same indent) silently truncated
compose mappings, and a rule that flagged "published port not in `EXPOSE`" fired
on most real services for no reason — `EXPOSE` has no runtime effect. The parser
was fixed, and that rule was replaced with host-port collision detection, which
is a real `port is already allocated` failure. Both decisions are pinned by tests.

**Noise is a bug.** Rules carry negative tests: `rm -rf /var/lib/apt/lists/*` is
not DRL017, `.env.example` is not DRL006, `--from=nginx:1.25` is not DRL020,
`apt-get install` with `--no-install-recommends` is not DRL009,
`MYSQL_ROOT_PASSWORD_FILE=/run/secrets/x` is not DRC007. Two of those go further
and read the evidence: DRL006 opens the copied `.npmrc` before accusing it (most
only set `registry=`), and DRC007 skips values that are paths. A linter that
cries wolf gets muted, and a muted linter is worse than none.

## Development

```console
$ pip install -e ".[mcp]"
$ python -m pytest -q          # tests own the coverage claim
$ docklint scan src            # dogfood: the repo audits itself clean
```

See [README_CN.md](README_CN.md) for the Chinese version.

## License

MIT.
