"""The rule registry.

Rule ids are stable and the pass number is part of the contract: pass 1 reads a
Dockerfile alone, pass 2 reads a compose file alone, pass 3 reads the relation
between them. Pass 3 is the reason this tool exists — every single-file linter
in this space stops at pass 2, and the expensive mistakes live in the gap.
"""

from __future__ import annotations

from .model import Rule

__all__ = ["RULES", "all_rules", "by_id", "groups"]


def _r(rid, title, severity, group, why, fix, pass_no=1, cwe="") -> Rule:
    return Rule(
        id=rid,
        title=title,
        severity=severity,
        group=group,
        why=why,
        fix=fix,
        pass_no=pass_no,
        cwe=cwe,
    )


_RULE_LIST = [
    # -- pass 1: the Dockerfile on its own --------------------------------
    _r(
        "DRL001",
        "Base image has no tag",
        "medium",
        "image",
        "An untagged FROM resolves to :latest, so the same Dockerfile builds a "
        "different image next week. That defeats reproducibility and silently "
        "imports new upstream CVEs.",
        "Pin a version (node:22.11.0-slim) or, better, a digest (node@sha256:...).",
    ),
    _r(
        "DRL002",
        "Base image pinned to :latest",
        "low",
        "image",
        ":latest is a moving target: two builds of one commit can differ, which "
        "makes incident review impossible.",
        "Replace :latest with a version tag or a digest.",
    ),
    _r(
        "DRL003",
        "Container runs as root",
        "high",
        "privilege",
        "With no USER, the process runs as uid 0. Any container escape or "
        "application RCE then lands with root inside the namespace and makes "
        "host-level escalation materially easier.",
        "Create an unprivileged user and switch to it: "
        "`RUN useradd -r -u 10001 app` then `USER 10001`.",
    ),
    _r(
        "DRL004",
        "ADD used instead of COPY",
        "low",
        "filesystem",
        "ADD silently extracts local tarballs and accepts remote URLs, so the "
        "build does something other than copy. That surprises reviewers and "
        "breaks the audit trail.",
        "Use COPY; unpack archives explicitly when you actually want that.",
    ),
    _r(
        "DRL005",
        "ADD downloads a remote URL",
        "high",
        "supply-chain",
        "A remote URL in ADD is fetched at build time with no checksum and no "
        "signature check; whatever the host serves is what ends up in the image.",
        "Download in a RUN step, verify a SHA-256, then COPY the verified file.",
        cwe="CWE-494",
    ),
    _r(
        "DRL006",
        "Build context copies credential material",
        "high",
        "secrets",
        "The copied file is baked into an image layer. Deleting it in a later "
        "RUN does not help: layers are additive and the file stays in the "
        "history, readable by anyone who can pull the image.",
        "Mount the credential at runtime, or pass it as a BuildKit secret "
        "(`RUN --mount=type=secret`).",
        cwe="CWE-538",
    ),
    _r(
        "DRL007",
        "sudo inside RUN",
        "medium",
        "privilege",
        "Build steps already run as root; sudo adds a setuid binary to the "
        "image and signals that the author expected an unprivileged shell. "
        "Both are wrong in a container.",
        "Drop sudo; if a step needs another user, use `USER` or `su-exec`.",
    ),
    _r(
        "DRL008",
        "Download piped straight into a shell",
        "high",
        "supply-chain",
        "`curl ... | sh` executes whatever the server returns, at build time, "
        "with no integrity check. A compromised mirror or a typo'd domain runs "
        "arbitrary code as root.",
        "Download, verify a checksum or signature, then execute the local file.",
        cwe="CWE-494",
    ),
    _r(
        "DRL009",
        "apt-get install without --no-install-recommends",
        "low",
        "hygiene",
        "Recommended packages pull in documentation, editors and sometimes "
        "daemons you never use. They enlarge the image and widen the CVE surface "
        "for no functional gain.",
        "Add --no-install-recommends and install only what you need.",
    ),
    _r(
        "DRL010",
        "apt lists left in the layer",
        "low",
        "hygiene",
        "`apt-get update` writes tens of megabytes of package indexes. If the "
        "same RUN does not delete them, they ship in the final image.",
        "Chain `&& rm -rf /var/lib/apt/lists/*` in the same RUN as the install.",
    ),
    _r(
        "DRL011",
        "pip install without --no-cache-dir",
        "low",
        "hygiene",
        "The pip wheel cache is pure build residue; in a single-use image it is "
        "dead weight that can double the Python layer.",
        "Add --no-cache-dir to every pip install in the Dockerfile.",
    ),
    _r(
        "DRL012",
        "ENV carries a literal secret",
        "high",
        "secrets",
        "ENV values are readable with `docker inspect` and appear in the image "
        "config. A literal password there is public the moment the image is.",
        "Pass secrets at runtime (`--env-file`, a secret manager, or compose "
        "`secrets`), never bake them into ENV.",
        cwe="CWE-798",
    ),
    _r(
        "DRL013",
        "ARG carries a secret-like value",
        "high",
        "secrets",
        "ARG values are recorded in the image history and `docker history` shows "
        "them. Using ARG for secrets is a common but false sense of safety.",
        "Use BuildKit `--mount=type=secret`, or inject at runtime.",
        cwe="CWE-798",
    ),
    _r(
        "DRL014",
        "No HEALTHCHECK",
        "low",
        "operations",
        "Without a HEALTHCHECK, orchestrators cannot tell a wedged process from "
        "a working one; traffic keeps flowing to a container that cannot serve.",
        "Add `HEALTHCHECK --interval=30s CMD <probe>`.",
    ),
    _r(
        "DRL015",
        "EXPOSE binds a privileged port",
        "low",
        "network",
        "Ports below 1024 require CAP_NET_BIND_SERVICE. Combined with a non-root "
        "USER the container simply fails to start; combined with root it keeps "
        "the privilege you were trying to remove.",
        "Listen on an unprivileged port (8080) and map it at runtime.",
    ),
    _r(
        "DRL016",
        "ONBUILD trigger present",
        "medium",
        "image",
        "ONBUILD defers an instruction to whoever uses this image as a base. The "
        "executed command is invisible in the child Dockerfile, which makes "
        "review and reproducibility close to impossible.",
        "Remove ONBUILD and document the required steps instead.",
    ),
    _r(
        "DRL017",
        "rm -rf on an unquoted variable",
        "high",
        "filesystem",
        "`rm -rf $DIR/` becomes `rm -rf /` when DIR is empty or unset: the "
        "trailing slash survives and the guard disappears. This has wiped real "
        "build machines.",
        "Use `${DIR:?must be set}` and quote it, or delete a literal path.",
        cwe="CWE-78",
    ),
    _r(
        "DRL018",
        "CMD uses shell form",
        "low",
        "operations",
        "Shell form wraps the process in `/bin/sh -c`, so the app is not PID 1 "
        "and never receives SIGTERM. Stops become SIGKILL after the grace period.",
        "Use exec form: `CMD [\"app\", \"--flag\"]`.",
    ),
    _r(
        "DRL019",
        "ENTRYPOINT uses shell form",
        "medium",
        "operations",
        "Same signal problem as CMD, but worse: ENTRYPOINT is the process, so "
        "every deployed container loses graceful shutdown and `docker run <img> "
        "args` silently drops its arguments.",
        "Use exec form: `ENTRYPOINT [\"app\"]` and put defaults in CMD.",
    ),
    _r(
        "DRL020",
        "COPY --from references an undefined stage",
        "high",
        "build-integrity",
        "The stage name does not exist in this file. BuildKit fails with "
        "`invalid from flag value`, or — worse — resolves it to an external "
        "image name and quietly copies from somewhere else.",
        "Reference a declared `FROM ... AS <name>` or a numeric stage index.",
    ),
    # -- pass 2: the compose file on its own ------------------------------
    _r(
        "DRC001",
        "Service runs privileged",
        "critical",
        "privilege",
        "`privileged: true` disables the default seccomp/AppArmor confinement "
        "and grants all capabilities plus access to every host device. One RCE "
        "in the service is then a host compromise.",
        "Remove privileged and add only the specific `cap_add` entries needed.",
        pass_no=2,
        cwe="CWE-250",
    ),
    _r(
        "DRC002",
        "Service shares the host network namespace",
        "high",
        "network",
        "`network_mode: host` removes port isolation: the container can reach "
        "every localhost service (databases, metadata endpoints, the Docker "
        "socket's HTTP API) and bind host ports directly.",
        "Use the default bridge network and publish only the ports you need.",
        pass_no=2,
    ),
    _r(
        "DRC003",
        "Service shares a host namespace",
        "high",
        "privilege",
        "`pid: host` lets the container see and signal every host process; "
        "`ipc: host` shares memory segments. Either one turns a contained "
        "process into a host-wide one.",
        "Drop the host namespace; use a shared sidecar network if you need IPC.",
        pass_no=2,
    ),
    _r(
        "DRC004",
        "Sensitive host path bind-mounted",
        "critical",
        "filesystem",
        "Mounting `/var/run/docker.sock` hands the container root-equivalent "
        "control of the host: it can start a privileged container and mount "
        "`/`. Other sensitive paths (`/etc`, `/root`, `/proc`, `/sys`) leak "
        "host state the service has no business reading.",
        "Remove the mount. If the service needs the Docker API, use a scoped "
        "proxy with an allow-list.",
        pass_no=2,
        cwe="CWE-269",
    ),
    _r(
        "DRC005",
        "Dangerous capability added",
        "high",
        "privilege",
        "SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN and DAC_READ_SEARCH each "
        "defeat a containment boundary: module loading, host tracing, arbitrary "
        "network reconfiguration, or reading files the uid cannot read.",
        "Drop the capability and grant the narrowest one that works.",
        pass_no=2,
        cwe="CWE-250",
    ),
    _r(
        "DRC006",
        "no-new-privileges not set",
        "low",
        "privilege",
        "Without `no-new-privileges:true`, a setuid binary inside the image can "
        "still raise the process's privileges. It is one line and it closes the "
        "cheapest escalation path.",
        "Add `security_opt: [\"no-new-privileges:true\"]` to the service.",
        pass_no=2,
    ),
    _r(
        "DRC007",
        "Plaintext secret in the environment",
        "high",
        "secrets",
        "The value is stored in the compose file, shows up in `docker inspect` "
        "and in the container's /proc/1/environ. Committed compose files leak it "
        "to everyone with repository access.",
        "Move it to `secrets:` or an untracked `.env` file excluded by "
        ".gitignore.",
        pass_no=2,
        cwe="CWE-798",
    ),
    _r(
        "DRC008",
        "Port published on every interface",
        "medium",
        "network",
        "A published port with no host_ip binds 0.0.0.0. On a laptop on a cafe "
        "network, that database or admin panel is now reachable by the whole "
        "subnet.",
        "Bind to loopback for local services: `\"127.0.0.1:8080:8080\"`.",
        pass_no=2,
    ),
    _r(
        "DRC009",
        "Service image is a floating tag",
        "low",
        "image",
        "`latest` or no tag means `docker compose pull` can change the running "
        "software without a commit. Rollbacks stop being deterministic.",
        "Pin the image to a version or digest.",
        pass_no=2,
    ),
    _r(
        "DRC010",
        "Container filesystem is writable",
        "info",
        "filesystem",
        "A read-only root filesystem turns many post-exploitation steps "
        "(dropping a payload, editing a config, installing a cron entry) into "
        "failures. It is not free — apps that write to their own directory need "
        "a tmpfs — which is why this is informational.",
        "Add `read_only: true` plus `tmpfs: [/tmp]` where needed.",
        pass_no=2,
    ),
    _r(
        "DRC011",
        "No restart policy",
        "info",
        "operations",
        "A container that dies stays dead. That is fine for one-shot jobs and a "
        "silent outage for a service.",
        "Set `restart: unless-stopped` for long-running services.",
        pass_no=2,
    ),
    _r(
        "DRC012",
        "env_file points at a missing file",
        "medium",
        "build-integrity",
        "`docker compose up` aborts when an env_file does not exist, so a fresh "
        "clone cannot start. The usual cause is an untracked `.env` that was "
        "never documented.",
        "Commit a `.env.example`, document the copy step, or drop the entry.",
        pass_no=2,
    ),
    # -- pass 3: relations between the files ------------------------------
    _r(
        "DRX001",
        "COPY source is excluded by .dockerignore",
        "high",
        "build-integrity",
        "The path is listed in .dockerignore, so it is not in the build context "
        "and COPY fails with `not found` — after the image build has already "
        "run for a while. This is the most common broken-build cause that a "
        "Dockerfile-only linter cannot see.",
        "Remove the ignore entry, or copy from a path that is in the context.",
        pass_no=3,
    ),
    _r(
        "DRX002",
        "compose build target does not exist",
        "high",
        "build-integrity",
        "`build.dockerfile` (or the context directory) is missing on disk, so "
        "`docker compose build` fails immediately. Typically the file was "
        "renamed or lives in a subdirectory.",
        "Point build.dockerfile at the real file, relative to the context.",
        pass_no=3,
    ),
    _r(
        "DRX003",
        "Two services claim the same host port",
        "high",
        "network",
        "Docker binds host ports first-come-first-served, so the second service "
        "fails with `port is already allocated` — or, with overrides, silently "
        "serves the wrong container. `EXPOSE` is documentation; the published "
        "port is the binding, and only the full set of compose files shows the "
        "collision.",
        "Publish the second service on a different host port, or bind it to "
        "loopback and reach it through a reverse proxy.",
        pass_no=3,
    ),
    _r(
        "DRX004",
        "Secret is both baked into the image and mounted",
        "high",
        "secrets",
        "The Dockerfile COPYs credential material into the image *and* compose "
        "mounts that same path at runtime. The runtime mount hides the baked "
        "copy from the running container, which is exactly why nobody notices "
        "it is still in the layer.",
        "Remove the COPY; the runtime mount is the only copy you need.",
        pass_no=3,
        cwe="CWE-538",
    ),
    _r(
        "DRX005",
        "Build context ships .git",
        "medium",
        "secrets",
        "With no .dockerignore (or one that does not exclude .git), the entire "
        "repository history enters the build context. Any `COPY . .` then puts "
        "it in a layer, including deleted secrets and author emails.",
        "Add a .dockerignore starting with `.git` and `.env`.",
        pass_no=3,
    ),
    _r(
        "DRX006",
        "compose overrides the image's unprivileged user",
        "high",
        "privilege",
        "The Dockerfile deliberately drops to a non-root USER; the compose file "
        "sets `user: root` (or `0`), undoing it. The image is safe and the "
        "deployment is not — the worst combination, because reviews look at the "
        "Dockerfile.",
        "Remove the user override, or set the same uid the image uses.",
        pass_no=3,
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULE_LIST}


def all_rules() -> list[Rule]:
    return list(_RULE_LIST)


def by_id(rule_id: str) -> Rule | None:
    return RULES.get(rule_id.upper())


def groups() -> list[str]:
    seen: list[str] = []
    for rule in _RULE_LIST:
        if rule.group not in seen:
            seen.append(rule.group)
    return seen
