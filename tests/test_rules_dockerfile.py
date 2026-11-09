"""Pass 1 rules: each one fires on its own trigger and stays quiet on the control.

Every test here uses the same clean baseline. If the baseline ever starts
producing findings, these tests fail as a group — which is the intended
canary: a rule that broadens silently is how a linter becomes noise.
"""

from __future__ import annotations

BASE = """\
FROM python:3.12-slim AS base
WORKDIR /app
COPY app.py /app/app.py
RUN useradd -r -u 10001 app
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s CMD python -c "print(1)"
CMD ["python", "/app/app.py"]
"""


def _with(line: str, replace: str | None = None) -> str:
    """Baseline with one line appended (or one line replaced)."""
    if replace is None:
        return BASE + line + "\n"
    return BASE.replace(replace, line)


def test_clean_baseline_has_no_findings(hits):
    assert hits(dockerfile=BASE) == set()


def test_drl001_untagged_base_image(hits):
    assert "DRL001" in hits(dockerfile=_with("FROM ubuntu", "FROM python:3.12-slim AS base"))


def test_drl002_latest_tag(hits):
    assert "DRL002" in hits(dockerfile=_with("FROM python:latest AS base", "FROM python:3.12-slim AS base"))


def test_drl002_does_not_fire_for_version_tags(hits):
    assert "DRL002" not in hits(dockerfile=BASE)


def test_drl003_runs_as_root_when_no_user(hits):
    text = BASE.replace("USER 10001\n", "")
    assert "DRL003" in hits(dockerfile=text)


def test_drl003_explicit_root_user(hits):
    assert "DRL003" in hits(dockerfile=_with("USER root", "USER 10001"))


def test_drl004_add_without_url(hits):
    assert "DRL004" in hits(dockerfile=_with("ADD pkg.tar.gz /opt/"))


def test_drl004_not_raised_when_add_fetches_a_url(hits):
    # A remote ADD is DRL005; reporting DRL004 as well would double-count one
    # instruction and train users to ignore both.
    out = hits(dockerfile=_with("ADD https://example.com/x.tgz /opt/"))
    assert "DRL005" in out and "DRL004" not in out


def test_drl005_remote_add_is_high(hits, project):
    from docklint.engine import scan

    root = project(dockerfile=_with("ADD https://example.com/x.tgz /opt/"))
    finding = next(f for f in scan(root).findings if f.rule.id == "DRL005")
    assert finding.rule.severity == "high"
    assert finding.line == 9


def test_drl006_credential_copy(hits):
    assert "DRL006" in hits(dockerfile=_with("COPY id_rsa /app/id_rsa"))


def test_drl006_ignores_env_example(hits):
    assert "DRL006" not in hits(dockerfile=_with("COPY .env.example /app/.env.example"))


def test_drl006_detects_key_extensions(hits):
    assert "DRL006" in hits(dockerfile=_with("COPY certs/server.pem /app/server.pem"))


def test_drl007_sudo(hits):
    assert "DRL007" in hits(dockerfile=_with("RUN sudo apt-get install -y curl"))


def test_drl008_pipe_to_shell(hits):
    assert "DRL008" in hits(dockerfile=_with("RUN curl -fsSL https://example.com/i.sh | sh"))


def test_drl008_wget_to_bash(hits):
    assert "DRL008" in hits(dockerfile=_with("RUN wget -qO- https://example.com/i | bash"))


def test_drl008_not_raised_for_a_download_without_a_pipe(hits):
    assert "DRL008" not in hits(dockerfile=_with("RUN curl -fsSLo /tmp/i.sh https://example.com/i.sh"))


def test_drl009_no_install_recommends(hits):
    assert "DRL009" in hits(dockerfile=_with("RUN apt-get install -y curl"))


def test_drl009_quiet_when_flag_present(hits):
    assert "DRL009" not in hits(
        dockerfile=_with("RUN apt-get install -y --no-install-recommends curl")
    )


def test_drl010_apt_lists_not_cleaned(hits):
    assert "DRL010" in hits(dockerfile=_with("RUN apt-get update && apt-get install -y curl"))


def test_drl010_quiet_when_lists_are_removed(hits):
    out = hits(
        dockerfile=_with(
            "RUN apt-get update && apt-get install -y --no-install-recommends curl "
            "&& rm -rf /var/lib/apt/lists/*"
        )
    )
    assert "DRL010" not in out


def test_drl011_pip_cache(hits):
    assert "DRL011" in hits(dockerfile=_with("RUN pip install requests"))


def test_drl011_quiet_with_no_cache_dir(hits):
    assert "DRL011" not in hits(dockerfile=_with("RUN pip install --no-cache-dir requests"))


def test_drl012_literal_env_secret(hits):
    assert "DRL012" in hits(dockerfile=_with("ENV DB_PASSWORD=hunter2"))


def test_drl012_not_raised_for_harmless_env(hits):
    assert "DRL012" not in hits(dockerfile=_with("ENV LOG_LEVEL=info"))


def test_drl013_arg_secret(hits):
    assert "DRL013" in hits(dockerfile=_with("ARG NPM_TOKEN=abc"))


def test_drl014_missing_healthcheck(hits):
    text = BASE.replace('HEALTHCHECK --interval=30s CMD python -c "print(1)"\n', "")
    assert "DRL014" in hits(dockerfile=text)


def test_drl015_privileged_port(hits):
    assert "DRL015" in hits(dockerfile=_with("EXPOSE 80"))


def test_drl015_quiet_for_high_ports(hits):
    assert "DRL015" not in hits(dockerfile=_with("EXPOSE 8443"))


def test_drl016_onbuild(hits):
    assert "DRL016" in hits(dockerfile=_with("ONBUILD RUN echo hi"))


def test_drl017_rm_rf_variable(hits):
    assert "DRL017" in hits(dockerfile=_with("RUN rm -rf $BUILD_DIR/"))


def test_drl017_quiet_for_literal_apt_path(hits):
    # The single most common false positive: deleting the apt lists is correct.
    assert "DRL017" not in hits(dockerfile=_with("RUN rm -rf /var/lib/apt/lists/*"))


def test_drl018_cmd_shell_form(hits):
    text = BASE.replace('CMD ["python", "/app/app.py"]', "CMD python /app/app.py")
    assert "DRL018" in hits(dockerfile=text)


def test_drl019_entrypoint_shell_form(hits):
    assert "DRL019" in hits(dockerfile=_with("ENTRYPOINT python /app/app.py"))


def test_drl020_undefined_copy_stage(hits):
    assert "DRL020" in hits(dockerfile=_with("COPY --from=ghost /out /app/out"))


def test_drl020_quiet_for_declared_alias(hits):
    assert "DRL020" not in hits(dockerfile=_with("COPY --from=base /app.py /app/copy.py"))


def test_drl020_quiet_for_an_external_image(hits):
    assert "DRL020" not in hits(dockerfile=_with("COPY --from=nginx:1.25 /etc/nginx/nginx.conf /app/"))


def test_drl020_quiet_for_numeric_stage(hits):
    assert "DRL020" not in hits(dockerfile=_with("COPY --from=0 /app.py /app/copy.py"))


def test_multistage_root_check_only_looks_at_the_final_stage(hits):
    text = "FROM python:3.12-slim AS build\nUSER root\nFROM python:3.12-slim\nUSER 10001\nCMD [\"x\"]\n"
    out = hits(dockerfile=text)
    assert "DRL003" not in out


def test_drl006_reads_the_file_when_it_can(project):
    """`.npmrc` is a credential file by convention; most only set registry."""
    from docklint.engine import scan

    root = project(
        dockerfile=BASE + "COPY .npmrc /app/.npmrc\n",
        extra={".npmrc": "registry=https://registry.npmjs.org/\n"},
    )
    assert "DRL006" not in {f.rule.id for f in scan(root).findings}


def test_drl006_still_fires_when_the_file_holds_a_token(project):
    from docklint.engine import scan

    root = project(
        dockerfile=BASE + "COPY .npmrc /app/.npmrc\n",
        extra={".npmrc": "//registry.npmjs.org/:_authToken=npm_abc123\n"},
    )
    assert "DRL006" in {f.rule.id for f in scan(root).findings}


def test_drl006_flags_unreadable_credential_paths(project):
    # The file is not in the context (or is a directory): stay conservative.
    root = project(dockerfile=BASE + "COPY .ssh /app/.ssh\n")
    from docklint.engine import scan

    assert "DRL006" in {f.rule.id for f in scan(root).findings}
