"""Pass 3 rules: the relations no single-file linter can see."""

from __future__ import annotations

from docklint.engine import scan

DF = """\
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
RUN useradd -r -u 10001 app
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s CMD python -c "print(1)"
CMD ["python", "/app/app.py"]
"""

COMPOSE = """\
services:
  web:
    build: .
    user: "10001"
    ports:
      - "127.0.0.1:8080:8080"
    security_opt:
      - no-new-privileges:true
    read_only: true
    restart: unless-stopped
"""

EXTRA = {"app.py": "print(1)\n"}


def _rules(root) -> set[str]:
    return {f.rule.id for f in scan(root).findings}


def test_clean_cross_project_has_no_cross_findings(project):
    root = project(dockerfile=DF, compose=COMPOSE, ignore=".git\n", extra=EXTRA)
    assert not {r for r in _rules(root) if r.startswith("DRX")}


def test_drx001_copy_of_ignored_path(project):
    root = project(dockerfile=DF, compose=COMPOSE, ignore="app.py\n", extra=EXTRA)
    assert "DRX001" in _rules(root)


def test_drx001_negation_keeps_the_file_in_context(project):
    root = project(
        dockerfile=DF, compose=COMPOSE, ignore="*.py\n!app.py\n", extra=EXTRA
    )
    assert "DRX001" not in _rules(root)


def test_drx001_reports_the_copy_line(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY app.py /app/app.py\nCOPY data/x.json /app/x.json")
    root = project(dockerfile=df, compose=COMPOSE, ignore="data/\n", extra=EXTRA)
    finding = next(f for f in scan(root).findings if f.rule.id == "DRX001")
    assert finding.line == 4  # the inserted COPY, directly under the first one
    assert "data/x.json" in finding.detail


def test_drx002_missing_build_dockerfile(project):
    compose = COMPOSE.replace("    build: .\n", "    build:\n      context: .\n      dockerfile: Dockerfile.absent\n")
    root = project(dockerfile=DF, compose=compose, ignore=".git\n", extra=EXTRA)
    assert "DRX002" in _rules(root)


def test_drx002_quiet_when_the_dockerfile_is_there(project):
    root = project(dockerfile=DF, compose=COMPOSE, ignore=".git\n", extra=EXTRA)
    assert "DRX002" not in _rules(root)


COLLIDING = COMPOSE + """  worker:
    image: python:3.12-slim
    ports:
      - "127.0.0.1:8080:9000"
"""


def test_drx003_two_services_claim_the_same_host_port(project):
    root = project(dockerfile=DF, compose=COLLIDING, ignore=".git\n", extra=EXTRA)
    finding = next(f for f in scan(root).findings if f.rule.id == "DRX003")
    assert "8080" in finding.detail
    assert finding.service == "worker"


def test_drx003_quiet_when_ports_are_distinct(project):
    root = project(dockerfile=DF, compose=COMPOSE, ignore=".git\n", extra=EXTRA)
    assert "DRX003" not in _rules(root)


def test_drx003_catches_a_collision_across_base_and_override(project):
    root = project(dockerfile=DF, compose=COMPOSE, ignore=".git\n", extra=EXTRA)
    (root / "docker-compose.override.yml").write_text(
        """services:
  sidecar:
    image: python:3.12-slim
    ports:
      - "127.0.0.1:8080:7000"
""",
        encoding="utf-8",
    )
    assert "DRX003" in _rules(root)


def test_drx004_secret_baked_and_mounted(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY id_rsa /app/id_rsa")
    compose = COMPOSE.replace(
        "    ports:\n", "    volumes:\n      - ./id_rsa:/app/id_rsa:ro\n    ports:\n"
    )
    root = project(dockerfile=df, compose=compose, ignore=".git\n", extra=EXTRA)
    rules = _rules(root)
    assert "DRX004" in rules and "DRL006" in rules


def test_drx004_quiet_when_only_one_side_exists(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY id_rsa /app/id_rsa")
    root = project(dockerfile=df, compose=COMPOSE, ignore=".git\n", extra=EXTRA)
    assert "DRX004" not in _rules(root)


def test_drx005_git_reaches_the_context(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY . /app")
    root = project(
        dockerfile=df, compose=COMPOSE, ignore="*.log\n", extra={**EXTRA, ".git/HEAD": "ref\n"}
    )
    assert "DRX005" in _rules(root)


def test_drx005_quiet_when_git_is_ignored(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY . /app")
    root = project(
        dockerfile=df, compose=COMPOSE, ignore=".git\n", extra={**EXTRA, ".git/HEAD": "ref\n"}
    )
    assert "DRX005" not in _rules(root)


def test_drx005_quiet_without_a_git_directory(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY . /app")
    root = project(dockerfile=df, compose=COMPOSE, ignore="*.log\n", extra=EXTRA)
    assert "DRX005" not in _rules(root)


def test_drx006_compose_overrides_the_unprivileged_user(project):
    compose = COMPOSE.replace('user: "10001"', "user: root")
    root = project(dockerfile=DF, compose=compose, ignore=".git\n", extra=EXTRA)
    finding = next(f for f in scan(root).findings if f.rule.id == "DRX006")
    assert "USER 10001" in finding.detail
    assert finding.service == "web"


def test_drx006_quiet_when_the_image_runs_as_root_anyway(project):
    df = DF.replace("USER 10001\n", "")
    compose = COMPOSE.replace('user: "10001"', "user: root")
    root = project(dockerfile=df, compose=compose, ignore=".git\n", extra=EXTRA)
    assert "DRX006" not in _rules(root)


def test_cross_findings_carry_both_coordinates(project):
    df = DF.replace("COPY app.py /app/app.py", "COPY id_rsa /app/id_rsa")
    compose = COMPOSE.replace(
        "    ports:\n", "    volumes:\n      - ./id_rsa:/app/id_rsa:ro\n    ports:\n"
    )
    root = project(dockerfile=df, compose=compose, ignore=".git\n", extra=EXTRA)
    finding = next(f for f in scan(root).findings if f.rule.id == "DRX004")
    assert finding.stage == "stage-0"
    assert finding.service == "web"
