"""Pass 2 rules: compose-only findings, with a control that must stay clean."""

from __future__ import annotations

BASE = """\
services:
  web:
    image: nginx:1.25
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - ./conf:/etc/nginx/conf.d:ro
    security_opt:
      - no-new-privileges:true
    read_only: true
    restart: unless-stopped
    environment:
      LOG_LEVEL: info
"""


def _add(lines: str, anchor: str = "    restart: unless-stopped\n") -> str:
    return BASE.replace(anchor, anchor + lines)


def test_clean_compose_baseline_has_no_findings(hits):
    assert hits(compose=BASE) == set()


def test_drc001_privileged(hits):
    assert "DRC001" in hits(compose=_add("    privileged: true\n"))


def test_drc002_host_network(hits):
    assert "DRC002" in hits(compose=_add("    network_mode: host\n"))


def test_drc003_pid_host(hits):
    assert "DRC003" in hits(compose=_add("    pid: host\n"))


def test_drc003_ipc_host(hits):
    assert "DRC003" in hits(compose=_add("    ipc: host\n"))


def test_drc004_docker_socket(hits):
    text = BASE.replace(
        "      - ./conf:/etc/nginx/conf.d:ro\n",
        "      - ./conf:/etc/nginx/conf.d:ro\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    )
    assert "DRC004" in hits(compose=text)


def test_drc004_sensitive_host_path(hits):
    text = BASE.replace(
        "      - ./conf:/etc/nginx/conf.d:ro\n",
        "      - ./conf:/etc/nginx/conf.d:ro\n      - /etc:/host-etc\n",
    )
    assert "DRC004" in hits(compose=text)


def test_drc004_quiet_for_a_relative_bind(hits):
    assert "DRC004" not in hits(compose=BASE)


def test_drc005_dangerous_capability(hits):
    assert "DRC005" in hits(compose=_add("    cap_add:\n      - SYS_ADMIN\n"))


def test_drc005_quiet_for_a_harmless_capability(hits):
    assert "DRC005" not in hits(compose=_add("    cap_add:\n      - CHOWN\n"))


def test_drc006_missing_no_new_privileges(hits):
    text = BASE.replace("    security_opt:\n      - no-new-privileges:true\n", "")
    assert "DRC006" in hits(compose=text)


def test_drc007_literal_secret(hits):
    assert "DRC007" in hits(compose=_add("      DB_PASSWORD: s3cr3t\n", "      LOG_LEVEL: info\n"))


def test_drc007_variable_reference_is_not_a_literal(hits):
    assert "DRC007" not in hits(
        compose=_add("      DB_PASSWORD: ${DB_PASSWORD}\n", "      LOG_LEVEL: info\n")
    )


def test_drc008_all_interfaces(hits):
    text = BASE.replace('      - "127.0.0.1:8080:80"', '      - "5432:5432"')
    assert "DRC008" in hits(compose=text)


def test_drc008_quiet_for_loopback(hits):
    assert "DRC008" not in hits(compose=BASE)


def test_drc009_latest_image(hits):
    text = BASE.replace("image: nginx:1.25", "image: nginx:latest")
    assert "DRC009" in hits(compose=text)


def test_drc009_untagged_image(hits):
    text = BASE.replace("image: nginx:1.25", "image: nginx")
    assert "DRC009" in hits(compose=text)


def test_drc010_writable_rootfs_is_informational(hits, project):
    from docklint.engine import scan

    text = BASE.replace("    read_only: true\n", "")
    root = project(compose=text)
    finding = next(f for f in scan(root).findings if f.rule.id == "DRC010")
    assert finding.rule.severity == "info"


def test_drc011_missing_restart(hits):
    text = BASE.replace("    restart: unless-stopped\n", "")
    assert "DRC011" in hits(compose=text)


def test_drc012_missing_env_file(hits):
    assert "DRC012" in hits(compose=_add("    env_file:\n      - ./.env.absent\n"))


def test_drc012_quiet_when_the_file_exists(project):
    from docklint.engine import scan

    root = project(
        compose=_add("    env_file:\n      - ./.env.absent\n"),
        extra={".env.absent": "A=1\n"},
    )
    assert "DRC012" not in {f.rule.id for f in scan(root).findings}


def test_drc012_quiet_for_optional_env_file(hits):
    text = _add("    env_file:\n      - path: ./.env.absent\n        required: false\n")
    assert "DRC012" not in hits(compose=text)


def test_drc007_quiet_for_the_file_suffix_convention(hits):
    # `MYSQL_ROOT_PASSWORD_FILE=/run/secrets/db-password` is the correct
    # pattern; the value is a path, not the secret.
    assert "DRC007" not in hits(
        compose=_add(
            "      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db-password\n", "      LOG_LEVEL: info\n"
        )
    )


def test_drc007_quiet_for_a_bare_path_value(hits):
    assert "DRC007" not in hits(
        compose=_add("      DB_PASSWORD: ./secrets/pw.txt\n", "      LOG_LEVEL: info\n")
    )
