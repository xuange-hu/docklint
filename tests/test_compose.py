"""Compose model: the many spellings of ports, volumes, environment, build."""

from __future__ import annotations

from docklint.compose import parse_compose, parse_mount, parse_port

BASE = """\
services:
  web:
    image: nginx:1.25
    ports:
      - "8080:80"
      - "127.0.0.1:5432:5432"
      - "9000"
      - "6000-6005:6000-6005/udp"
      - target: 7000
        published: 7000
        host_ip: 127.0.0.1
    volumes:
      - ./conf:/etc/nginx/conf.d:ro
      - data:/var/lib/data
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      A: "1"
      B: 2
    env_file:
      - .env
"""


def test_services_are_discovered():
    compose = parse_compose(BASE, "docker-compose.yml")
    assert compose.service_names() == ["web"]
    assert compose.errors == []


def test_short_port_forms():
    compose = parse_compose(BASE)
    ports = compose.ports("web")
    assert ports[0].published == "8080" and ports[0].target == "80"
    assert ports[0].publishes_all_interfaces
    assert ports[1].host_ip == "127.0.0.1"
    assert not ports[1].publishes_all_interfaces
    assert ports[2].published == "" and ports[2].target == "9000"
    assert ports[3].protocol == "udp"
    assert ports[3].published == "6000-6005"


def test_long_port_form():
    compose = parse_compose(BASE)
    port = compose.ports("web")[4]
    assert port.target == "7000"
    assert port.host_ip == "127.0.0.1"
    assert port.raw.startswith("host_ip")


def test_mount_forms_and_read_only():
    compose = parse_compose(BASE)
    mounts = compose.mounts("web")
    assert mounts[0].type == "bind" and mounts[0].read_only
    assert mounts[0].target == "/etc/nginx/conf.d"
    assert mounts[1].type == "volume" and mounts[1].source == "data"
    assert "docker.sock" in mounts[2].source


def test_environment_both_forms():
    compose = parse_compose(BASE)
    env = compose.environment("web")
    assert env["A"][0] == "1"
    assert env["B"][0] == "2"


def test_environment_list_form_and_bare_names():
    text = "services:\n  app:\n    environment:\n      - TOKEN=abc\n      - EMPTY\n"
    compose = parse_compose(text)
    env = compose.environment("app")
    assert env["TOKEN"][0] == "abc"
    assert env["EMPTY"][0] == ""


def test_build_string_form():
    compose = parse_compose("services:\n  app:\n    build: .\n")
    assert compose.build_spec("app") == (".", "Dockerfile")


def test_build_mapping_form():
    text = "services:\n  app:\n    build:\n      context: ./svc\n      dockerfile: app.Dockerfile\n"
    compose = parse_compose(text)
    assert compose.build_spec("app") == ("./svc", "app.Dockerfile")


def test_service_without_build_returns_none():
    compose = parse_compose("services:\n  app:\n    image: nginx:1.25\n")
    assert compose.build_spec("app") is None


def test_parse_port_handles_int_and_dict():
    assert parse_port(8080).target == "8080"
    port = parse_port({"target": 80, "published": 8080})
    assert port.target == "80" and port.published == "8080"


def test_parse_mount_long_form_defaults_to_bind_for_paths():
    mount = parse_mount({"source": "/etc/ssl", "target": "/certs"})
    assert mount.type == "bind"
    assert mount.read_only is False


def test_unbalanced_flow_collection_is_tolerated_not_crashed():
    # A lenient reader is the right call here: `docker compose config` will
    # reject this file with a precise message, and a linter that throws a
    # RecursionError tells the user nothing. The value stays literal.
    compose = parse_compose("services:\n  app: [unclosed\n")
    assert compose.service_names() == ["app"]
    # Not a mapping, so the typed accessor declines rather than guessing.
    assert compose.service("app") is None


def test_non_mapping_services_is_an_error():
    compose = parse_compose("services:\n  - app\n")
    assert compose.errors


def test_non_mapping_top_level_is_an_error():
    compose = parse_compose("- a\n- b\n")
    assert compose.errors


def test_anchors_are_noted_because_we_do_not_expand_them():
    text = "x-common: &common\n  restart: always\nservices:\n  app:\n    <<: *common\n    image: nginx\n"
    compose = parse_compose(text)
    assert any("anchors" in note for note in compose.notes)


def test_comments_inside_scalars_are_stripped():
    text = "services:\n  app:\n    image: nginx:1.25  # pinned\n"
    compose = parse_compose(text)
    assert str(compose.service("app").get("image")) == "nginx:1.25"


def test_quoted_colon_does_not_split_the_key():
    text = 'services:\n  app:\n    environment:\n      URL: "http://x:8080/a"\n'
    compose = parse_compose(text)
    assert compose.environment("app")["URL"][0] == "http://x:8080/a"


def test_service_line_points_at_the_service_key():
    compose = parse_compose(BASE)
    assert compose.service_line("web") == 2
    assert compose.service_line("nope") == 0


def test_indentless_sequence_under_a_key_does_not_truncate_the_mapping():
    """Real compose files write `args:` followed by `- item` at the same indent.

    Before this was supported, the mapping ended at `args:` and `context:` /
    `dockerfile:` became invisible — which produced a false DRX002 against a
    real repository (docker/awesome-compose, react-express-mysql).
    """
    text = (
        "services:\n"
        "  app:\n"
        "    build:\n"
        "      args:\n"
        "      - NODE_ENV=development\n"
        "      context: backend\n"
        "      dockerfile: app.Dockerfile\n"
    )
    compose = parse_compose(text)
    assert compose.build_spec("app") == ("backend", "app.Dockerfile")


def test_indentless_sequence_does_not_swallow_a_sibling_service():
    text = "services:\n  a:\n    image: nginx\n    expose:\n    - 80\n  b:\n    image: nginx\n"
    compose = parse_compose(text)
    assert compose.service_names() == ["a", "b"]
    assert compose.service("a").get("expose") == [80]
