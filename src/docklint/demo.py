"""Zero-setup demo: a deliberately broken project that trips every rule.

The fixtures below are the executable definition of "covered". If a rule stops
firing here, `tests/test_demo.py` fails, so the coverage claim in the README
cannot rot the way prose does.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

__all__ = ["FILES", "materialize", "demo_dir"]

# A `.git` directory is part of the fixture on purpose: DRX005 only means
# something when the build context actually contains one.
FILES: dict[str, str] = {
    "Dockerfile": """\
# syntax=docker/dockerfile:1.6
FROM python:latest AS build
ARG DOCKER_PASSWORD=hunter2
ENV API_TOKEN=abc123
RUN apt-get update && apt-get install -y curl git
RUN curl -fsSL https://example.com/install.sh | sh
RUN pip install requests
RUN sudo rm -rf $BUILD_DIR/
ONBUILD RUN echo "this runs inside your child image"
COPY id_rsa /app/id_rsa
COPY data/fixture.json /app/fixture.json
ADD https://example.com/tool.tgz /opt/
ADD archive.tar.gz /opt/
COPY --from=ghost /build/out /app/out
EXPOSE 80
CMD python app.py

FROM ubuntu
COPY . /app
ENTRYPOINT python app.py
""",
    "Dockerfile.service": """\
FROM python:3.12-slim
WORKDIR /srv
COPY app.py /srv/app.py
EXPOSE 9091
USER 10001
CMD ["python", "/srv/app.py"]
""",
    "docker-compose.yml": """\
services:
  app:
    build: .
    environment:
      DB_PASSWORD: "s3cr3t-value"
      LOG_LEVEL: debug
    ports:
      - "5432:5432"
    volumes:
      - ./id_rsa:/app/id_rsa:ro
  api:
    build:
      context: .
      dockerfile: Dockerfile.service
    user: root
    ports:
      - "9091:9090"
  missing:
    build:
      context: .
      dockerfile: Dockerfile.missing
  metrics:
    image: prom/prometheus:v2.51.0
    ports:
      - "5432:9090"
  metrics:
    image: prom/prometheus:v2.51.0
    ports:
      - "5432:9090"
  proxy:
    image: nginx:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    env_file:
      - ./.env.missing
  debug:
    image: alpine:3.19
    privileged: true
    network_mode: host
    pid: host
    cap_add:
      - SYS_ADMIN
""",
    ".dockerignore": """\
data/
.env.local
""",
    "app.py": "print('demo')\n",
    "data/fixture.json": '{"demo": true}\n',
    ".git/HEAD": "ref: refs/heads/main\n",
    "README.md": "# demo project\n\nDeliberately broken; run `docklint demo`.\n",
}


def materialize(target: Path | str) -> Path:
    """Write the fixture project into ``target`` and return the path."""
    root = Path(target)
    root.mkdir(parents=True, exist_ok=True)
    for name, content in FILES.items():
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
    return root


def demo_dir() -> tempfile.TemporaryDirectory:
    """A temporary directory holding the fixture project."""
    tmp = tempfile.TemporaryDirectory(prefix="docklint-demo-")
    materialize(Path(tmp.name))
    return tmp
