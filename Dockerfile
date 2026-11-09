# syntax=docker/dockerfile:1.6
FROM python:3.12-slim

WORKDIR /app

# Copy metadata and sources separately so a source-only edit does not
# invalidate the dependency layer.
COPY pyproject.toml README.md /app/
COPY src/docklint /app/src/docklint

RUN useradd --create-home --uid 10001 app \
    && pip install --no-cache-dir /app

USER 10001

HEALTHCHECK --interval=30s --timeout=3s CMD docklint rules >/dev/null || exit 1

ENTRYPOINT ["docklint"]
