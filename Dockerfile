ARG TRIVY_VERSION=0.76.1

FROM docker.io/aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM ghcr.io/astral-sh/uv:python3.15-trixie-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM docker.io/library/python:3.15-slim-trixie
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/home/app/.cache/trivy
RUN useradd --create-home --uid 1000 app \
    && mkdir -p "$TRIVY_CACHE_DIR" \
    && chown -R app:app /home/app
USER app
EXPOSE 8085
CMD ["trivy-dashboard-service"]
