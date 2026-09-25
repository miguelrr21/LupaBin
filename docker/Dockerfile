FROM ghcr.io/astral-sh/uv:0.8.22 AS uv
FROM python:3.12.11-slim-bookworm AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock LICENSE README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --no-cache

FROM python:3.12.11-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LUPABIN_WORKER=1
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
USER 65532:65532
ENTRYPOINT ["/app/.venv/bin/python", "-m", "lupabin.worker"]
