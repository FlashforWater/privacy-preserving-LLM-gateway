# syntax=docker/dockerfile:1.7
#
# Multi-stage build (guide §21.2). The runtime stage carries no compiler, no
# package manager cache, no test fixtures and no development keys — the build
# stage is where those live and it is discarded.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY app ./app
# Install the runtime dependency set only. Document parsing and OCR extras are
# installed explicitly by the image that needs them.
RUN pip install --no-cache-dir ".[documents]"


FROM python:3.12-slim AS runtime

# Non-root from the start; the application never needs to write to its own tree.
RUN groupadd --gid 10001 gateway \
 && useradd --uid 10001 --gid gateway --home-dir /app --no-create-home gateway

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=gateway:gateway app ./app
COPY --chown=gateway:gateway config ./config
COPY --chown=gateway:gateway migrations ./migrations
COPY --chown=gateway:gateway scripts ./scripts

USER gateway

# Liveness only. Orchestration readiness must use /health/ready, which also
# verifies policy, vault encryption and required detectors.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).status==200 else 1)"

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
