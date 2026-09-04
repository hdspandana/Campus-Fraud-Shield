# Dockerfile
# ═════════════════════════════════════════════════════════════════
# Multi-stage build for Campus Fraud Shield.
#
# ONE image serves BOTH entrypoints (app.py's Streamlit UI and
# api.py's FastAPI service) — which process actually runs is picked
# at `docker run` time via CMD override / docker-compose (see
# docker-compose.yml), not baked in here. That avoids maintaining two
# near-identical Dockerfiles that would drift out of sync with each
# other, the same reasoning core/pipeline.py already uses to keep
# app.py and api.py on one shared code path instead of two copies.
#
# Build:
#   docker build -t campus-fraud-shield .
# Run the API:
#   docker run -p 8000:8000 campus-fraud-shield \
#       uvicorn api:app --host 0.0.0.0 --port 8000
# Run the Streamlit app:
#   docker run -p 8501:8501 campus-fraud-shield \
#       streamlit run app.py --server.address 0.0.0.0
# (docker-compose.yml wires both up with the right ports/healthchecks
# in one command — that's the easier path for local dev.)
# ═════════════════════════════════════════════════════════════════

# ── Stage 1: build ──────────────────────────────────────────────────
# Separated from the runtime stage so build-only tooling (pip's
# compiler toolchain needs for torch/faiss wheels) doesn't end up in
# the final image — meaningfully smaller image, faster deploys.
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps needed to build/install some ML wheels (torch, faiss-cpu
# occasionally need a compiler for platforms without a prebuilt wheel).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Runs as a non-root user — a container running its app as root is a
# real, avoidable privilege-escalation surface if the process is ever
# compromised, and costs nothing to avoid here.
RUN useradd --create-home --uid 1000 appuser

WORKDIR /app

COPY --from=builder /install /usr/local
COPY . .

# The base image the sentence-transformers model gets cached into
# (~/.cache/huggingface) needs to be writable by appuser, same for
# anywhere the app writes at runtime (data/fraud_shield.db, models/).
RUN chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/app/.cache/huggingface

EXPOSE 8000 8501

# No CMD here on purpose — docker-compose.yml specifies which
# entrypoint (api or streamlit) each service runs. A bare `docker run
# campus-fraud-shield` without a command will show FastAPI's default
# "command not found" rather than silently doing the wrong thing.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
        port=os.environ.get('HEALTHCHECK_PORT','8000'); \
        path=os.environ.get('HEALTHCHECK_PATH','/api/v1/health'); \
        sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}{path}', timeout=3).status==200 else 1)" \
    || exit 1