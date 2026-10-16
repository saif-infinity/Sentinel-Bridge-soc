# syntax=docker/dockerfile:1
# Backend image — used by docker-compose.prod.yml (backend/worker/syslog) and by CI.
# The repo referenced `build: ./backend` but shipped no Dockerfile, so neither
# `docker compose -f docker-compose.prod.yml up --build` nor the CI build job worked.

FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps for the onnxruntime/insightface/opencv wheels + curl for the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libgl1 libglib2.0-0 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first (cache-friendly).
COPY requirements.txt ./
RUN pip install -r requirements.txt \
    # insightface pulls the GUI opencv build, which collides with the headless one
    && pip uninstall -y opencv-python \
    && pip install --force-reinstall --no-deps opencv-python-headless==4.14.0.94

COPY app ./app
COPY migrations ./migrations
COPY scripts ./scripts
COPY tests ./tests
COPY ruff.toml ./

# Non-root runtime user; compose already sets read_only + no-new-privileges.
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /app/app/face_data /tmp/sentinel \
    && chown -R sentinel:sentinel /app /tmp/sentinel
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# --proxy-headers: the container sits behind nginx in docker-compose.prod.yml, so
# request.client.host would otherwise be the proxy for every client and the login
# rate-limit would be global instead of per-attacker.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
