# Sentinel Bridge — developer tasks.
#
# FIX: the previous Makefile was Windows-only and machine-specific — it hardcoded
#   WAZUH_DIR = $(USERPROFILE)\OneDrive\Desktop\wazuh version(4.7.2)-pfe\wazuh-docker\single-node
#   OLLAMA    = $(LOCALAPPDATA)\Programs\Ollama\ollama.exe
# and used `start`, `cmd /c`, `.\venv\Scripts\…` and `rmdir /s /q`. On Linux/macOS
# every target failed, and the Wazuh path only existed on one laptop.
# Everything below is POSIX; Windows users keep start.bat (which is fine as-is).

SHELL        := /bin/bash
VENV         := backend/venv
PIP          := $(VENV)/bin/pip
PYTHON       := $(VENV)/bin/python
UVICORN      := $(VENV)/bin/uvicorn
CELERY       := $(VENV)/bin/celery
COMPOSE      := docker compose

.DEFAULT_GOAL := help

.PHONY: help install install-backend install-frontend install-admin-frontend \
        infra infra-down dev dev-backend dev-worker dev-frontend dev-admin \
        test lint lint-backend lint-frontend format build clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Install ────────────────────────────────────────────────────────────
install: install-backend install-frontend install-admin-frontend ## Install everything

install-backend: ## Python venv + deps (+ the opencv headless fix)
	cd backend && python3 -m venv venv
	$(PIP) install -r backend/requirements.txt
	# insightface pulls the GUI opencv build, which collides with the headless one
	$(PIP) uninstall -y opencv-python || true
	$(PIP) install --force-reinstall --no-deps opencv-python-headless==4.14.0.94
	$(PIP) install pytest ruff

install-frontend: ## SOC frontend deps
	cd frontend && npm ci

install-admin-frontend: ## Admin console deps
	cd admin-frontend && npm ci

# ── Local infrastructure ───────────────────────────────────────────────
infra: ## Start PostgreSQL (TimescaleDB) + Redis for development
	$(COMPOSE) up -d

infra-down: ## Stop local infrastructure
	$(COMPOSE) down

# ── Run ────────────────────────────────────────────────────────────────
dev: ## Run infra + backend + worker + both frontends (Ctrl-C stops everything)
	@$(MAKE) infra
	@trap '$(COMPOSE) stop' INT TERM; \
		$(MAKE) -j4 dev-backend dev-worker dev-frontend dev-admin

dev-backend: ## FastAPI on 127.0.0.1:8001
	cd backend && ../$(UVICORN) app.main:app --reload --host 127.0.0.1 --port 8001 --proxy-headers

dev-worker: ## Celery worker + beat
	cd backend && ../$(CELERY) -A app.worker.celery_app worker --loglevel=info --pool=solo -B

dev-frontend: ## Vite dev server (SOC frontend)
	cd frontend && npm run dev

dev-admin: ## Vite dev server (admin console)
	cd admin-frontend && npm run dev

# ── Quality gates (the same ones CI runs) ──────────────────────────────
test: ## Backend test suite (tests/conftest.py provides the required env)
	cd backend && ../$(PYTHON) -m pytest --tb=short -q

lint: lint-backend lint-frontend ## Everything CI checks

lint-backend: ## ruff over the backend
	cd backend && ../$(VENV)/bin/ruff check .

lint-frontend: ## Production build of BOTH frontends (catches unresolvable imports)
	cd frontend && npm run build
	cd admin-frontend && npm run build

format: ## ruff --fix (safe fixes only)
	cd backend && ../$(VENV)/bin/ruff check . --fix

build: ## Build both frontends into dist/
	cd frontend && npm run build
	cd admin-frontend && npm run build

clean: ## Remove venv, node_modules and caches
	rm -rf backend/venv backend/.ruff_cache backend/.pytest_cache
	rm -rf frontend/node_modules frontend/dist
	rm -rf admin-frontend/node_modules admin-frontend/dist
	find . -type d -name __pycache__ -not -path "*/node_modules/*" -prune -exec rm -rf {} +
