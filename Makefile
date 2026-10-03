.PHONY: install install-backend install-frontend dev dev-backend dev-frontend dev-worker dev-wazuh dev-ollama clean lint prod prod-down build help

WAZUH_DIR = $(USERPROFILE)\OneDrive\Desktop\wazuh version(4.7.2)-pfe\wazuh-docker\single-node
OLLAMA     = $(LOCALAPPDATA)\Programs\Ollama\ollama.exe

help:
	@echo "Usage:"
	@echo "  make install          Install all dependencies (backend + frontend)"
	@echo "  make install-backend  Install Python dependencies"
	@echo "  make install-frontend Install Node.js dependencies"
	@echo "  make dev              Run all services (backend + frontend + worker)"
	@echo "  make dev-backend      Run FastAPI backend (uvicorn)"
	@echo "  make dev-frontend     Run Vite frontend dev server"
	@echo "  make dev-worker       Run Celery worker"
	@echo "  make dev-wazuh        Start Wazuh single-node (docker-compose)"
	@echo "  make dev-ollama       Start Ollama server"
	@echo "  make build            Build frontend for production"
	@echo "  make prod             Start all services in production"
	@echo "  make prod-down        Stop all production services"
	@echo "  make clean            Remove venv, node_modules, caches"
	@echo "  make lint             Run linters (ruff, eslint)"

install: install-backend install-frontend

install-backend:
	cd backend && python -m venv venv && .\venv\Scripts\pip install -r requirements.txt
	# insightface tire opencv-python (GUI) -> entre en collision fichiers avec headless.
	./backend/venv/Scripts/pip uninstall -y opencv-python && ./backend/venv/Scripts/pip install --force-reinstall --no-deps opencv-python-headless==4.14.0.94

install-frontend:
	cd frontend && npm install

dev:
	@echo "Starting all services..."
	start "ollama" cmd /c "$(OLLAMA) serve"
	start "wazuh" cmd /c "cd /d $(WAZUH_DIR) && docker-compose up -d"
	start "backend" cmd /c "cd /d $(CURDIR)\backend & .\venv\Scripts\uvicorn app.main:app --reload --host 127.0.0.1 --port 8001"
	start "worker" cmd /c "cd /d $(CURDIR)\backend & .\venv\Scripts\celery -A app.worker.celery_app worker --loglevel=info --pool=solo -B"
	start "frontend" cmd /c "cd /d $(CURDIR)\frontend & npm run dev"

dev-backend:
	cd backend && .\venv\Scripts\uvicorn app.main:app --reload --host 127.0.0.1 --port 8001

dev-frontend:
	cd frontend && npm run dev

dev-worker:
	cd backend && .\venv\Scripts\celery -A app.worker.celery_app worker --loglevel=info --pool=solo -B

dev-wazuh:
	cd "$(WAZUH_DIR)" && docker-compose up -d

dev-ollama:
	"$(OLLAMA)" serve

build:
	cd frontend && npm run build

prod:
	docker compose -f docker-compose.prod.yml up -d --build

prod-down:
	docker compose -f docker-compose.prod.yml down

clean:
	rmdir /s /q backend\venv 2>nul || true
	rmdir /s /q frontend\node_modules 2>nul || true
	rmdir /s /q __pycache__ 2>nul || true
	rmdir /s /q backend\__pycache__ 2>nul || true
	rmdir /s /q backend\app\__pycache__ 2>nul || true
	rmdir /s /q .pytest_cache 2>nul || true

lint:
	cd backend && .\venv\Scripts\ruff check . || true
	cd frontend && npx eslint src --ext .jsx,.js 2>nul || true
