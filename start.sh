#!/usr/bin/env bash
# Sentinel Bridge — One-click dev launcher (Linux/macOS)
# Starts: Redis, PostgreSQL, Backend, Celery, Frontend, Admin-Frontend, Ollama
# Usage:  ./start.sh
#         ./start.sh --no-ollama
#         ./start.sh --no-admin

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
ADMIN_DIR="$PROJECT_DIR/admin-frontend"
VENV_DIR="$BACKEND_DIR/venv"

# ── Load nvm if available (ensures npm/node are on PATH) ────────────
# Resolve the real home first: under sudo HOME=/root but the user's nvm
# lives in the real user's home, so node would never load.
REAL_HOME="${SUDO_USER:+/home/$SUDO_USER}"
REAL_HOME="${REAL_HOME:-$HOME}"
export NVM_DIR="$REAL_HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh" 2>/dev/null

START_OLLAMA=true
START_ADMIN=true
for arg in "$@"; do
  case "$arg" in --no-ollama) START_OLLAMA=false;; --no-admin) START_ADMIN=false;; esac
done

info()  { echo -e "${BLUE}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✖${NC} $*"; }

PIDS=()
cleanup() {
  echo ""
  warn "Shutting down all services..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    # kill children of process too
    pkill -P "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null
  ok "All stopped."
  exit 0
}
trap cleanup SIGINT SIGTERM

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║    Sentinel Bridge  —  Dev Mode      ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── 1. Redis ────────────────────────────────────────────────────────
info "Redis..."
REDIS_OK=false
if command -v redis-cli &>/dev/null && redis-cli ping 2>/dev/null | grep -q PONG; then
  ok "Redis already running (native)."
  REDIS_OK=true
else
  # Try docker
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
      ok "Redis already running (Docker)."
      REDIS_OK=true
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
      docker start sentinel-redis >/dev/null 2>&1 && { ok "Redis restarted (Docker)."; REDIS_OK=true; }
    else
      docker run -d --name sentinel-redis -p 6379:6379 redis:7 >/dev/null 2>&1 && { ok "Redis started (Docker :6379)."; REDIS_OK=true; }
    fi
  fi
fi
if [[ "$REDIS_OK" == false ]]; then
  warn "Redis not available. Rate-limiting will use in-memory fallback."
  warn "Install Redis: sudo apt install redis-server && sudo systemctl start redis"
fi

# ── 2. PostgreSQL ───────────────────────────────────────────────────
info "PostgreSQL..."
PG_OK=false
if pg_isready -q 2>/dev/null; then
  ok "PostgreSQL already running."
  PG_OK=true
else
  if sudo systemctl start postgresql 2>/dev/null; then
    ok "PostgreSQL started."
    PG_OK=true
  else
    warn "Could not start PostgreSQL automatically."
    warn "Start manually: sudo systemctl start postgresql"
  fi
fi

# ── Save npm/node paths (before venv activation may shadow them) ────
NPM_BIN=""
for p in "$REAL_HOME/.nvm/versions/node/"*/bin/npm /usr/bin/npm /usr/local/bin/npm; do
  [[ -x "$p" ]] && { NPM_BIN="$p"; break; }
done
if [[ -z "$NPM_BIN" ]]; then
  fail "npm not found. Install Node.js first."
  exit 1
fi
ok "npm found: $NPM_BIN"
# Ensure the node binary next to npm is on PATH so `#!/usr/bin/env node`
# shebangs (npm, vite) resolve even when nvm failed to load (e.g. sudo runs).
export PATH="$(dirname "$NPM_BIN"):$PATH"

# ── 3. Backend ──────────────────────────────────────────────────────
info "Backend (uvicorn :8001)..."
if [[ ! -f "$VENV_DIR/bin/activate" ]]; then
  fail "Python venv not found at $VENV_DIR"
  fail "Run: cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"
cd "$BACKEND_DIR"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001 --log-level info \
  2>&1 | sed 's/^/[backend] /' &
PIDS+=($!)
ok "Backend starting on http://127.0.0.1:8001 (PID ${PIDS[-1]})"
sleep 2

# ── 4. Celery Worker ───────────────────────────────────────────────
info "Celery worker..."
celery -A app.worker.celery_app worker --loglevel=info --pool=solo \
  2>&1 | sed 's/^/[celery]  /' &
PIDS+=($!)
ok "Celery worker started (PID ${PIDS[-1]})"

# ── 5. Frontend ────────────────────────────────────────────────────
info "Frontend (Vite :5173)..."
cd "$FRONTEND_DIR"
"$NPM_BIN" run dev 2>&1 | sed 's/^/[front]  /' &
PIDS+=($!)
ok "Frontend starting on http://localhost:5173 (PID ${PIDS[-1]})"

# ── 6. Admin Frontend ──────────────────────────────────────────────
if [[ "$START_ADMIN" == true ]]; then
  info "Admin-frontend (Vite :5174)..."
  cd "$ADMIN_DIR"
  "$NPM_BIN" run dev 2>&1 | sed 's/^/[admin]   /' &
  PIDS+=($!)
  ok "Admin starting on http://localhost:5174 (PID ${PIDS[-1]})"
fi

# ── 7. Ollama ──────────────────────────────────────────────────────
if [[ "$START_OLLAMA" == true ]] && command -v ollama &>/dev/null; then
  if ! pgrep -f "ollama serve" &>/dev/null; then
    info "Ollama..."
    ollama serve 2>&1 | sed 's/^/[ollama]  /' &
    PIDS+=($!)
    ok "Ollama starting on http://localhost:11434 (PID ${PIDS[-1]})"
  else
    ok "Ollama already running."
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}"
echo -e "${BOLD}   All services up. Ctrl+C to stop.${NC}"
echo -e "${BOLD}${CYAN}════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}Backend${NC}      http://127.0.0.1:8001"
echo -e "  ${GREEN}Frontend${NC}     http://localhost:5173"
[[ "$START_ADMIN" == true ]] && echo -e "  ${GREEN}Admin${NC}        http://localhost:5174"
[[ "$REDIS_OK" == true ]] && echo -e "  ${GREEN}Redis${NC}        localhost:6379" \
  || echo -e "  ${YELLOW}Redis${NC}        NOT RUNNING (rate-limiting degraded)"
echo -e "  ${GREEN}Celery${NC}       solo pool"
[[ "$START_OLLAMA" == true ]] && command -v ollama &>/dev/null \
  && echo -e "  ${GREEN}Ollama${NC}       http://localhost:11434"
echo ""

wait
