# Sentinel Bridge - SOC/IPS/SIEM/XDR Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.139+-00ADD8.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.2+-61DAFB.svg)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.0+-646CFF.svg)](https://vitejs.dev)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](https://www.python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-TimescaleDB-blue.svg)](https://www.timescale.com)

A unified Security Operations Center (SOC), Intrusion Prevention System (IPS), Security Information and Event Management (SIEM), and Extended Detection and Response (XDR) platform built with FastAPI and React. The project is designed as a multi-tenant, role-based security platform with real-time monitoring, threat detection, incident response, and automation capabilities.

## Table of Contents

- [1. Architecture Overview](#1-architecture-overview)
- [2. Project Structure](#2-project-structure)
- [3. Core Components](#3-core-components)
- [4. Advantages & Key Features](#4-advantages--key-features)
- [5. Technologies & Libraries](#5-technologies--libraries)
- [6. Working Logic](#6-working-logic)
- [7. Getting Started](#7-getting-started)
- [8. Configuration](#8-configuration)
- [9. API & Access](#9-api--access)
- [10. Project Status & Notes](#10-project-status--notes)

## 1. Architecture Overview

Sentinel Bridge follows a layered, microservices-oriented architecture with clear separation between presentation, application, domain, and infrastructure layers.

### 1.1 High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND LAYER                         │
├─────────────────────────────┬─────────────────────────────────┤
│      SOC Frontend (Vite)     │    Admin Frontend (Vite)       │
│      - React + Tailwind     │    - React + Vite              │
│      - React Router         │    - Surveillance UI           │
│      - React Query          │    - Admin Supervision         │
│      - Toast Notifications  │    - Recharts (Analytics)     │
└──────────┬──────────────────┴─────────────────┬───────────────┘
           │                                   │
           └───────────────┬───────────────────┘
                           │ HTTP/REST (JWT/API Key)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        BACKEND LAYER                          │
│                    FastAPI (Async/REST API)                   │
├─────────────────────────────────────────────────────────────────┤
│  Interface (API)  │  Application  │  Domain  │  Infrastructure │
│  - Routers        │  - Services   │  - Models│  - DB/Repos     │
│  - Middleware     │  - Bootstrap  │  - Rules │  - Adapters     │
│  - Auth/RBAC      │  - Orchestr.  │         │  - External     │
└──────────┬──────────────┬─────────────┬────────┴───────────────┘
           │              │             │
           ▼              ▼             ▼
┌─────────────────┐ ┌─────────┐ ┌─────────────────────────────────┐
│   PostgreSQL    │ │  Redis  │ │        External Systems        │
│ (TimescaleDB)   │ │ (Cache/ │ │  - Wazuh SIEM/Indexer          │
│ - Multi-tenant  │ │ Broker) │ │  - Suricata IDS/IPS           │
│ - Hypertables   │ │ Celery  │ │  - Ollama (LLM/AI)            │
│ - Audit Logs    │ │ Worker  │ │  - Threat Intel (AbuseIPDB)   │
└─────────────────┘ └─────────┘ └─────────────────────────────────┘
```

### 1.2 Design Principles

- **Layered Clean Architecture**: Separation of concerns with `interface/`, `application/`, `domain/`, and `infrastructure/` layers
- **Multi-Tenancy**: Tenant isolation via `tenant_id` across all models, middleware, and queries
- **RBAC (Role-Based Access Control)**: Hierarchical roles (`viewer < analyst < admin < super_admin`) with per-route policy enforcement
- **Defense-in-Depth**: API key + JWT authentication, webhook token/slug auth, CORS, and tenant scoping
- **Event-Driven**: Celery workers for asynchronous processing, outbox pattern for reliable event handling
- **Data Integrity**: TimescaleDB hypertables for time-series data (alerts, suricata alerts), composite primary keys, and proper indexing

## 2. Project Structure

```text
projet-pfe-version4/
├── backend/                        # FastAPI backend application
│   ├── app/
│   │   ├── interface/              # API layer (routers, middleware, schemas)
│   │   │   ├── api/                # REST endpoint routers (alerts, auth, cases, etc.)
│   │   │   ├── middleware/         # Cross-cutting concerns (tenant, action log)
│   │   │   └── main.py             # Main FastAPI app composition
│   │   ├── application/            # Business logic & orchestration
│   │   │   ├── bootstrap.py        # Startup initialization
│   │   │   ├── services/           # Application services
│   │   │   └── system_config.py    # System configuration management
│   │   ├── domain/                 # Domain models & business rules
│   │   │   ├── models.py           # Core domain models (Alert, SuricataAlert, Case...)
│   │   │   ├── rule_models.py      # Rule engine models (MITRE mapping)
│   │   │   └── pipeline_models.py  # Event pipeline models
│   │   ├── infrastructure/         # External integrations & persistence
│   │   │   ├── persistence/        # DB repositories, password store
│   │   │   ├── scanner.py          # Network scanning utilities
│   │   │   └── integrations/       # Wazuh, Suricata, Threat Intel adapters
│   │   ├── core/                   # Shared utilities (auth, config, RBAC, db)
│   │   ├── auth.py                 # Authentication utilities (delegates to core)
│   │   ├── models.py               # Model exports (re-exports domain models)
│   │   └── worker.py               # Celery worker entry point
│   ├── requirements.txt            # Python dependencies
│   ├── start.sh / start.bat       # Startup scripts
│   └── alembic/                    # Database migrations
├── frontend/                      # SOC Dashboard (main frontend)
│   ├── src/
│   │   ├── components/             # React UI components
│   │   ├── pages/                  # Page components/routes
│   │   ├── lib/                    # Utilities (api client, auth, context)
│   │   ├── hooks/                  # Custom React hooks
│   │   └── styles/                 # CSS/Tailwind styles
│   ├── package.json
│   └── vite.config.js
├── admin-frontend/                # Admin/Supervision Dashboard
│   ├── src/
│   │   ├── components/             # Admin-specific components
│   │   ├── views/                  # Admin views (Dashboard, Surveillance, etc.)
│   │   ├── pages/                  # Page views
│   │   ├── api.js                  # API client for admin
│   │   └── styles/                 # Admin styles
│   ├── package.json
│   └── vite.config.js
├── docker-compose.yml             # Development Docker setup
├── docker-compose.prod.yml        # Production Docker setup
├── Makefile                       # Build/run shortcuts
└── README.md                      # Project documentation
```

## 3. Core Components

### 3.1 Backend Components

#### 3.1.1 API Layer (`interface/`)
- **Routers**: Modular REST endpoints organized by domain (alerts, cases, rules, hunts, playbooks, intel, investigations, response, reporting, exports, auth, tenants, surveillance, etc.)
- **Middleware**:
  - `TenantMiddleware`: Enforces tenant context on all requests (`request.state.tenant_id`)
  - `ActionLogMiddleware`: Audits and logs user actions for compliance
- **RBAC Enforcement**: Per-router policies with `apply_role_guard()` applied after router inclusion

#### 3.1.2 Application Layer (`application/`)
- **Bootstrap**: `run_startup()` handles database initialization, migration checks (MITRE columns, intel columns), TimescaleDB hypertables, and service initialization
- **Services**: Domain/application services for business logic (alert processing, case management, threat intel enrichment, surveillance, face recognition)
- **System Config**: Centralized configuration management with tenant-scoped values

#### 3.1.3 Domain Layer (`domain/`)
- **Core Models**: `Alert`, `SuricataAlert`, `Device`, `Asset`, `Case`, `CaseAlertLink`, `TimelineEvent`, `Hunt`, `Tenant`, `TenantUser`, `AccessLog`, `ActionLog`, etc.
- **Rule Models**: `Rule`, `RuleMatchOutbox` with MITRE ATT&CK integration (`mitre_attack_ids`, `tactics`)
- **Pipeline Models**: Event normalization and processing pipeline

#### 3.1.4 Core Services (`core/`)
- **Auth & JWT**: Token verification, scope validation (`has_scopes`, `has_scopes_or_api_key`)
- **RBAC**: Role hierarchy, `require_role()` dependency, policy enforcement (`ROUTER_POLICIES`)
- **Database**: SQLAlchemy session management, tenant-scoped queries
- **Config**: Pydantic settings with environment-based configuration

### 3.2 Frontend Components (SOC Frontend)

Located in `frontend/src/`, the main SOC dashboard includes:

- **Authentication & Layout**: Login flow with JWT, protected routes, global layout
- **Alert Management**: Real-time alert viewing, filtering, enrichment with threat intel
- **Case Management (Cases)**: Incident case creation, linking alerts, triage workflow
- **Hunting (Hunts)**: Threat hunting interface and queries
- **Playbooks**: Automated response playbooks and execution tracking
- **Threat Intelligence (Intel)**: IOC management and enrichment
- **Investigations**: Investigation tracking and evidence management
- **Response & Reporting**: Response actions and report generation
- **Surveillance**: User access monitoring, face verification logs
- **Settings & Admin**: System configuration, user management
- **API Client**: `createFetchWithAuth()` with global toast error handling, 401/429 retry logic

### 3.3 Admin Frontend (Admin Supervision)

Located in `admin-frontend/src/`, provides administrative oversight:

- **Admin Dashboard**: System metrics, overview, and analytics (Recharts)
- **Surveillance View**: Real-time surveillance monitoring, access logs, face verification
- **User & Tenant Management**: Tenant administration, user provisioning
- **System Monitoring**: Performance metrics, alerts overview
- **Styles**: Dedicated CSS for surveillance/admin views (`styles/surveillance.css`)

### 3.4 Background Processing

- **Celery Worker** (`worker.py`): Asynchronous task processing (alert enrichment, playbook execution, reports, etc.)
- **Redis**: Message broker for Celery, caching layer, and rate-limiting (fallback to in-memory)
- **Outbox Pattern**: `RuleMatchOutbox`, `PipelineEvent` for reliable event delivery and replay

## 4. Advantages & Key Features

### 4.1 Security & Compliance

- **Multi-Tenant Isolation**: Strict tenant scoping on all data models and queries
- **Granular RBAC**: Role-based access with hierarchical permissions (viewer/analyst/admin/super_admin)
- **Dual Authentication**: Support for JWT Bearer tokens and API keys; console admin tokens for operator access
- **Audit Trail**: Comprehensive action logging (`ActionLog`, `TimelineEvent`) with actor, resource, IP, and timestamp tracking
- **Webhook Security**: Token-based and slug-based per-tenant webhook authentication
- **CORS & SSL Control**: Configurable CORS origins; SSL verification based on environment

### 4.2 Detection & Response (SOC/IPS/SIEM/XDR)

- **Alert Normalization**: Unified alert model with pipeline processing (`normalized_severity`, `pipeline_source`, `pipeline_processed_at`)
- **Threat Intelligence Enrichment**: Automatic enrichment of alerts with AbuseIPDB/other intel providers (score, verdict, source, checked timestamp)
- **Case Management**: Triage workflow via `CaseAlertLink` (status/note/triaged_by/triaged_at) - triage lives on links, not on raw alerts
- **MITRE ATT&CK Mapping**: Rules mapped to MITRE techniques/tactics (`mitre_attack_ids`, `tactics`)
- **Playbook Automation**: Automated incident response with execution tracking (`PlaybookRun`) and outbox guard for idempotency
- **Hunting Capabilities**: Proactive threat hunting interface and workflows
- **Suricata Integration**: Native Suricata alert ingestion and processing

### 4.3 Monitoring & Access Control

- **Face Recognition**: InsightFace-based face recognition engine (`buffalo_s` model: SCRFD detector + ArcFace, 512-dim embeddings, cosine threshold 0.45). Lazy-loaded, thread-safe
- **Access Surveillance**: Login/logout tracking, face verification status, session duration, IP tracking
- **Device & Asset Inventory**: Track network devices, assets with employee/department mapping
- **Network Sensor Monitoring**: Bandwidth and traffic metrics per sensor
- **Wazuh Integration**: SIEM log ingestion and correlation

### 4.4 Architecture & Operations

- **Time-Series Optimization**: TimescaleDB hypertables for high-volume alert data with composite PKs (`(id, timestamp)`)
- **Scalable Background Jobs**: Celery + Redis for async processing (enrichment, reports, playbook runs)
- **Idempotent Processing**: Outbox pattern with unique constraints prevents duplicate processing
- **Multi-Tenant Ready**: All tables include `tenant_id`; middleware enforces tenant context
- **Developer-Friendly**: Auto-setup scripts (`start.sh`), Docker compose for dev/prod, Makefile targets, hot-reload in dev mode
- **Port Flexibility**: Backend runs on `:8001` (avoids conflict with Coolify on `:8000`); frontends configured accordingly

### 4.5 Data & Analytics

- **Rich Alert Enrichment**: Alerts enriched with asset/device metadata (employee name, department, MAC address)
- **Reporting**: Report generation (PDF/XHTML) with templates, schedules, recipients, and logs
- **Investigation Management**: Structured investigations with evidence and recommendations
- **Response Tracking**: Response action results with rollback capability

## 5. Technologies & Libraries

### 5.1 Backend (Python)

| Library | Version/Range | Purpose |
|---|---|---|
| **FastAPI** | >=0.139,<1.0 | Modern async web framework |
| **Uvicorn** | >=0.32,<1.0 | ASGI server |
| **SQLAlchemy** | >=2.0,<3.0 | ORM with async support patterns |
| **pg8000** | >=1.31,<2.0 | PostgreSQL driver (pure Python) |
| **Pydantic & Pydantic-Settings** | >=2.10,<3.0 / >=2.8,<3.0 | Data validation & configuration |
| **Celery** | >=5.6,<6.0 | Distributed task queue |
| **Redis** | >=4.5.2,<5.0.0 | Broker/cache for Celery |
| **python-jose[cryptography]** | >=3.5,<4.0 | JWT token handling |
| **passlib[bcrypt]** | >=1.7,<2.0 / bcrypt>=4.2,<6.0 | Password hashing |
| **httpx** | >=0.28,<1.0 | Async HTTP client (threat intel, external APIs) |
| **python-multipart** | >=0.0.20,<1.0 | File upload support |
| **insightface** | ==1.0.1 | Face recognition (SCRFD + ArcFace) |
| **onnxruntime** | ==1.29.0 | ONNX inference runtime |
| **opencv-python-headless** | >=4.8,<5.0 | Computer vision (headless) |
| **numpy** | >=2.2,<3.0 | Numerical computing |
| **Pillow** | >=11.0,<12.0 | Image processing |
| **scapy** | >=2.6,<3.0 | Packet manipulation/scanning |
| **python-nmap** | >=0.7,<1.0 | Nmap integration |
| **paramiko** | >=3.5,<4.0 | SSH client |
| **xhtml2pdf** | >=0.2,<1.0 | PDF report generation |
| **jinja2** | >=3.1,<4.0 | Template engine |
| **tenacity** | >=9,<10 | Retry logic |
| **aiosmtplib** | >=1.1,<2.0 | Async SMTP |
| **syslog-rfc5424-parser** | >=0.3.0 | Syslog parsing |
| **psutil** | >=7.0,<8.0 | System/process monitoring |
| **urllib3** | >=2.3,<3.0 | HTTP utilities |

### 5.2 Frontend (React/JavaScript)

| Library | Version | Purpose |
|---|---|---|
| **React** | ^18.2.0 | UI library |
| **React DOM** | ^18.2.0 | React renderer |
| **React Router DOM** | ^7.18.1 | Client-side routing |
| **Vite** | ^5.0.0 | Build tool & dev server |
| **@vitejs/plugin-react** | ^4.0.0 | React plugin for Vite |
| **Tailwind CSS** | ^4.0.0 | Utility-first CSS framework |
| **@tailwindcss/postcss** | ^4.2.2 | Tailwind PostCSS integration |
| **Autoprefixer** | ^10.5.0 | CSS vendor prefixing |
| **PostCSS** | ^8.5.10 | CSS transformation |
| **@tanstack/react-query** | ^5.101.4 | Data fetching & caching |
| **React Toastify** | ^9.1.3 | Toast notifications |
| **Recharts** | ^2.10.0 / ^2.12.7 | Charts & data visualization |
| **Lucide React** | ^0.300.0 | Icon library |
| **clsx** | ^2.1.1 | Conditional class names |

### 5.3 Infrastructure & Tools

| Tool | Purpose |
|---|---|
| **PostgreSQL + TimescaleDB** | Relational DB with time-series hypertables |
| **Redis** | Message broker, cache, rate-limiting |
| **Celery** | Async task processing & scheduling |
| **Docker / Docker Compose** | Containerization (dev & prod) |
| **Wazuh** | SIEM platform integration |
| **Suricata** | IDS/IPS engine |
| **Ollama** | Local LLM inference |
| **Nginx** | Reverse proxy (prod) |
| **Make** | Task automation |

## 6. Working Logic

### 6.1 Request Flow (API Request Lifecycle)

1. **Request Arrival**: HTTP request hits FastAPI app (`app.interface.main:app`)
2. **CORS Middleware**: Validates origins per `ALLOWED_ORIGINS`
3. **Tenant Middleware**: Extracts/sets `tenant_id` from headers/context, attaches to `request.state`
4. **Action Log Middleware**: Logs user actions for audit trail
5. **Route Matching**: FastAPI routes request to appropriate router
6. **RBAC Enforcement**: `apply_role_guard()` injects `require_role(min_role)` dependency at route level (index 0)
7. **Authentication**: 
   - API Key: checked against `API_KEY` or `SUPER_ADMIN_API_KEY`
   - JWT Bearer: verified via `verify_token()`; falls back to admin console tokens (`verify_admin_token()`) for operator access
   - Webhook: `webhook_token_auth` or `webhook_slug_auth` for external integrations
8. **Authorization**: Role hierarchy check (`ROLE_RANK`) vs required minimum role
9. **Business Logic**: Application services/domain logic processes request
10. **Data Access**: SQLAlchemy queries with tenant scoping (`Alert.tenant_id == tenant_id`)
11. **Response**: Structured JSON returned to client

### 6.2 Alert Processing Pipeline

1. **Ingestion**: Alerts arrive via API endpoints (manual), webhooks (Wazuh/Suricata), or scanners
2. **Tenant Scoping**: All ingested alerts tagged with `tenant_id` (from request context)
3. **Normalization**: Pipeline sets `normalized_severity`, `pipeline_source`, `pipeline_processed_at` (F1 Pipeline)
4. **Threat Intel Enrichment** (F3): Async enrichment via Celery - queries threat intel providers (AbuseIPDB), sets `intel_score`, `intel_verdict`, `intel_source`, `intel_checked_at`
5. **Storage**: Persisted to `alerts` or `suricata_alerts` (TimescaleDB hypertables with composite PK `(id, timestamp)`)
6. **Case Linking**: Analysts can link alerts to cases via `CaseAlertLink` (triage state lives here: `status`, `note`, `triaged_by`, `triaged_at`)
7. **Correlation**: Rules engine evaluates alerts against `Rule` definitions with MITRE ATT&CK mappings
8. **Playbook Execution** (F3): On rule match, `on_rule_match()` publishes to `CHANNEL_RULE_MATCH`; approved `PlaybookRun` instances execute (guarded by unique constraint `UNIQUE(event_id, playbook_id)`)

### 6.3 Face Recognition & Surveillance Logic

1. **Model Loading**: InsightFace `FaceAnalysis` initialized with `buffalo_s` model (det_500m SCRFD detector + w600k_mbf ArcFace recognizer, 512-dim embeddings). Lazy-loaded via thread-safe `_get_app()`
2. **Face Detection/Recognition**: For login/verification, face embeddings compared using cosine similarity (threshold 0.45)
3. **Models Location**: Downloaded to `~/.insightface/models/buffalo_s/` (auto-installed by `start.sh`)
4. **Access Logging**: Successful/failed verification logged to `AccessLog` with `face_verified`, `face_image`, `ip_address`, `login_method`, `session_duration`
5. **Surveillance API**: Provides `/api/surveillance/users`, `/api/surveillance/logs`, `/api/surveillance/stats` for monitoring

### 6.4 RBAC Logic

1. **Role Hierarchy**: `viewer` (0) < `analyst` (1) < `admin` (2) < `super_admin` (3)
2. **Policy Definition**: `ROUTER_POLICIES` maps router names to policies `{read, write, exempt, exempt_paths}`
3. **Guard Application**: `apply_role_guard()` iterates all routes in router; for non-exempt routes (or non-exempt paths), inserts `Depends(require_role(min_role))` at dependency index 0 (before legacy deps)
4. **Role Resolution**: `require_role()` resolves user role from DB (`TenantUser.role`) as source of truth, falls back to legacy JSON store
5. **Auth Lane Priority**:
   - **API Key**: If valid `API_KEY` and required role <= admin → allow with admin role; if `SUPER_ADMIN_API_KEY` and requesting super_admin → allow
   - **JWT**: Verify token; if fails, try admin console token (`ADMIN_JWT_SECRET`) → treated as `super_admin` (operator access)
   - **Scope Check**: For JWT, ensure token scopes/role satisfy minimum required rank

### 6.5 Multi-Tenancy Logic

1. **Tenant Context**: `TenantMiddleware` sets `request.state.tenant_id` (from headers/context)
2. **Model Scoping**: All tenant-scoped tables have `tenant_id` (String(36), indexed)
3. **Query Enforcement**: All read/write queries filter by `tenant_id` (e.g., `.filter(Alert.tenant_id == tenant_id)`)
4. **Tenant Registration**: Public endpoint `/api/tenants/register` is exempt from write guard per policy
5. **Default Tenant**: Falls back to `"default"` if tenant context not resolved

### 6.6 Background Job & Idempotency

1. **Celery App**: Configured in `worker.py`, broker=Redis, backend=Redis
2. **Playbook Execution**: `PlaybookRun` has `UNIQUE(event_id, playbook_id)` constraint; pre-insert guard prevents duplicates (replay = no-op)
3. **Outbox Pattern**: `RuleMatchOutbox` ensures reliable event publishing; events processed asynchronously
4. **Threading**: Approved playbook runs execute in daemon threads

## 7. Getting Started

### 7.1 Prerequisites

- **Python 3.10+** (tested with 3.10+)
- **Node.js 18+ & npm** (for frontends)
- **PostgreSQL** (recommended with TimescaleDB for hypertables)
- **Redis** (for Celery broker/cache)
- **Docker & Docker Compose** (optional, for containerized setup)
- **Git**

### 7.2 Installation & Setup

#### Option 1: Automated Setup (Linux/macOS) - Recommended

The `start.sh` script handles automatic installation of all dependencies:

```bash
# Clone the repository
git clone https://github.com/saif-infinity/projet-soc-ips-siem-xdr-.git
cd projet-soc-ips-siem-xdr-

# Make script executable (Linux)
chmod +x start.sh

# Run with setup (installs deps, venv, models, npm packages)
./start.sh --setup

# Or just run (if already set up)
./start.sh
```

**`start.sh` auto-installs:**
- Python 3, python3-venv
- Node.js/npm (via nvm if needed)
- Python virtual environment + pip requirements
- InsightFace `buffalo_s` models (`~/.insightface/models/buffalo_s/`)
- npm install for both frontends (SOC + admin)
- Redis (Docker or native)

**Options:**
- `--setup`: Force full setup
- `--no-ollama`: Skip Ollama startup
- `--no-admin`: Skip admin frontend

#### Option 2: Manual Setup

**Backend:**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Fix opencv-python headless collision (critical for InsightFace)
pip uninstall -y opencv-python
pip install --force-reinstall --no-deps opencv-python-headless==4.14.0.94

# Download InsightFace models (if not present)
# Models auto-download on first FaceAnalysis init, or manually place in ~/.insightface/models/buffalo_s/
```

**Frontend (SOC):**

```bash
cd frontend
npm install
```

**Admin Frontend:**

```bash
cd admin-frontend
npm install
```

**External Services:**

- Start PostgreSQL (with database created)
- Start Redis: `redis-server` or `docker run -d -p 6379:6379 redis:7`

### 7.3 Running the Application

#### Development Mode

**All services via start.sh:**

```bash
./start.sh
```

This starts: Redis, Backend (FastAPI on :8001), SOC Frontend (Vite), Admin Frontend (Vite), Worker (Celery), plus optional Ollama/Wazuh.

**Via Makefile (Windows-oriented):**

```bash
make dev  # Starts all services (Windows cmd syntax)
make dev-backend
make dev-frontend
make dev-worker
```

**Manual:**

```bash
# Terminal 1 - Backend
cd backend && source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001

# Terminal 2 - Celery Worker
cd backend && source venv/bin/activate
celery -A app.worker.celery_app worker --loglevel=info --pool=solo -B

# Terminal 3 - SOC Frontend
cd frontend && npm run dev

# Terminal 4 - Admin Frontend
cd admin-frontend && npm run dev
```

#### Production Mode

```bash
# Via Docker Compose
docker compose -f docker-compose.prod.yml up -d --build

# Or via Makefile
make prod
```

## 8. Configuration

### 8.1 Environment Variables

Create `backend/.env` from `.env.example` (if available). Key configuration items:

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` or `production` (affects SSL verification) |
| `DATABASE_URL` | - | PostgreSQL connection string |
| `JWT_SECRET_KEY` | - | Secret for JWT token signing (generate with `openssl rand -hex 32`) |
| `ADMIN_JWT_SECRET` | - | Secret for console admin tokens (operator access) |
| `API_KEY` | - | Global API key for service access |
| `ADMIN_API_KEY` | - | Admin API key |
| `SUPER_ADMIN_API_KEY` | - | Super admin API key |
| `SUPER_ADMIN_PASSWORD` | - | Super admin password |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection for Celery |
| `REDIS_PASSWORD` | - | Redis password if enabled |
| `ALLOWED_ORIGINS` | - | CORS allowed origins (comma-separated) |
| `THREAT_INTEL_ENABLED` | `false` | Enable/disable threat intel enrichment (F3) |
| `THREAT_INTEL_API_KEY` | - | AbuseIPDB API key (recommended when enabled) |
| `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS` | - | Wazuh SIEM integration |
| `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` | - | Wazuh Indexer |
| `SURICATA_HOST`, `SURICATA_USER`, `SURICATA_PASS` | - | Suricata integration |
| `NOTIFICATION_ENCRYPTION_KEY` | - | Fernet key for encrypted notifications |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | - | Stripe billing (optional) |
| `VITE_AUTOLOGIN` | `0` | Frontend dev: `1` to bypass login (NEVER use in prod) |

**Important Notes:**
- `ADMIN_JWT_SECRET` allows console admin tokens to be accepted as `super_admin` operator access (used by admin-frontend)
- `THREAT_INTEL_ENABLED` defaults to `false` (F3 feature flag)
- Backend runs on port `8001` due to Coolify occupying port `8000` on this environment
- Frontend proxies via Vite to backend `:8001`

### 8.2 Frontend Configuration

**SOC Frontend (`frontend/.env`):**
```env
VITE_AUTOLOGIN=0  # 1 = dev bypass only
```

**API Base:** `frontend/src/lib/api.js` defaults to empty string `""` (uses Vite proxy to backend :8001)

**Admin Frontend (`admin-frontend/src/api.js`):** Points to backend API (configure base URL as needed for deployment)

## 9. API & Access

### 9.1 Endpoints

Once running, access:
- **Backend API**: [http://localhost:8001](http://localhost:8001)
- **API Docs (Swagger)**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **ReDoc**: [http://localhost:8001/redoc](http://localhost:8001/redoc)
- **SOC Frontend**: [http://localhost:5173](http://localhost:5173) (default Vite port)
- **Admin Frontend**: [http://localhost:5174](http://localhost:5174) or next available port

### 9.2 Authentication

The API supports multiple auth methods:
1. **Bearer JWT**: `Authorization: Bearer <jwt_token>` (user tokens)
2. **API Key**: `X-API-Key: <api_key>` header (service/admin access)
3. **Admin Console Token**: Bearer token signed with `ADMIN_JWT_SECRET` → treated as `super_admin` (operator)
4. **Webhook Tokens**: `X-SOC-Token` for webhook endpoints (with tenant resolution)

### 9.3 RBAC Policies (Key Highlights)

- **Auth routes**: Exempt (public login/registration)
- **Rules**: Admin read/write; `/api/rules/coverage` exempt for analysts
- **Tenants**: Viewer read, Admin write; `/api/tenants/register` exempt (public registration)
- **Playbooks/Response/Reporting**: Analyst read, Admin write
- **Settings/Database**: Admin-level access (settings write = admin; DB exempt)
- **Faces/Surveillance/Admin/SuperAdmin**: Varying policies (see `ROUTER_POLICIES` in `interface/main.py`)

## 10. Project Status & Notes

### 10.1 Important Technical Notes

- **Port Binding**: On this environment, port `8000` is used by Coolify UI; backend runs on `:8001` (configured throughout stack: start.sh, Makefile, docker-compose.prod.yml, Vite proxies)
- **InsightFace/OpenCV Collision**: `insightface` depends on `opencv-python` (GUI) which conflicts with `opencv-python-headless`. The setup explicitly uninstalls GUI and reinstalls headless `4.14.0.94`
- **Backend as Package**: `backend/app` is a top-level package (no `backend/__init__.py`); relative imports follow specific depth rules (1-dot from `app/*.py`, 2-dots from `app/services/`, 3-dots from deeper subdirs)
- **Triage Model**: Case triage/status lives on `CaseAlertLink` (not on `Alert` or `SuricataAlert`) - this is by design
- **Multi-Tenant Alignment**: Schema includes `tenant_id` across 10+ tables; `alerts` and `suricata_alerts` have intel fields (`intel_score`, `intel_verdict`, `intel_source`, `intel_checked_at`)
- **MITRE Columns**: `rules.mitre_attack_ids`/`tactics` exist; migration `ensure_mitre_columns` runs at bootstrap and in rules module
- **Face Recognition Models**: Auto-downloaded to `~/.insightface/models/buffalo_s/` via `start.sh` setup

### 10.2 Known Considerations

- **Dev Autologin**: `VITE_AUTOLOGIN=1` bypasses login in dev only - **never** enable in production
- **Redis Fallback**: If Redis unavailable, rate-limiting uses in-memory fallback (logged as warning)
- **Threat Intel Disabled by Default**: `THREAT_INTEL_ENABLED=false` - set to `true` with valid API key for enrichment
- **TimescaleDB**: Hypertables created at startup for time-series optimization on alerts/suricata_alerts

---

**Sentinel Bridge** - Unified Security Operations Platform | Built for detection, investigation, and response at scale.
