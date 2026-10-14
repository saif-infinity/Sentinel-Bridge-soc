# 🛡️ Sentinel Bridge - SOC/IPS/SIEM/XDR Platform

<div align="center">

![FastAPI](https://img.shields.io/badge/FastAPI-0.139%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18.2%2B-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-5.0%2B-646CFF?style=for-the-badge&logo=vite&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL%20%2B%20TimescaleDB-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=for-the-badge&logo=celery&logoColor=white)

**Unified Security Operations Platform — Detection • Investigation • Response • Automation**

[🚀 Get Started](#-getting-started) • [📐 Architecture](#-architecture-overview) • [🔄 Workflows](#-data-flow--workflows) • [📚 API Docs](#-api--access) • [⚙️ Configuration](#%EF%B8%8F-configuration)

</div>

---

## 📖 Overview

**Sentinel Bridge** is a next-generation, multi-tenant Security Operations Center (SOC) platform that unifies Intrusion Prevention (IPS), Security Information & Event Management (SIEM), and Extended Detection & Response (XDR) capabilities. Built with a modern **FastAPI + React** stack, it delivers real-time threat detection, intelligent correlation, automated response, and comprehensive security monitoring in a single, cohesive platform.

> 🎯 **Mission**: Empower security teams to detect, investigate, triage, and respond to threats faster with automation, rich context, and auditable workflows.

---

## ✅ Statut réel des fonctionnalités

> Cette section existe parce que le reste du README décrirait sinon des capacités
> que le code n'a pas. Un SOC qui ment sur son propre état est pire qu'un SOC
> incomplet : c'est précisément quand une sonde tombe que l'analyste doit le savoir.
> Mise à jour : 2026-10.

### Implémenté et fonctionnel
| Capacité | Où |
|---|---|
| Ingestion → normalisation ECS-like → pipeline d'acceptation | `backend/app/application/{pipeline,normalization}.py` |
| Corrélation par règles persistée en base + MITRE ATT&CK | `backend/app/application/rules/`, `domain/rule_models.py` |
| Cases, investigations, hunts, recommandations | `backend/app/application/{cases,hunts,investigations}/` |
| RBAC (viewer < analyst < admin < super_admin) + multi-tenancy | `backend/app/core/rbac.py`, `interface/middleware/tenant.py` |
| Ingestion syslog agentless (RFC5424, TCP+UDP 1514) | `backend/app/infrastructure/syslog/` |
| Stockage time-series TimescaleDB (hypertables) | `backend/app/infrastructure/timescale.py` |
| Threat intelligence (AbuseIPDB) avec cache TTL | `backend/app/infrastructure/threat_intel/` |
| Playbooks SOAR + actions de réponse réelles (blocage Wazuh, quarantaine SSH, restart de service) avec approbation et rollback | `backend/app/application/{soar,response}/` |
| Notifications (email/Telegram/webhook) chiffrées Fernet | `backend/app/infrastructure/notifications/` |
| Rapports (génération + templates + livraison) et exports | `backend/app/application/reporting/` |
| Terminal de diagnostic restreint vers Suricata (SSH, host key vérifiée) | `backend/app/interface/api/terminal.py` |

### Partiel — dépend d'un déploiement réel
| Capacité | Limite |
|---|---|
| Source Wazuh (alertes, agents, topologie) | Nécessite un Wazuh manager joignable. S'il est absent, la topologie renvoie encore des **agents fictifs** (`application/wazuh/topology.py`) — à remplacer par un état `source_unavailable`. |
| Source Suricata | Désactivée par défaut (`ENABLE_SURICATA_SOURCE=False`) ; ingestion EVE fonctionnelle. |
| Terminal Wazuh | Passe par `docker exec` depuis le backend : ne fonctionne que si le backend a accès au socket Docker (donc **pas** dans `docker-compose.prod.yml`, qui est `read_only` + sans socket). |
| Matériel des agents | `infrastructure/wazuh/client.py` renvoie des valeurs **mock** (`"Intel Core i7-10700K (Mock)"`) quand l'agent ne répond pas. |
| IPS | Suricata est utilisé en **IDS** (détection). Il n'y a pas de blocage inline ; le "IPS" du titre passe par les actions de réponse (blocage d'IP via Wazuh/SSH). |
| Bande passante « par analyste » | `interface/api/sensors.py` échantillonne `psutil.net_io_counters()` **du serveur** et l'attribue à chaque analyste en ligne. Ce n'est pas le trafic du poste client — il faudrait l'agent hôte pour cela. |

### Non implémenté (assumé)
| Capacité | État |
|---|---|
| Push de configuration vers les équipements réseau | **Générateur de commandes CLI uniquement** (Cisco/Juniper/Arista/Fortinet/…). `POST /{id}/push-config` renvoie désormais `success: false` avec la mention *DRY RUN* : aucun transport SSH n'existe pour les équipements. |
| Test de connectivité d'un équipement | Sonde **TCP réelle** vers le port d'administration (auparavant : `random.random() > 0.3` persisté en base). Ne teste ni SSH ni l'authentification. |
| Paiement / licences (PricingPage, champs Stripe) | Interface présente, aucun backend de paiement branché. |
| Reconnaissance faciale comme facteur d'authentification | À considérer comme **expérimental et faible** : le chemin de secours compare des histogrammes couleur Haar (`cv2.compareHist`, seuil 0.78), ce n'est pas une biométrie ; la « liveness » (ratio de texture) est battue par une photo imprimée. À ne jamais utiliser comme seul facteur. |
| Honeypot | Écoute réelle sur 2323/3389/8443/5555 dans le processus API, tenant codé en dur à `default`, non isolé. À déplacer dans son propre service. |

### Dette connue
- Pas d'Alembic : le schéma est créé par `Base.metadata.create_all()` puis ajusté par **8 `ALTER TABLE` interpolés à la main**. Aucun rollback, aucun historique de version.
- Deux frontends React séparés (`frontend/`, `admin-frontend/`) avec deux systèmes de design et deux implémentations d'auth.
- La classification de sévérité « critique » diffère selon les écrans (>=7, >=8, >=10, >=12). Un helper unique existe maintenant dans `frontend/src/lib/formatters.js` ; les 6 call-sites restent à migrer.
- Le mot de passe de la console admin **est** `ADMIN_API_KEY` (secret statique partagé, pas de comptes nominatifs).

---

## 🏗️ Architecture Overview

Sentinel Bridge follows a **Clean Architecture** pattern with strict separation of concerns, ensuring maintainability, testability, and scalability.

### High-Level System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              PRESENTATION LAYER                              │
├───────────────────────────────────┬─────────────────────────────────────────┤
│           SOC Dashboard          │           Admin Supervision           │
│           (frontend/)           │           (admin-frontend/)          │
│  • React 18 + Vite + Tailwind   │  • React 18 + Vite                   │
│  • React Router DOM 7           │  • Surveillance Monitoring           │
│  • TanStack React Query         │  • Analytics with Recharts           │
│  • Toast Notifications          │  • Administrative Controls           │
└──────────────┬──────────────────┴──────────────────────────┬─────────────────┘
               │                                             │
               │  HTTPS/REST + JWT/API Key + Webhooks      │
               ▼                                             ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 API GATEWAY LAYER                            │
│                            FastAPI Application (:8001)                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│  Interface Layer        │  Application Layer      │  Domain Layer │ Infra. Layer│
│  • REST Routers         │  • Business Services    │  • Entities   │ • DB/Repos  │
│  • RBAC Middleware      │  • Orchestration        │  • Value Obj. │ • Adapters  │
│  • Tenant Middleware    │  • Bootstrap/Startup    │  • Rules      │ • Integrat. │
│  • Action Audit         │  • Event Handlers       │  • Policies   │ • External  │
└──────────┬──────────────┬─────────────────────┬───────────┴──────┬────────────┘
           │              │                     │                  │
           ▼              ▼                     ▼                  ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────────────┐ ┌─────────────────┐
│  PostgreSQL     │ │    Redis    │ │  Async Processing   │ │ External Systems│
│  + TimescaleDB  │ │  (Broker +  │ │  • Celery Worker    │ │ • Wazuh SIEM    │
│  • Hypertables  │ │   Cache)    │ │  • Task Scheduler   │ │ • Suricata IPS  │
│  • Multi-Tenant │ │             │ │  • Outbox Pattern   │ │ • Ollama LLM    │
│  • Audit Trail  │ │             │ │                     │ │ • AbuseIPDB     │
└─────────────────┘ └─────────────┘ └─────────────────────┘ └─────────────────┘
```

### Architectural Layers

| Layer | Directory | Responsibility |
|---|---|---|
| **🖥️ Interface** | `backend/app/interface/` | API contracts, HTTP routing, middleware, request/response validation, RBAC enforcement |
| **⚙️ Application** | `backend/app/application/` | Use cases, business workflows, service orchestration, cross-cutting business logic |
| **🎯 Domain** | `backend/app/domain/` | Core entities, domain models, business rules, invariants (technology-agnostic) |
| **🔌 Infrastructure** | `backend/app/infrastructure/` | External integrations (DB, Wazuh, Suricata, Threat Intel), persistence, I/O operations |

---

## 🗂️ Project Structure

```text
projet-pfe-version4/
│
├── 📦 backend/                        # FastAPI Backend (Core Engine)
│   ├── app/
│   │   ├── interface/                 # 🌐 API Layer
│   │   │   ├── api/                   # REST endpoint routers (modular by domain)
│   │   │   │   ├── alerts.py          # Alert management & enrichment
│   │   │   │   ├── cases.py           # Incident case management
│   │   │   │   ├── rules.py           # Detection rules + MITRE mapping
│   │   │   │   ├── hunts.py           # Threat hunting
│   │   │   │   ├── playbooks.py       # Automated response
│   │   │   │   ├── intel.py           # Threat intelligence
│   │   │   │   ├── investigations.py  # Investigation workflows
│   │   │   │   ├── response.py        # Response actions & rollbacks
│   │   │   │   ├── reporting.py       # Report generation
│   │   │   │   ├── auth.py            # Authentication endpoints
│   │   │   │   ├── tenants.py         # Multi-tenant management
│   │   │   │   ├── surveillance.py    # Access surveillance
│   │   │   │   ├── faces.py           # Face recognition
│   │   │   │   └── ...                # Additional domain routers
│   │   │   ├── middleware/            # HTTP middleware
│   │   │   │   ├── tenant.py          # Tenant context enforcement
│   │   │   │   └── action_log.py      # Audit/action logging
│   │   │   └── main.py                # FastAPI app composition & RBAC setup
│   │   │
│   │   ├── application/               # ⚙️ Application Layer
│   │   │   ├── bootstrap.py           # Startup initialization & migrations
│   │   │   ├── services/              # Application services
│   │   │   └── system_config.py       # System configuration
│   │   │
│   │   ├── domain/                    # 🎯 Domain Layer
│   │   │   ├── models.py              # Core domain entities
│   │   │   ├── rule_models.py         # Rule engine + MITRE ATT&CK
│   │   │   └── pipeline_models.py     # Event pipeline models
│   │   │
│   │   ├── infrastructure/            # 🔌 Infrastructure Layer
│   │   │   ├── persistence/           # Data persistence
│   │   │   ├── integrations/          # External system adapters
│   │   │   └── scanner.py             # Network scanning utilities
│   │   │
│   │   ├── core/                      # 🧩 Core Shared Utilities
│   │   │   ├── auth.py                # Auth helpers & scope validation
│   │   │   ├── rbac.py                # Role-based access control
│   │   │   ├── config.py              # Pydantic settings
│   │   │   ├── db.py                  # DB session management
│   │   │   └── jwt_utils.py           # JWT utilities
│   │   │
│   │   ├── auth.py                    # Auth facade
│   │   ├── models.py                  # Model re-exports
│   │   └── worker.py                  # Celery worker entry point
│   │
│   ├── requirements.txt               # Python dependencies
│   ├── alembic/                       # DB migrations
│   ├── start.sh                       # 🚀 Linux/macOS startup
│   └── start.bat                      # 🚀 Windows startup
│
├── 🎨 frontend/                       # SOC Dashboard (Primary UI)
│   ├── src/
│   │   ├── components/                # Reusable UI components
│   │   ├── pages/                     # Route-level pages
│   │   ├── lib/                       # Utils, API client, auth, context
│   │   ├── hooks/                     # Custom React hooks
│   │   └── styles/                    # Global styles & Tailwind
│   ├── package.json
│   └── vite.config.js
│
├── 🛠️ admin-frontend/                 # Admin & Surveillance UI
│   ├── src/
│   │   ├── components/                # Admin UI components
│   │   ├── views/                     # Admin views
│   │   ├── pages/                     # Page components
│   │   ├── api.js                     # Admin API client
│   │   └── styles/                    # Admin-specific styles
│   ├── package.json
│   └── vite.config.js
│
├── 🐳 docker-compose.yml              # Dev container orchestration
├── 🐳 docker-compose.prod.yml         # Production deployment
├── 📋 Makefile                        # Build & run automation
└── 📖 README.md                       # This documentation
```

---

## 🔧 Core Components

### 1. Backend Engine (FastAPI)

| Component | Location | Description |
|---|---|---|
| **API Routers** | `interface/api/` | Domain-driven REST endpoints with OpenAPI/Swagger documentation |
| **Tenant Middleware** | `interface/middleware/tenant.py` | Enforces tenant isolation on every request (`request.state.tenant_id`) |
| **Action Log Middleware** | `interface/middleware/action_log.py` | Comprehensive audit trail for compliance & forensics |
| **RBAC Guard** | `core/rbac.py` | Per-route role enforcement with hierarchical permissions |
| **Bootstrap** | `application/bootstrap.py` | Startup orchestration: migrations, TimescaleDB hypertables, MITRE/intel columns |
| **Celery Worker** | `worker.py` | Async task execution (enrichment, playbooks, reports, correlations) |

### 2. SOC Frontend (React)

| Component | Purpose |
|---|---|
| **Alert Management** | Real-time alert ingestion, filtering, enrichment, and triage |
| **Case Management** | Incident tracking, alert linking, timeline, investigation workflow |
| **Hunts** | Proactive threat hunting queries & saved hunts |
| **Playbooks** | Automated response playbook library & execution tracking |
| **Threat Intel** | IOC enrichment, reputation scoring, verdict tracking |
| **Investigations** | Structured investigations with evidence & recommendations |
| **Response & Reporting** | Response actions, rollbacks, PDF report generation |
| **Surveillance** | Access logs, face verification, session monitoring |

### 3. Admin Frontend (React)

| Component | Purpose |
|---|---|
| **Admin Dashboard** | System health, metrics, and security posture (Recharts visualizations) |
| **Surveillance View** | Live access monitoring, face verification logs, user activity tracking |
| **Tenant Management** | Multi-tenant provisioning, quotas, and lifecycle management |
| **System Monitoring** | Performance, alerts, sensors, and infrastructure metrics |

---

## ✨ Advantages & Key Features

### 🛡️ Security & Zero-Trust Design

- **🔐 Multi-Tenant Isolation**: Strict `tenant_id` scoping across all models, middleware, and queries
- **👥 Granular RBAC**: Hierarchical roles (`viewer` < `analyst` < `admin` < `super_admin`) with per-route policies
- **🔑 Dual Authentication**: JWT Bearer + API Keys, with console admin token support for operators
- **📝 Immutable Audit Trail**: Complete action logging (`ActionLog`, `TimelineEvent`) with actor, resource, IP, timestamp, and face verification
- **🪝 Secure Webhooks**: Token-based (`X-SOC-Token`) and slug-based per-tenant webhook authentication with constant-time comparison
- **🌐 CORS & TLS Controls**: Environment-aware SSL verification and configurable allowed origins

### 🎯 Detection, Correlation & Response (SOC/IPS/SIEM/XDR)

- **📊 Unified Alert Pipeline**: Normalized severity, pipeline source, and processing timestamps for consistent triage
- **🧠 Threat Intel Enrichment**: Automated IP/domain enrichment (AbuseIPDB) with verdict, score, source, and freshness tracking
- **🎫 Intelligent Case Management**: Triage state lives on `CaseAlertLink` (status, notes, triager, timestamps) — preserving raw alert integrity
- **🎯 MITRE ATT&CK Mapping**: Native mapping of detection rules to tactics/techniques (`mitre_attack_ids`, `tactics`)
- **🤖 Automated Response (SOAR)**: Playbook execution with idempotency guards, outbox pattern, and daemon-thread execution
- **🏹 Proactive Threat Hunting**: Flexible hunting interface for hypothesis-driven investigations
- **🕵️ Suricata IDS/IPS**: Native Suricata alert ingestion, normalization, and correlation
- **🧩 Wazuh SIEM Integration**: Log ingestion, correlation, and enriched context

### 👤 Identity, Access & Surveillance

- **👁️ Face Recognition (InsightFace)**: `buffalo_s` model (SCRFD det_500m + ArcFace w600k_mbf), 512-dim embeddings, cosine similarity threshold **0.45**. Thread-safe lazy loading
- **🚪 Access Surveillance**: Login/logout tracking, face verification status, session duration, IP, login method
- **💻 Asset & Device Inventory**: Auto-mapping of assets/devices to alerts (employee, department, MAC address)
- **📡 Network Sensor Monitoring**: Real-time bandwidth, bytes in/out, interface metrics

### ⚡ Performance, Scalability & Reliability

- **⏱️ Time-Series Optimized**: TimescaleDB hypertables for high-volume alerts (`alerts`, `suricata_alerts`) with composite PK `(id, timestamp)`
- **⚙️ Async Processing**: Celery + Redis for non-blocking enrichment, reports, playbooks, and correlations
- **🛡️ Idempotent Processing**: Outbox pattern + unique constraints prevent duplicate executions (replay-safe)
- **🔄 Resilient Architecture**: Redis fallback to in-memory for rate-limiting when unavailable
- **🚀 Developer Experience**: One-command setup (`start.sh --setup`), hot-reload in dev, Docker for prod, Makefile shortcuts

### 📈 Analytics, Reporting & Compliance

- **📑 Rich Reporting**: PDF/XHTML report generation with Jinja2 templates, scheduling, recipients, and delivery logs
- **🔍 Investigation Management**: Structured investigations with evidence artifacts, recommendations, and timelines
- **↩️ Safe Response Tracking**: Response action results with full rollback capability
- **📊 Data Visualization**: Recharts-powered analytics in admin dashboard

---

## 🔄 Data Flow & Workflows

Understanding how data moves through Sentinel Bridge is key to mastering the platform. Below are the core workflows with step-by-step data flows.

### 1. 🔐 Authentication Flow

```text
User/Admin Login
        │
        ▼
┌─────────────────────────────────────────────┐
│   Frontend (SOC/Admin) - Login Form        │
└─────────────────────┬───────────────────────┘
                      │ POST /api/auth/login (credentials)
                      ▼
┌─────────────────────────────────────────────┐
│  Auth Router (interface/api/auth.py)       │
│  • Validate credentials                     │
│  • Check tenant context                     │
└─────────────────────┬───────────────────────┘
                      │ Verify against TenantUser (DB) or legacy store
                      ▼
┌─────────────────────────────────────────────┐
│  JWT Generation (core/jwt_utils.py)         │
│  • Create token with sub, scopes, tenant_id │
│  • Sign with JWT_SECRET_KEY                 │
└─────────────────────┬───────────────────────┘
                      │ Return JWT + user info
                      ▼
┌─────────────────────────────────────────────┐
│  Frontend stores token (localStorage)       │
│  • apiFetch/createFetchWithAuth attaches     │
│    Authorization: Bearer <token>            │
└─────────────────────────────────────────────┘

On Subsequent Requests:
Request → TenantMiddleware → RBAC Guard (require_role) → Route Handler
```

**Data Flow:** `Login Form → Auth API → DB/User Validation → JWT Issuance → Client Storage → Authenticated Requests with Tenant/RBAC checks`

---

### 2. 🚨 Alert Ingestion & Enrichment Workflow

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  SOURCES: Wazuh Webhook | Suricata Webhook | Manual API | Scanners       │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ HTTP POST (with auth/webhook token)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  API Router (interface/api/alerts.py / suricata.py / webhooks)           │
│  • TenantMiddleware sets tenant_id                                       │
│  • webhook_token_auth/webhook_slug_auth validates (if webhook)           │
│  • RBAC checks (if manual API)                                           │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ Parse & validate payload
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Application Service / Direct Model Creation                              │
│  • Create Alert/SuricataAlert with tenant_id                             │
│  • Set normalized_severity, pipeline_source, pipeline_processed_at (F1)  │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ Persist to DB
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PostgreSQL + TimescaleDB                                                 │
│  • alerts/suricata_alerts (hypertables, composite PK id+timestamp)       │
│  • Indexed by tenant_id, timestamp, severity                             │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ Async enrichment trigger
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Celery Worker (worker.py) - Threat Intel Enrichment (F3)                │
│  • If THREAT_INTEL_ENABLED=true, query AbuseIPDB API (httpx)            │
│  • Apply retry with tenacity                                              │
│  • Update intel_score, intel_verdict, intel_source, intel_checked_at     │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │ Return enriched alert to API/UI
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Frontend (SOC) - Alert List                                              │
│  • Enriched with asset/device metadata (employee, dept, MAC)             │
│  • Display intel verdict/score when available                             │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Points:** Triage state is **not** stored on raw alerts — it's stored on `CaseAlertLink`. Enrichment is asynchronous to avoid blocking ingestion.

---

### 3. 🧩 Case Management & Triage Workflow

```text
Analyst Action: Link Alert to Case (or Create Case)
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│  POST /api/cases or /api/cases/{id}/link                │
│  RBAC: analyst/admin (per policy)                        │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Case Service / Router Logic                              │
│  • Validate tenant scope (tenant_id from middleware)       │
│  • Create Case if needed (status=open, assignee, etc.)    │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Create CaseAlertLink                                      │
│  alert_type: "alert" | "suricata"                         │
│  alert_id, case_id, tenant_id                             │
│  status: "open" (default)                                 │
│  triaged_by: null | actor                                 │
│  triaged_at: null                                         │
│  note: optional                                           │
└──────────────────────────┬────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Create TimelineEvent (Audit Trail)                        │
│  event_type: "alert_linked" | "case_created"              │
│  actor, message, timestamp, tenant_id                      │
└──────────────────────────┬────────────────────────────────┘
                           │ Commit transaction
                           ▼
┌─────────────────────────────────────────────────────────┐
│  DB: cases + case_alert_links + timeline_events            │
│  Triage lives EXCLUSIVELY on case_alert_links              │
└─────────────────────────────────────────────────────────┘

Triage Update (in_progress/resolved/dismissed):
PUT/PATCH link → update status, triaged_by, triaged_at, note → append TimelineEvent
```

**Design Rationale:** Keeping triage on `CaseAlertLink` allows the same raw alert to be linked to multiple cases in different contexts without mutating source evidence.

---

### 4. 🎯 Rule Engine, MITRE & Playbook Automation Workflow (F3)

```text
New Alert/SuricataAlert Stored
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│  Rule Evaluation (rules.py / rule engine)                 │
│  • Match alert against active Rules (tenant-scoped)        │
│  • Consider conditions, severity, source, fields           │
│  • Extract MITRE: mitre_attack_ids, tactics                │
└──────────────────────────┬────────────────────────────────┘
                           │ Match found?
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Create RuleMatchOutbox Entry                               │
│  event_id = stable correlation key                          │
│  playbook_id (if associated)                                │
│  payload: alert context + rule + MITRE mapping              │
│  tenant_id                                                  │
│  UNIQUE(event_id, playbook_id)                             │
└──────────────────────────┬────────────────────────────────┘
                           │ Publish to channel
                           ▼
┌─────────────────────────────────────────────────────────┐
│  CHANNEL_RULE_MATCH Event                                   │
│  bootstrap.py subscribes: on_rule_match(channel, event)    │
└──────────────────────────┬────────────────────────────────┘
                           │ Look up PlaybookRun by (event_id, playbook_id)
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Idempotency Guard                                           │
│  • Check existing PlaybookRun?                               │
│  • If exists → pre-insert guard returns (outbox replay = no-op)│
│  • Else → create PlaybookRun (status=pending/approved)       │
└──────────────────────────┬────────────────────────────────┘
                           │ Approved run?
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Execute Playbook (Automated Response)                       │
│  • Runs in daemon thread (non-blocking)                      │
│  • Executes response actions per playbook steps               │
│  • Logs ResponseRun, ResponseActionResult, ResponseRollback  │
└──────────────────────────┬────────────────────────────────┘
                           │ Update status & timestamps
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Audit Trail: TimelineEvent + ActionLog                      │
│  Correlate to Case (if linked)                               │
└─────────────────────────────────────────────────────────┘
```

**Critical:** `UNIQUE(event_id, playbook_id)` + pre-insert guard ensures **exactly-once** semantics on replay/outbox processing.

---

### 5. 👁️ Face Recognition & Surveillance Workflow

```text
Face Registration / Login Attempt
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│  Client submits image/frame (frontend)                      │
│  POST /api/faces/verify or /api/surveillance/...            │
└──────────────────────────┬────────────────────────────────┘
                           │ Tenant-scoped request
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Face Service (infrastructure/integrations/face*)           │
│  • Get FaceAnalysis via thread-safe _get_app()              │
│  • Lazy-load: buffalo_s (det_500m + w600k_mbf)              │
│  • Models: ~/.insightface/models/buffalo_s/                 │
└──────────────────────────┬────────────────────────────────┘
                           │ Extract embeddings (512-dim)
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Face Comparison                                             │
│  • Load registered face encodings for user/tenant             │
│  • Compute cosine similarity between embeddings               │
│  • Threshold = 0.45 (configured)                              │
│  • face_verified = true if similarity >= 0.45                 │
└──────────────────────────┬────────────────────────────────┘
                           │ Decision
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Access Logging                                                │
│  Write to AccessLog:                                           │
│  username, login_time/logout_time, is_online                  │
│  face_image (binary/reference), face_verified                  │
│  ip_address, login_method, session_duration, tenant_id         │
└──────────────────────────┬────────────────────────────────┘
                           │ Return result to client
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Surveillance UI (admin-frontend/views/SurveillanceView.jsx)  │
│  • Display access logs, online users, stats                   │
│  • Show face verification status & thumbnails                  │
└─────────────────────────────────────────────────────────┘
```

**Model Details:** InsightFace `buffalo_s` — SCRFD face detector (det_500m), ArcFace recognition (w600k_mbf), 512-dimensional embeddings. Cosine similarity threshold **0.45** for verification.

---

### 6. 🔐 RBAC & Multi-Tenancy Enforcement Flow

```text
Incoming HTTP Request
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│  1. CORS Middleware (interface/main.py)                    │
│     Check ALLOWED_ORIGINS                                  │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  2. TenantMiddleware (interface/middleware/tenant.py)       │
│     Extract tenant_id from context/header/request           │
│     Set request.state.tenant_id = resolved or "default"     │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  3. ActionLogMiddleware (interface/middleware/action_log.py)│
│     Capture audit context (user, IP, action, resource)      │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  4. Route Resolution (FastAPI)                              │
│     Match to router/endpoint                                │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  5. RBAC Guard Injection (apply_role_guard)                 │
│     For non-exempt routes: insert require_role(min_role)    │
│     at dependencies[0] (before legacy scope deps)           │
│     Policy from ROUTER_POLICIES[name] or DEFAULT_POLICY      │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  6. require_role(min_role) executes (core/rbac.py)          │
│     Try API Key lane:                                        │
│       • API_KEY → admin role (if min_role <= admin)          │
│       • SUPER_ADMIN_API_KEY → super_admin (if min_role==super)│
│     Else JWT lane:                                           │
│       • verify_token() → if None, try verify_admin_token()   │
│         (ADMIN_JWT_SECRET) → treats as super_admin operator   │
│       • resolve_user_role(DB first, else legacy JSON)        │
│       • Check is_active & ROLE_RANK[role] >= ROLE_RANK[min]  │
└──────────────────────────┬────────────────────────────────┘
                           │ AuthN/AuthZ OK?
                           ▼
┌─────────────────────────────────────────────────────────┐
│  7. Route Handler (interface/api/*.py)                       │
│     All queries filtered by tenant_id:                        │
│     db.query(Model).filter(Model.tenant_id == tenant_id)     │
└──────────────────────────┬────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────┐
│  8. Response returned (tenant-scoped data only)              │
└─────────────────────────────────────────────────────────┘
```

**Role Hierarchy:** `viewer (0) < analyst (1) < admin (2) < super_admin (3)`

**Source of Truth:** `TenantUser.role` in DB; legacy JSON store as fallback. Admin console tokens (signed with `ADMIN_JWT_SECRET`) are accepted as `super_admin` operator access.

---

## 🛠️ Technologies & Libraries

### Backend Stack (Python)

| Category | Library | Version | Purpose |
|---|---|---|---|
| **Web Framework** | [FastAPI](https://fastapi.tiangolo.com/) | >=0.139,<1.0 | Async REST API with OpenAPI |
| **ASGI Server** | [Uvicorn](https://www.uvicorn.org/) | >=0.32,<1.0 | Lightning-fast ASGI server |
| **ORM** | [SQLAlchemy](https://www.sqlalchemy.org/) | >=2.0,<3.0 | Modern ORM with type hints |
| **Database Driver** | [pg8000](https://github.com/tlocke/pg8000) | >=1.31,<2.0 | Pure-Python PostgreSQL driver |
| **Validation** | [Pydantic](https://docs.pydantic.dev/) | >=2.10,<3.0 | Data validation & serialization |
| **Config** | [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | >=2.8,<3.0 | Env-based configuration |
| **Async Tasks** | [Celery](https://docs.celeryq.dev/) | >=5.6,<6.0 | Distributed task queue |
| **Message Broker** | [Redis](https://redis.io/) | >=4.5.2,<5.0.0 | Broker, cache, rate-limiting |
| **Auth (JWT)** | [python-jose](https://github.com/mpdavis/python-jose) | >=3.5,<4.0 | JWT encoding/decoding (with cryptography) |
| **Password Hashing** | [passlib](https://passlib.readthedocs.io/) + [bcrypt](https://github.com/pyca/bcrypt/) | >=1.7,<2.0 / >=4.2,<6.0 | Secure password storage |
| **HTTP Client** | [httpx](https://www.python-httpx.org/) | >=0.28,<1.0 | Async HTTP for external APIs |
| **Face Recognition** | [InsightFace](https://insightface.ai/) | ==1.0.1 | SCRFD + ArcFace face recognition |
| **Inference** | [onnxruntime](https://onnxruntime.ai/) | ==1.29.0 | ONNX model inference |
| **CV/Imaging** | [opencv-python-headless](https://opencv.org/) | >=4.8,<5.0 | Computer vision (headless) |
| **Imaging** | [Pillow](https://python-pillow.org/) | >=11.0,<12.0 | Image processing |
| **Networking** | [scapy](https://scapy.net/) | >=2.6,<3.0 | Packet manipulation & analysis |
| **Nmap** | [python-nmap](https://xael.org/pages/python-nmap-en.html) | >=0.7,<1.0 | Nmap integration |
| **SSH** | [paramiko](https://www.paramiko.org/) | >=3.5,<4.0 | SSH connectivity |
| **Templates/PDF** | [Jinja2](https://jinja.palletsprojects.com/) + [xhtml2pdf](https://github.com/xhtml2pdf/xhtml2pdf) | >=3.1,<4.0 / >=0.2,<1.0 | Report templating & PDF export |
| **Resilience** | [tenacity](https://tenacity.readthedocs.io/) | >=9,<10 | Retry/backoff logic |
| **Email** | [aiosmtplib](https://aiosmtplib.readthedocs.io/) | >=1.1,<2.0 | Async SMTP delivery |
| **Syslog** | [syslog-rfc5424-parser](https://github.com/easypost/syslog-rfc5424-parser) | >=0.3.0 | RFC5424 syslog parsing |
| **Monitoring** | [psutil](https://github.com/giampaolo/psutil) | >=7.0,<8.0 | System & process metrics |
| **Utils** | [python-dateutil](https://dateutil.readthedocs.io/), [python-multipart](https://github.com/Kludex/python-multipart), [urllib3](https://urllib3.readthedocs.io/) | Various | Date handling, uploads, HTTP utils |

### Frontend Stack (React/TypeScript-adjacent JS)

| Library | Version | Purpose |
|---|---|---|
| **[React](https://react.dev/)** | ^18.2.0 | Component-based UI |
| **[React DOM](https://react.dev/reference/react-dom)** | ^18.2.0 | DOM rendering |
| **[React Router DOM](https://reactrouter.com/)** | ^7.18.1 | Declarative routing |
| **[Vite](https://vitejs.dev/)** | ^5.0.0 | Next-gen build tool & HMR |
| **[@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react)** | ^4.0.0 | React integration for Vite |
| **[Tailwind CSS](https://tailwindcss.com/)** | ^4.0.0 | Utility-first styling |
| **[@tailwindcss/postcss](https://tailwindcss.com/docs/installation/using-postcss)** | ^4.2.2 | PostCSS integration |
| **[TanStack React Query](https://tanstack.com/query/latest)** | ^5.101.4 | Data fetching, caching, sync |
| **[React Toastify](https://fkhadra.github.io/react-toastify/)** | ^9.1.3 | Elegant toast notifications |
| **[Recharts](https://recharts.org/)** | ^2.10.0 / ^2.12.7 | Composable charts |
| **[Lucide React](https://lucide.dev/)** | ^0.300.0 | Beautiful SVG icons |
| **[clsx](https://github.com/lukeed/clsx)** | ^2.1.1 | Conditional class composition |

### Infrastructure & DevOps

| Tool | Purpose |
|---|---|
| **[PostgreSQL](https://www.postgresql.org/)** + **[TimescaleDB](https://www.timescale.com/)** | Relational DB with time-series hypertables |
| **[Redis](https://redis.io/)** | Broker, cache, distributed locks |
| **[Celery](https://docs.celeryq.dev/)** | Async job processing & scheduling |
| **[Docker](https://www.docker.com/)** + **[Docker Compose](https://docs.docker.com/compose/)** | Containerization for dev/prod |
| **[Wazuh](https://wazuh.com/)** | SIEM platform integration |
| **[Suricata](https://suricata.io/)** | High-performance IDS/IPS |
| **[Ollama](https://ollama.com/)** | Local LLM inference (AI-assisted workflows) |
| **[Nginx](https://nginx.org/)** | Reverse proxy & static serving (prod) |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+** (3.11 recommended)
- **Node.js 18+** & **npm 9+**
- **PostgreSQL 14+** (TimescaleDB extension recommended for hypertables)
- **Redis 7+**
- **Docker & Docker Compose** (optional but recommended for prod)
- **Git**

### 1. Automated Setup (Recommended) — Linux/macOS

The `start.sh` script automates the entire setup process end-to-end.

```bash
# Clone the repository
git clone https://github.com/saif-infinity/projet-soc-ips-siem-xdr-.git
cd projet-soc-ips-siem-xdr-

# Make executable
chmod +x start.sh

# Full setup (installs deps, venv, models, npm packages)
./start.sh --setup

# Start all services
./start.sh
```

**What `start.sh --setup` does automatically:**

1. ✅ Checks & installs Python 3 + python3-venv
2. ✅ Installs/sets up Node.js via nvm (if needed)
3. ✅ Creates Python virtual environment (`backend/venv/`)
4. ✅ Installs Python dependencies from `requirements.txt`
5. ✅ Fixes OpenCV headless collision (critical for InsightFace)
6. ✅ Downloads InsightFace `buffalo_s` models → `~/.insightface/models/buffalo_s/`
7. ✅ Installs npm dependencies for both `frontend/` and `admin-frontend/`
8. ✅ Checks/starts Redis (native or Docker)

**Available Flags:**

| Flag | Description |
|---|---|
| `--setup` | Force complete environment setup |
| `--no-ollama` | Skip Ollama startup |
| `--no-admin` | Skip admin frontend startup |

---

### 2. Manual Setup

#### Backend Setup

```bash
cd backend

# Create & activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# CRITICAL: Fix OpenCV collision for InsightFace
pip uninstall -y opencv-python
pip install --force-reinstall --no-deps opencv-python-headless==4.14.0.94
```

#### Frontend Setup

```bash
# SOC Frontend
cd frontend && npm install

# Admin Frontend
cd admin-frontend && npm install
```

#### External Services

```bash
# Start Redis (native)
redis-server

# OR via Docker
docker run -d --name sentinel-redis -p 6379:6379 redis:7
```

Ensure PostgreSQL is running with a database ready (configured via `DATABASE_URL`).

---

### 3. Running the Application

#### Development Mode

**Option A: One command (recommended)**

```bash
./start.sh
```

Starts: Redis, FastAPI Backend (:8001), SOC Frontend (:5173), Admin Frontend (:5174), Celery Worker (+ Beat), with optional Ollama/Wazuh.

**Option B: Makefile (Windows-friendly)**

```bash
make dev                # All services
make dev-backend        # FastAPI only
make dev-frontend       # SOC frontend only
make dev-worker         # Celery worker only
make dev-wazuh          # Wazuh stack
make dev-ollama         # Ollama server
```

**Option C: Manual (granular control)**

```bash
# Terminal 1 - Backend API
cd backend && source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001

# Terminal 2 - Celery Worker (+ Scheduler)
cd backend && source venv/bin/activate
celery -A app.worker.celery_app worker --loglevel=info --pool=solo -B

# Terminal 3 - SOC Frontend
cd frontend && npm run dev

# Terminal 4 - Admin Frontend
cd admin-frontend && npm run dev
```

#### Production Mode

```bash
# Docker Compose (recommended for production)
docker compose -f docker-compose.prod.yml up -d --build

# Stop
docker compose -f docker-compose.prod.yml down

# Or via Makefile
make prod
make prod-down
```

---

## ⚙️ Configuration

### 1. Environment Variables (`backend/.env`)

Create `backend/.env` from `.env.example` if available. Below are the key configuration variables:

| Variable | Default | Required | Description |
|---|---|---|---|
| `ENVIRONMENT` | `development` | No | `development`/`production` — affects SSL verification |
| `DATABASE_URL` | — | **Yes** | PostgreSQL connection (e.g., `postgresql+pg8000://user:pass@localhost:5432/db`) |
| `JWT_SECRET_KEY` | — | **Yes** | JWT signing secret → `openssl rand -hex 32` |
| `ADMIN_JWT_SECRET` | — | **Recommended** | Console admin token secret (operator super_admin access) |
| `API_KEY` | — | Recommended | Global service API key |
| `ADMIN_API_KEY` | — | Optional | Admin-level API key |
| `SUPER_ADMIN_API_KEY` | — | Optional | Super admin API key |
| `SUPER_ADMIN_PASSWORD` | — | Optional | Super admin console password |
| `REDIS_URL` | `redis://localhost:6379/0` | Yes | Celery broker/cache |
| `REDIS_PASSWORD` | — | Optional | Redis password |
| `ALLOWED_ORIGINS` | — | Recommended | CORS origins (comma-separated, e.g., `http://localhost:5173,http://localhost:5174`) |
| `THREAT_INTEL_ENABLED` | `false` | No | Enable threat intel enrichment (F3) |
| `THREAT_INTEL_API_KEY` | — | If enabled | AbuseIPDB API key |
| `WAZUH_HOST/USER/PASS` | — | Optional | Wazuh SIEM integration |
| `WAZUH_INDEXER_*` | — | Optional | Wazuh Indexer credentials |
| `SURICATA_HOST/USER/PASS` | — | Optional | Suricata IDS/IPS integration |
| `NOTIFICATION_ENCRYPTION_KEY` | — | Optional | Fernet key for encrypted notifications |
| `STRIPE_SECRET_KEY`/`STRIPE_WEBHOOK_SECRET` | — | Optional | Billing integration |
| `VITE_AUTOLOGIN` | `0` | Dev only | Frontend dev bypass (⚠️ **NEVER** use in production) |

> ⚠️ **Security Note:** Generate all secrets with `openssl rand -hex 32`. Never commit `.env` files to version control.

### 2. Frontend Configuration

**SOC Frontend (`frontend/.env`):**

```env
VITE_AUTOLOGIN=0  # Set to 1 ONLY for local dev bypass - NEVER in production
```

**API Client Notes:**
- `frontend/src/lib/api.js`: `API_BASE` defaults to `""` (uses Vite dev proxy → backend `:8001`)
- `admin-frontend/src/api.js`: Configured to call backend API (adjust base URL for production deployment)

---

## 📚 API & Access

### Service URLs (Development)

| Service | URL | Description |
|---|---|---|
| **Backend API** | [http://localhost:8001](http://localhost:8001) | FastAPI REST API |
| **Swagger UI** | [http://localhost:8001/docs](http://localhost:8001/docs) | Interactive API documentation |
| **ReDoc** | [http://localhost:8001/redoc](http://localhost:8001/redoc) | Alternative API docs |
| **OpenAPI JSON** | [http://localhost:8001/openapi.json](http://localhost:8001/openapi.json) | OpenAPI schema |
| **SOC Frontend** | [http://localhost:5173](http://localhost:5173) | Main SOC Dashboard |
| **Admin Frontend** | [http://localhost:5174](http://localhost:5174) | Admin & Surveillance UI |

### Authentication Methods

| Method | Header | Usage | Notes |
|---|---|---|---|
| **JWT Bearer** | `Authorization: Bearer <jwt>` | User authentication | Standard OAuth2/JWT flow |
| **API Key** | `X-API-Key: <api_key>` | Service-to-service | Grants broad permissions based on key tier |
| **Admin Console Token** | `Authorization: Bearer <admin_jwt>` | Operator access | Signed with `ADMIN_JWT_SECRET` → treated as `super_admin` |
| **Webhook Token** | `X-SOC-Token: <token>` | External webhooks | Per-tenant resolution with constant-time compare |
| **Webhook Slug** | URL path `/webhook/{slug}` | Per-tenant webhooks | Secret URL slug; tenant resolved by slug match |

### Key RBAC Policies (Reference)

| Router | Read Role | Write Role | Exemptions |
|---|---|---|---|
| **auth** | — | — | `exempt: true` (public) |
| **rules** | `admin` | `admin` | `exempt_paths: ["/api/rules/coverage"]` (analysts allowed) |
| **tenants** | `viewer` | `admin` | `exempt_paths: ["/api/tenants/register"]` (public registration) |
| **playbooks** | `analyst` | `admin` | — |
| **response** | `analyst` | `admin` | — |
| **reporting** | `analyst` | `admin` | — |
| **settings** | `admin` | `admin` | — |
| **database** | — | — | `exempt: true` |
| **super_admin** | — | — | `exempt: true` |
| **faces, admin, surveillance** | Varies | Varies | Per policy in `ROUTER_POLICIES` |

> Full policy definitions: `backend/app/interface/main.py` → `ROUTER_POLICIES`

---

## 💡 Technical Notes & Implementation Details

| Note | Details |
|---|---|
| **🔌 Port Binding** | Backend runs on **`:8001`** (port `8000` occupied by Coolify UI on this environment). All configs (start.sh, Makefile, docker-compose.prod.yml, Vite proxies) reflect this. |
| **📦 Backend Package Layout** | `backend/app` is a top-level package (no `backend/__init__.py`). Relative imports: 1-dot from `app/*.py`, 2-dots from `app/services/` & `app/application/`, 3-dots from deeper subdirs (`app/infrastructure/*`, `app/application/services/*`). |
| **🔗 Triage Model** | **Case triage lives on `CaseAlertLink`**, not on `Alert` or `SuricataAlert`. This preserves raw evidence integrity and allows multi-case linking. |
| **🗄️ Multi-Tenancy** | All tenant-scoped tables include indexed `tenant_id`. Middleware enforces context; all queries must filter by `tenant_id`. `alerts` & `suricata_alerts` have intel fields. |
| **🎯 MITRE ATT&CK** | `rules.mitre_attack_ids` & `tactics` columns. Migration `ensure_mitre_columns` runs at bootstrap and in rules module. |
| **👁️ Face Recognition** | InsightFace `buffalo_s` auto-downloaded to `~/.insightface/models/buffalo_s/`. Lazy-loaded via thread-safe `_get_app()`. Cosine threshold **0.45**. |
| **⚠️ OpenCV Collision** | `insightface` pulls `opencv-python` (GUI) which conflicts with `opencv-python-headless`. Setup uninstalls GUI & reinstalls `opencv-python-headless==4.14.0.94`. |
| **⏱️ TimescaleDB** | Hypertables auto-created at startup for `alerts` & `suricata_alerts` (time-series optimization). Composite PK `(id, timestamp)`. |
| **🧵 Idempotency** | `PlaybookRun` has `UNIQUE(event_id, playbook_id)` + pre-insert guard. `RuleMatchOutbox` enables replay-safe processing. |
| **🔄 Redis Fallback** | If Redis unavailable, rate-limiting falls back to in-memory (warning logged). |
| **🚫 Dev Autologin** | `VITE_AUTOLOGIN=1` bypasses auth in dev **ONLY**. Never enable in production. |
| **🚩 Feature Flag** | `THREAT_INTEL_ENABLED=false` by default. Set `true` with valid API key to enable enrichment. |

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** with clear messages: `git commit -m "feat: add amazing feature"`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

---



## 🔗 Project Links & Portfolio

- **GitHub Repository**: [projet-soc-ips-siem-xdr-](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-)
- **Portfolio (Project Showcase)**: [View Project on Portfolio](https://saif-infinity.github.io/portfolio/projects/sentinel-bridge-soc-ips-siem-xdr)
- **Live Demo** *(if available)*: [Demo Link](#) — *To be added later*

---

## 📄 License

This project is part of an academic/professional PFE (End-of-Study Project). Please check with the repository owner regarding licensing terms.

---

<div align="center">

**Sentinel Bridge — Unified SOC/IPS/SIEM/XDR Platform**

*Built for speed. Designed for clarity. Engineered for security.*

[🏠 Repository](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-) • [📖 API Docs](http://localhost:8001/docs) • [🚀 Get Started](#-getting-started)

</div>
