# Sentinel Bridge

![Sentinel Bridge — Une vision unifiée. Une réponse éclairée.](docs/assets/sentinel-bridge-banner.svg)

<div align="center">

**Plateforme SOC / SIEM · Investigation XDR · Automatisation SOAR**

Un laboratoire de sécurité pour relier les événements, les investigations et les actions de réponse.

[![CI GitHub Actions](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/actions/workflows/ci.yml/badge.svg)](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/actions/workflows/ci.yml)
[![Dernier commit sur master](https://img.shields.io/github/last-commit/saif-infinity/projet-soc-ips-siem-xdr-/master?style=flat-square&label=commit%20master&color=0f766e)](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/commits/master)
[![Issues ouvertes](https://img.shields.io/github/issues/saif-infinity/projet-soc-ips-siem-xdr-?style=flat-square&label=issues&color=0f766e)](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/issues)
[![GitHub stars](https://img.shields.io/github/stars/saif-infinity/projet-soc-ips-siem-xdr-?style=flat-square&color=0f766e)](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/stargazers)
[![Licence AGPL-3.0](https://img.shields.io/badge/licence-AGPL--3.0-0f766e?style=flat-square)](LICENSE)

![Python](https://img.shields.io/badge/Python-3.13%20%28CI%29-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-149eca?style=flat-square&logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-5-646cff?style=flat-square&logo=vite&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-TimescaleDB-4169e1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Celery-dc382d?style=flat-square&logo=redis&logoColor=white)

[Démarrer](#demarrage) · [Guide visuel](docs/ARCHITECTURE.md) · [Architecture](#architecture) · [Avantages](#avantages) · [API](#api) · [Sécurité](#securite) · [Contribuer](#contribuer)

</div>

> [!IMPORTANT]
> **Projet de laboratoire / PFE en cours de consolidation.** Le code contient des mécanismes de collecte, de corrélation et de réponse, mais ne constitue ni un IPS inline, ni une solution certifiée prête à être déployée sans revue de sécurité. Les capacités implémentées, les dépendances externes et les simulations sont distinguées ci-dessous.

<details open>
<summary><strong>Explorer le projet avec le guide visuel interactif</strong></summary>

Une page autonome complète les SVG : **14 composants cliquables**, les **8 étapes détaillées** (entrée → traitement → sortie), les bénéfices attendus et les limites. Les schémas peuvent être agrandis et zoomés ; la navigation fonctionne aussi au clavier et sur mobile.

Ouvrir **[docs/index.html](docs/index.html)** dans un navigateur après avoir récupéré le dépôt, ou servir uniquement la documentation depuis la racine :

```bash
python3 -m http.server 8080 --bind 0.0.0.0 --directory docs
```

Ouvrir le port 8080 exposé par l’environnement ; sur son propre ordinateur, `http://localhost:8080`. Sur GitHub, le lien HTML affiche le **code de la page**, pas un site déjà hébergé. Aucun backend, accès réseau externe, paquet npm ou secret n’est nécessaire pour utiliser le guide. Cette page est une documentation statique, pas un dashboard connecté ni une simulation d’action réelle.

</details>

<details>
<summary><strong>Sommaire — choisir son parcours de lecture</strong></summary>

- [Présentation et objectifs](#presentation)
- [Avantages attendus](#avantages)
- [Guide visuel détaillé — nature, architecture et huit étapes](docs/ARCHITECTURE.md)
- [Fonctionnalités et statut réel](#fonctionnalites)
- [Architecture et flux d’un incident](#architecture)
- [Interfaces SOC et administration](#interfaces)
- [Agent Windows .exe (lab local)](#agent)
- [Démarrage local](#demarrage)
- [Configuration](#configuration)
- [Connecter les sources et les services](#integrations)
- [API et exemples](#api)
- [Sécurité, rôles et multi-tenancy](#securite)
- [Base de données et migrations](#migrations)
- [Tests, builds et CI](#qualite)
- [Préparer un déploiement](#production)
- [Dépannage](#depannage)
- [Feuille de route](#roadmap)
- [Contribuer](#contribuer)
- [Licence, crédits et liens](#licence)

</details>

<a id="presentation"></a>

## 01 · Présentation et objectifs

**Sentinel Bridge** centralise plusieurs briques d’un centre opérationnel de sécurité : alertes Wazuh, événements réseau Suricata, journaux syslog, inventaire, règles de corrélation, dossiers d’incident et actions de réponse. Le backend FastAPI est partagé par deux interfaces React : un espace analyste SOC et une console d’administration.

Le projet vise trois usages complémentaires :

| Usage | Ce que l’on peut travailler avec le projet |
| :--- | :--- |
| **Laboratoire SOC** | Relier des sources de logs à un pipeline commun, comprendre la normalisation et tester des règles de détection. |
| **Démonstration PFE / portfolio** | Présenter un parcours complet : événement → alerte → investigation → décision → rapport. |
| **Base de développement** | Étudier RBAC, multi-tenancy, tâches asynchrones, outbox, workflows SOAR et intégrations de sécurité. |

![Nature de Sentinel Bridge : centraliser avec le SIEM, expliquer avec les investigations multi-sources et agir sous conditions avec le SOAR.](docs/assets/project-nature.svg)

[Voir le SVG](docs/assets/project-nature.svg) · [Nature du projet et rôle de chaque acteur](docs/ARCHITECTURE.md#nature)

### Ce que signifient SOC, SIEM, XDR et IPS ici

- **SOC** : les outils de travail de l’analyste, pas un service humain de surveillance fourni par le dépôt.
- **SIEM** : collecte, normalisation, conservation, recherche et corrélation des événements.
- **XDR / SOAR** : rapprochement de plusieurs sources, investigation et orchestration de réponses via des connecteurs.
- **IPS** : le nom du dépôt évoque la prévention, mais **aucun chemin de blocage Suricata inline n’est implémenté ici**. Les actions Wazuh/SSH ne doivent pas être confondues avec un IPS réseau inline.

**Principe de lecture :** une intégration présente dans le code n’est pas une garantie de fonctionnement sur une infrastructure non configurée. Aucun chiffre de performance, SLA ou niveau de conformité n’est revendiqué.

<a id="avantages"></a>

### Avantages attendus et limites

Chaque apport correspond à un mécanisme identifiable dans le code : normaliser les sources, limiter les répétitions, partager les preuves, encadrer les décisions et faciliter les extensions.

![Des problèmes SOC aux apports attendus : normalisation, déduplication, dossiers partagés, décisions tracées et architecture extensible. Aucun gain chiffré n’est revendiqué.](docs/assets/value-map.svg)

[Voir le SVG](docs/assets/value-map.svg) · [Mécanismes, bénéfices et limites à vérifier](docs/ARCHITECTURE.md#valeur)

<a id="fonctionnalites"></a>

## 02 · Fonctionnalités et statut réel

**Légende :** `Implémenté` = code et parcours présents ; `À connecter` = dépend d’un service ou d’un équipement externe ; `Expérimental` = à limiter au laboratoire ; `Dry-run` = aucune action envoyée à l’équipement.

| Domaine | Capacités présentes | Statut et limites |
| :--- | :--- | :--- |
| **Collecte** | Webhooks Wazuh et Suricata ; réception syslog TCP/UDP. | **Implémenté / à connecter.** Wazuh et Suricata sont désactivés par défaut dans `Settings`. |
| **Pipeline** | Normalisation inspirée ECS, sévérité normalisée, déduplication, suppression et statistiques d’ingestion. | **Implémenté.** Ce n’est pas une certification de compatibilité ECS complète. |
| **Détection** | Règles persistées, conditions, correspondances, annotations MITRE ATT&CK et couverture. | **Implémenté.** Les règles et leur qualité doivent être validées dans le contexte du déploiement. |
| **Investigation** | Cases, timeline, triage, hunts, investigations, preuves et recommandations. | **Implémenté.** Le triage d’une alerte liée à un dossier est porté par `CaseAlertLink`. |
| **Accès** | JWT, clés API, hiérarchie de rôles, comptes/tenants et approbation d’inscription. | **Implémenté.** Plusieurs mécanismes d’authentification coexistent ; voir [sécurité](#securite). |
| **Threat Intelligence** | AbuseIPDB, cache TTL et enrichissement des IoC. | **À connecter.** Sans clé fournisseur, les résultats peuvent rester `unknown`. |
| **Réponse** | Playbooks, approbation, suivi d’exécution, connecteurs Wazuh/SSH et mécanismes de rollback. | **À connecter.** Les effets et le rollback dépendent de chaque action et de ses permissions. |
| **IA** | Clients Ollama et Hugging Face Router pour analyses, rapports et assistance à l’investigation. | **À connecter / expérimental.** Une recommandation générée doit être revue par un humain. |
| **Rapports** | Rapports planifiés, exports CSV/PDF/Markdown, métriques SOC et livraison. | **Implémenté.** Les métriques ne valent ni benchmark ni certification de conformité. |
| **Notifications** | Email, Telegram et webhooks ; chiffrement Fernet des configurations de canaux. | **À connecter.** Serveur SMTP, tokens et destinations restent à fournir. |
| **Inventaire réseau** | CRUD d’équipements, génération de commandes CLI, prévisualisation et sonde TCP réelle. | **Implémenté + dry-run.** `push-config` renvoie `success: false` et n’applique rien. Une connexion TCP réussie ne valide pas l’authentification SSH. |
| **Biométrie / surveillance** | InsightFace, fallback Haar, capture et demandes de connexion faciale. | **Expérimental.** Le fallback par histogramme et la liveness ne sont pas un facteur d’authentification fort. |
| **Honeypot** | Écoute TCP et journalisation des tentatives. | **Expérimental, opt-in.** Exécuté dans le processus API, non isolé comme un service dédié. |
| **Tarification** | Écran Pricing et champs de configuration Stripe. | **Non opérationnel comme paiement intégré.** Ne pas les présenter comme un service de facturation fonctionnel. |

### Sévérité : préserver le sens des événements

Le helper partagé [formatters.js](frontend/src/lib/formatters.js) privilégie `normalized_severity` sur l’échelle 0–15 :

| Affichage frontend | Plage normalisée | Exemple de repli Suricata brut |
| :--- | :--- | :--- |
| Low | 0–3 | Sévérité Suricata `4` → `1` |
| Medium | 4–7 | Sévérité Suricata `3` → `5` |
| High | 8–11 | Sévérité Suricata `2` → `10` |
| Critical | 12–15 | Sévérité Suricata `1` → `15` |

**Attention :** l’échelle native de Suricata est inversée : `1` est le plus grave. Les seuils du reporting et de certains jobs IA backend restent à unifier ; ne pas déduire de cette table une uniformité totale de tous les rapports.

<a id="architecture"></a>

## 03 · Architecture et flux d’un incident

### Vue d’ensemble

![Carte logique : interfaces React et sources, FastAPI et pipeline, données PostgreSQL, Redis, workers Celery, récepteur syslog et connecteurs optionnels.](docs/assets/architecture-map.svg)

[Voir le SVG](docs/assets/architecture-map.svg) · [Rôle des processus, du bus local, de l’outbox et des files](docs/ARCHITECTURE.md#composants)

<details>
<summary><strong>Version Mermaid — vue d’ensemble éditable</strong></summary>

```mermaid
flowchart TB
    subgraph UI[Interfaces utilisateur]
        SOC["Dashboard SOC<br/>React · Vite · Tailwind"]
        ADMIN["Console administration<br/>React · Vite"]
    end

    subgraph CORE[Backend Python]
        API["FastAPI<br/>REST · JWT · RBAC · contexte tenant"]
        PIPE["Pipeline<br/>normalisation · déduplication · règles"]
        CASES["Cases · investigations<br/>playbooks · reporting"]
        WORKER["Celery worker + Beat<br/>jobs et planification"]
        SYSLOG["Récepteur syslog<br/>TCP / UDP"]
    end

    subgraph DATA[Données et messagerie]
        PG[(PostgreSQL / TimescaleDB)]
        REDIS[(Redis / Streams)]
    end

    subgraph EXT[Services externes — à configurer]
        SOURCES["Wazuh · Suricata<br/>équipements autorisés"]
        INTEL[AbuseIPDB]
        AI[Ollama / HF Router]
        NOTIFY[Email / Telegram / webhooks]
    end

    SOC -->|HTTP / WebSocket| API
    ADMIN -->|HTTP| API
    SOURCES -->|Webhooks| API
    SOURCES -->|Syslog| SYSLOG
    SYSLOG --> REDIS
    API --> PIPE
    PIPE --> CASES
    API --> PG
    PIPE --> PG
    CASES --> PG
    CASES --> REDIS
    REDIS <--> WORKER
    WORKER <--> PG
    WORKER -.->|Réponse contrôlée| SOURCES
    PIPE -.->|Enrichissement| INTEL
    WORKER -.-> AI
    WORKER -.-> NOTIFY

    classDef core fill:#0f766e,color:#fff,stroke:#14b8a6
    classDef data fill:#1e293b,color:#fff,stroke:#64748b
    class API,PIPE,CASES,WORKER,SYSLOG core
    class PG,REDIS data
```

</details>

Les lignes pointillées représentent des services optionnels ou des actions nécessitant une configuration externe. Ce schéma décrit les composants, pas une topologie de production prête à l’emploi. **Les jobs Celery, les threads SOAR, le bus local et l’outbox SQL sont des mécanismes distincts** ; leur présence ne garantit pas une livraison « exactly once ».

<details>
<summary><strong>Stack technique et rôle des dépendances</strong></summary>

| Brique | Technologies | Rôle dans le projet |
| :--- | :--- | :--- |
| API et validation | FastAPI, Pydantic 2, pydantic-settings, Uvicorn | Contrats HTTP, validation et configuration typée. |
| Persistance | SQLAlchemy 2, pg8000, PostgreSQL 16 / TimescaleDB, Alembic | Modèles, stockage d’événements et évolution du schéma. |
| Traitement asynchrone | Celery 5.6+, Redis 7, Redis Streams | Jobs, résultats, planification, rate-limit et flux syslog. |
| Interface SOC | React 18, Vite 5, Tailwind CSS, TanStack Query, React Router | Navigation, requêtes, état de session et composants de dashboard. |
| Visualisation | Recharts, Lucide React, React Toastify | Graphiques, icônes et retours utilisateur. |
| Connecteurs | HTTPX, Paramiko, Scapy, python-nmap | APIs externes, SSH et découverte/diagnostic réseau autorisés. |
| Vision expérimentale | InsightFace 1.0.1, ONNX Runtime 1.29.0, OpenCV headless | Détection et vérification faciale, avec limites documentées. |
| Exports et livraison | xhtml2pdf, Jinja2, aiosmtplib, cryptography | Rapports, templates, notifications et chiffrement des configurations. |
| Qualité | Pytest, Ruff, GitHub Actions | Régressions, lint et contrôle des builds. |

Les contraintes exactes sont dans [requirements.txt](backend/requirements.txt), [frontend/package.json](frontend/package.json) et [admin-frontend/package.json](admin-frontend/package.json). Les modèles téléchargés et services externes ne sont pas intégralement livrés avec le dépôt.

</details>

### Organisation du code

La structure est **inspirée de la Clean Architecture**. Des modules de compatibilité restent présents à la racine de `app/` ; les modèles de domaine utilisent notamment SQLAlchemy.

| Couche | Emplacement | Responsabilité |
| :--- | :--- | :--- |
| Interface | [backend/app/interface/](backend/app/interface/) | Routes HTTP, middleware, contrats et contrôle d’accès. |
| Application | [backend/app/application/](backend/app/application/) | Pipeline, cas d’usage, corrélation, investigation et orchestration. |
| Domaine | [backend/app/domain/](backend/app/domain/) | Modèles métier : alertes, tenants, cases, règles et exécutions. |
| Infrastructure | [backend/app/infrastructure/](backend/app/infrastructure/) | Connecteurs, jobs, exports, transport, reconnaissance faciale et persistance. |
| Configuration | [backend/app/core/](backend/app/core/) | Settings, DB, JWT, RBAC, application Celery et logging. |

<details>
<summary><strong>Arborescence commentée du dépôt</strong></summary>

```text
projet-soc-ips-siem-xdr-/
├── .github/workflows/ci.yml       # Lint, tests, builds et validation Compose
├── backend/
│   ├── app/
│   │   ├── core/                 # Configuration, DB, sécurité, Celery
│   │   ├── interface/            # API et middleware
│   │   ├── application/          # Pipeline, règles, cases, SOAR, reporting
│   │   ├── domain/               # Modèles métier
│   │   ├── infrastructure/       # Intégrations et jobs
│   │   ├── main.py               # Point d’entrée uvicorn app.main:app
│   │   └── worker.py             # Enregistrement des modules de tâches
│   ├── migrations/               # Alembic, baseline 0001
│   ├── tests/                    # Tests unitaires et de régression
│   ├── .env.example              # Exemple à compléter, jamais des secrets réels
│   ├── alembic.ini
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                     # Interface analyste SOC
├── admin-frontend/               # Console d’administration distincte
├── docs/
│   ├── index.html                 # Guide interactif, sans backend ni build
│   ├── ARCHITECTURE.md            # Guide visuel, étapes, décisions et limites
│   ├── assets/                    # SVG locaux, CSS et JS du guide interactif
│   ├── tests/                     # Tests statiques de documentation, sans backend
│   └── diagrams/generate.py       # Générateur SVG Python sans dépendance externe
├── agent/                        # Agent Windows/Linux (lab) — collectors, queue, .exe build (`agent/sentinel-agent.spec`, `build.ps1`)
├── docker-compose.yml            # Infrastructure locale : Postgres + Redis
├── docker-compose.prod.yml       # Base de déploiement à adapter
├── Makefile                      # Raccourcis de développement
├── CONFIG_KEYS.md                # Notes de configuration historiques
├── LICENSE
└── NOTICE
```

</details>

### Du signal à la réponse

![Parcours pédagogique en huit étapes : collecter, structurer, contextualiser, dédupliquer, corréler, investiguer, décider et capitaliser. Les branches après un match sont conditionnelles.](docs/assets/incident-lifecycle.svg)

[Voir le SVG](docs/assets/incident-lifecycle.svg) · [Guide pas à pas](docs/ARCHITECTURE.md#etapes)

| Collecte et préparation · 01–04 | Détection et suites · 05–08 |
| :--- | :--- |
| [01 · Collecter](docs/ARCHITECTURE.md#etape-01) → [02 · Structurer](docs/ARCHITECTURE.md#etape-02) | [05 · Corréler](docs/ARCHITECTURE.md#etape-05) → [06 · Investiguer](docs/ARCHITECTURE.md#etape-06) |
| [03 · Contextualiser](docs/ARCHITECTURE.md#etape-03) → [04 · Dédupliquer](docs/ARCHITECTURE.md#etape-04) | [07 · Décider / répondre](docs/ARCHITECTURE.md#etape-07) → [08 · Capitaliser](docs/ARCHITECTURE.md#etape-08) |

**Ce parcours n’est pas automatique de bout en bout.** Une source désactivée peut être ignorée ; un doublon s’arrête avant les règles ; un événement sans match ne déclenche pas ces branches. Un match peut déclencher l’investigation, le SOAR direct ou les deux. Une action ne clôture pas mécaniquement une case et ne prouve pas la livraison d’un rapport.

<details>
<summary><strong>Version Mermaid — décisions et branches du parcours</strong></summary>

```mermaid
flowchart TB
    A[Événement collecté et source activée] --> B[Adapter, normaliser et contextualiser]
    B --> C{Déduplication / suppression}
    C -->|accepted| D[Persister et évaluer les règles]
    C -->|deduped / suppressed| E[Compteurs puis retour du pipeline]
    D --> F{Correspondance ?}
    F -->|Non| N[Alerte conservée sans RuleMatchEvent]
    F -->|Oui| M[RuleMatchEvent]
    M --> O[(Tentative outbox SQL)]
    M --> BUS[Dispatch local même si écriture outbox échouée]
    BUS -.->|Si éligible| I[Job sur la file investigation]
    BUS -.->|Si éligible| S[PlaybookRun : approbation et thread local]
    I --> V[Case, preuves, score et synthèse]
    V -.->|Recommandations et politique éligibles| R[ResponseRun : approbation et jobs Celery]
    S --> T[Résultats et traces]
    R --> T
    V --> T
    T -.->|Sur demande ou selon configuration| Z[Clôture, rapports et exports]
```

</details>

L’outbox et l’unicité d’une exécution par événement/playbook contribuent à l’idempotence. Elles ne garantissent pas que toutes les actions externes sont transactionnelles ou réversibles. Le [guide visuel](docs/ARCHITECTURE.md) décrit les entrées, sorties, gardes et avantages de chaque étape, avec des liens vers le code.

<a id="interfaces"></a>

## 04 · Deux interfaces, deux responsabilités

| Espace | Principaux écrans | Public visé |
| :--- | :--- | :--- |
| **SOC — `frontend/`** | Dashboard, alertes, Suricata, topologie, inventaire, règles, MITRE, cases, hunting, playbooks, terminal et assistance IA. | Analystes et responsables SOC, selon leurs rôles et scopes. |
| **Administration — `admin-frontend/`** | Demandes d’inscription, demandes de connexion faciale, actions, sessions, tentatives, paramètres, base de données, capteurs et honeypot. | Opérateur de la plateforme. |

Les interfaces partagent l’API, **pas un système de design ou un mécanisme d’authentification unique**. Leur fusion reste un chantier séparé.

### Accès local

| Service | Adresse de développement | Remarque |
| :--- | :--- | :--- |
| Interface SOC | `http://localhost:5173` | Proxy Vite vers le backend. |
| Console administration | `http://localhost:5174` | Ajouter cette origine à `ALLOWED_ORIGINS` si nécessaire. |
| API FastAPI | `http://127.0.0.1:8001` | Point d’entrée `app.main:app`. |
| Swagger UI / ReDoc | `http://127.0.0.1:8001/docs` / `/redoc` | Documentation générée depuis le code. |
| PostgreSQL / Redis | `127.0.0.1:5432` / `127.0.0.1:6379` | Bind local dans le Compose de développement. |
| Ollama, optionnel | `http://127.0.0.1:11434` | Profil Compose `ai`. |

Ces adresses concernent **la machine sur laquelle les services tournent**. Pour un serveur distant, utiliser un domaine, TLS et un reverse proxy ; ne pas coder `localhost` dans le navigateur pour joindre un backend distant.

<a id="demarrage"></a>

<a id="agent"></a>

## 05 · Agent Windows .exe (lab local, sans cloud)

**Télécharger l'agent comme une application** : un seul `SentinelAgent.exe` portable (~15-20 MB, embarque Python) + `config.json`, sans installation Python sur le PC cible. Le code source de l'exe est dans `agent/` (auditable, pas de binaire externe opaque).

| Besoin | Réponse |
| :--- | :--- |
| **Où l'obtenir ?** | **Actions** → workflow **Build Agent EXE (Windows)** → artefact `SentinelAgent-Windows.zip`, ou builder en local `cd agent && powershell -ExecutionPolicy Bypass -File build.ps1` → `dist\SentinelAgent.exe` |
| **Que contient le zip ?** | `SentinelAgent.exe` + `config.example.json` + `README.md` |
| **Comment installer ?** | Copier `SentinelAgent.exe` + `config.json` côte à côte (ex: `C:\SentinelAgent\`), éditer `server_url=http://192.168.1.50:8001` (IP LAN du serveur, pas localhost), `token=sb_...` depuis `POST /api/agent/enroll`, puis `SentinelAgent.exe --check` et `sentinel_agent\service\install_windows_exe.ps1` (NSSM ou Task Scheduler) |
| **Désinstaller ?** | `sentinel_agent\service\uninstall_windows_exe.ps1` (Admin) — file `data\queue.jsonl` conservée |
| **Lab local** | Serveur `http://192.168.1.50:8001` ouvert via `netsh advfirewall` (§ `docs/agent/README.md`), Postgres/Redis restent en `127.0.0.1` (non exposés), Wi-Fi Guest/AP isolation à désactiver |

Guides détaillés : [agent/README.md](agent/README.md) · [Build .exe](agent/BUILD_EXE.md) · [Installer Windows](docs/agent/INSTALL_WINDOWS.md) · [Dépannage](docs/agent/TROUBLESHOOTING.md) — [Résultats & suite](docs/agent/RESULTATS_ET_SUITE.md)

## 05 · Démarrage local

### Prérequis

- **Linux x86_64** est l’environnement de référence de la CI. Le manifeste admin inclut une dépendance Rollup spécifique à Linux x64 : un autre OS/CPU peut nécessiter une adaptation.
- **Python 3.13** pour s’aligner sur la CI et l’image Docker. La suite a aussi été vérifiée sous Python 3.11.
- **Node.js 22 recommandé** pour le développement ; la CI applicative est actuellement configurée sur Node 20.
- **Docker Engine + Compose v2**, Git et un shell Bash.
- Accès internet pour les dépendances et images ; prévoir du stockage supplémentaire pour les modèles de vision ou LLM si ces options sont activées.

> Les commandes suivantes supposent un checkout contenant les correctifs d’audit documentés ici. Tant qu’ils ne sont pas fusionnés, `master` peut différer : vérifier la branche de la [PR d’audit](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/pull/1) avant d’installer.

### Étape 1 — Récupérer le code

```bash
git clone https://github.com/saif-infinity/projet-soc-ips-siem-xdr-.git
cd projet-soc-ips-siem-xdr-
```

### Étape 2 — Installer les dépendances

Depuis la racine du dépôt :

```bash
python3 -m venv backend/venv
source backend/venv/bin/activate

python -m pip install -r backend/requirements.txt pytest ruff

# InsightFace installe aussi opencv-python : rétablir le build headless.
python -m pip uninstall -y opencv-python
python -m pip install --force-reinstall --no-deps opencv-python-headless==4.14.0.94

npm ci --prefix frontend
npm ci --prefix admin-frontend
```

Le remplacement OpenCV est nécessaire : les variantes GUI et headless partagent le module `cv2`. Les lockfiles npm sont conservés ; ne pas remplacer `npm ci` par une mise à jour arbitraire des dépendances.

L’initialisation du moteur facial peut tenter de télécharger le modèle `buffalo_s` dans `~/.insightface/`. Si le modèle est indisponible, le code dispose d’un fallback Haar expérimental : son activation n’est pas une preuve que la reconnaissance ArcFace fonctionne. Prévoir le téléchargement et les licences des modèles selon son environnement.

### Étape 3 — Configurer un laboratoire sans sources actives

```bash
cp backend/.env.example backend/.env
chmod 600 backend/.env

# Générer chaque secret séparément et le renseigner dans backend/.env.
openssl rand -hex 32
```

Modifier `backend/.env` pour obtenir, au minimum, cette configuration. **Remplacer chaque `<...>` par une valeur locale distincte**, ne pas utiliser ces emplacements tels quels :

```dotenv
# Secrets locaux : tous obligatoires, même lorsque les sources sont désactivées.
JWT_SECRET_KEY=<secret-aleatoire>
API_KEY=<autre-secret-aleatoire>
ADMIN_API_KEY=<secret-console-admin>
ADMIN_JWT_SECRET=<secret-jwt-admin-distinct>
WAZUH_PASS=<valeur-locale-ou-identifiant-reel>
WAZUH_INDEXER_PASS=<valeur-locale-ou-identifiant-reel>
SURICATA_PASS=<valeur-locale-ou-identifiant-reel>
WAZUH_SSH_PASS=<valeur-locale-ou-identifiant-reel>

# Ces identifiants Postgres correspondent uniquement au Compose de développement.
DATABASE_URL=postgresql+pg8000://postgres:postgres@127.0.0.1:5432/postgres
REDIS_URL=redis://127.0.0.1:6379/0
ENVIRONMENT=development
ALLOWED_ORIGINS=["http://localhost:5173","http://localhost:5174"]
AUTO_CREATE_SCHEMA=true
REGISTRATION_REQUIRES_APPROVAL=true

# Laboratoire initial : sources, scanner et services d’analyse externes désactivés.
ENABLE_HOST_AGENT_SOURCE=false
ENABLE_WAZUH_SOURCE=false
ENABLE_SURICATA_SOURCE=false
ENABLE_HONEYPOT=false
THREAT_INTEL_ENABLED=false
```

**À ne pas oublier :** `WAZUH_SSH_PASS` est requis par `Settings` mais n’est pas présent dans l’exemple actuel ; l’ajouter explicitement. La configuration proposée désactive volontairement le scanner hôte et les intégrations externes, contrairement à certaines valeurs par défaut du code.

### Étape 4 — Démarrer l’infrastructure

```bash
docker compose up -d postgres redis
docker compose ps
```

Attendre que les services soient disponibles. Si Postgres ou Redis sont déjà installés, adapter les DSN et éviter les conflits sur les ports locaux.

### Étape 5 — Lancer les quatre processus

<details open>
<summary><strong>Terminal A — API FastAPI</strong></summary>

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

</details>

<details open>
<summary><strong>Terminal B — worker Celery et planification de laboratoire</strong></summary>

```bash
cd backend
source venv/bin/activate
celery -A app.core.celery:celery_app worker \
  --include app.worker --queues celery,investigation \
  --loglevel=info --pool=solo \
  --beat --schedule /tmp/sentinel-celerybeat
```

Cette commande utilise l’objet Celery réel de `app/core/celery.py`, importe `app.worker` pour enregistrer les tâches et consomme les files **`celery` et `investigation`**. La tâche principale d’investigation est explicitement routée vers cette seconde file ; un worker limité à la file par défaut ne la traite pas. La cible historique `app.worker.celery_app` n’est pas exportée par ce module dans l’état actuel ; ne pas reprendre cette commande des anciens scripts sans vérification.

En production, séparer le worker et Beat, garantir une seule instance du scheduler et placer son état dans un emplacement persistant adapté.

</details>

<details open>
<summary><strong>Terminal C — interface SOC</strong></summary>

```bash
cd frontend
npm run dev
```

</details>

<details open>
<summary><strong>Terminal D — console administration</strong></summary>

```bash
cd admin-frontend
npm run dev
```

</details>

### Étape 6 — Vérifier et créer les accès

```bash
curl --fail http://127.0.0.1:8001/
```

Cette route indique que l’API répond ; **ce n’est pas un contrôle complet de readiness** de la DB, du broker et des sources. Consulter également les logs et `docker compose ps`.

- Ouvrir l’interface SOC et soumettre une inscription : elle reste en attente avec `REGISTRATION_REQUIRES_APPROVAL=true`.
- La console admin utilise le nom **`admin`** et le secret configuré dans **`ADMIN_API_KEY`** comme mot de passe. Il s’agit d’un accès partagé privilégié, pas d’un compte opérateur nominatif.
- Un compte `super_admin` en base peut être initialisé au démarrage si `SUPER_ADMIN_PASSWORD` est configuré avant le premier lancement ; ne pas confondre ce compte avec la connexion statique de la console admin.
- Les parcours de vérification faciale présents dans l’UI restent expérimentaux, même lorsqu’ils font partie du parcours de connexion.

**Arrêt du laboratoire :** interrompre les processus avec `Ctrl+C`, puis exécuter `docker compose stop`. `docker compose down` retire les conteneurs/réseaux sans supprimer les volumes par défaut ; **`down -v` détruit les volumes et leurs données**.

<a id="configuration"></a>

## 06 · Configuration : les sources de vérité

| Sujet | Référence |
| :--- | :--- |
| Champs, valeurs par défaut et secrets obligatoires | [backend/app/core/config.py](backend/app/core/config.py) |
| Exemple d’environnement | [backend/.env.example](backend/.env.example) |
| Images, ports et variables Compose | [docker-compose.yml](docker-compose.yml) / [docker-compose.prod.yml](docker-compose.prod.yml) |
| Proxies du navigateur | [frontend/vite.config.js](frontend/vite.config.js) / [admin-frontend/vite.config.js](admin-frontend/vite.config.js) |
| Politiques de rôles par routeur | [backend/app/interface/main.py](backend/app/interface/main.py) |

`Settings` charge `.env` depuis le répertoire de travail : lancer l’API, Celery et Alembic depuis **`backend/`**. L’environnement du processus est prioritaire. Les valeurs de `Settings` sont instanciées à l’import : redémarrer les processus après modification.

**Compose et l’API ne chargent pas implicitement le même fichier.** Pour l’interpolation, Compose utilise le shell, le `.env` à la racine ou un fichier fourni avec `--env-file`. Un `env_file` déclaré dans un service injecte des variables dans le conteneur ; il ne remplace pas ce mécanisme d’interpolation. Aligner les DSN et les identifiants des services selon son mode d’exécution.

Les [notes CONFIG_KEYS.md](CONFIG_KEYS.md) complètent la lecture, mais certaines notes sont historiques. En cas de divergence, se référer au code et aux valeurs explicites de son déploiement.

<details>
<summary><strong>Variables principales et activation contrôlée</strong></summary>

| Variable | Usage / précaution |
| :--- | :--- |
| `JWT_SECRET_KEY`, `ADMIN_JWT_SECRET` | Deux secrets de signature distincts ; ne jamais reprendre les valeurs de test en production. |
| `API_KEY`, `ADMIN_API_KEY` | Clé d’intégration privilégiée et secret de la console ; conserver uniquement côté opérateur/serveur. |
| `DATABASE_URL`, `REDIS_URL` | DSN complets ; adapter les noms d’hôtes selon exécution locale ou conteneurisée. |
| `ENVIRONMENT` | Utiliser `production` pour activer les comportements de sécurité liés à ce mode. |
| `ALLOWED_ORIGINS` | Liste JSON d’origines autorisées, incluant les deux interfaces si elles ne sont pas sur la même origine. |
| `AUTO_CREATE_SCHEMA` | `true` pour le raccourci local ; privilégier `false` et un schéma migré en production. |
| `ENABLE_HOST_AGENT_SOURCE` | `true` par défaut dans le code ; peut déclencher une découverte réseau. Ne l’activer que sur un réseau autorisé. |
| `ENABLE_WAZUH_SOURCE`, `ENABLE_SURICATA_SOURCE` | `false` par défaut ; configurer les sources puis les activer. Les réglages par tenant peuvent prendre le relais. |
| `ENABLE_HONEYPOT`, `HONEYPOT_PORTS` | Honeypot désactivé par défaut ; liste JSON de ports, sinon 2323/3389/8443/5555. Réserver à un environnement isolé. |
| `THREAT_INTEL_ENABLED`, `THREAT_INTEL_API_KEY` | Le flag du code est `true` par défaut ; une clé AbuseIPDB est nécessaire pour l’enrichissement externe. |
| `OLLAMA_URL`, `OLLAMA_MODEL` | Serveur et modèle local ; default du modèle : `qwen2.5:1.5b`. |
| `HF_ROUTER_URL`, `HF_MODEL`, `HF_TOKEN` | Service LLM distant ; évaluer la confidentialité des données envoyées. |
| `NOTIFICATION_ENCRYPTION_KEY` | Clé Fernet dédiée ; sinon le code dispose d’un fallback dérivé du secret JWT. Préférer une clé séparée. |
| `TRUST_PROXY_HEADERS` | `false` par défaut ; activer seulement derrière un proxy de confiance qui maîtrise les en-têtes. |
| `REGISTRATION_REQUIRES_APPROVAL` | `true` par défaut ; une inscription n’est pas un compte immédiatement autorisé. |

</details>

Les variables du récepteur syslog (`SYSLOG_HOST`, `SYSLOG_PORT`, `SYSLOG_TENANT_MAPPINGS`, `SYSLOG_DEFAULT_TENANT`) sont lues depuis **l’environnement de son processus dédié**, pas depuis des champs `Settings`. Ne pas ajouter aveuglément des clés non déclarées au `.env` de l’API.

<a id="integrations"></a>

## 07 · Connecter les sources et les services

### Wazuh et Suricata

1. Préparer une instance externe Wazuh ou Suricata ; ce dépôt ne fournit pas leur installation complète.
2. Renseigner les URLs, ports et identifiants correspondants dans l’environnement du backend ou les réglages de source par tenant.
3. Activer la source et vérifier `GET /api/settings/sources` ainsi que les journaux d’ingestion.
4. Configurer le forwarder et les tokens/URLs de webhook fournis par les réglages du projet.
5. Envoyer un événement synthétique identifiable dans le laboratoire, vérifier sa réception, sa sévérité normalisée et son tenant.

| Source | Points d’entrée |
| :--- | :--- |
| Suricata EVE JSON / NDJSON | `POST /api/suricata/webhook` ou `/api/suricata/webhook/{slug}` ; route historique `/webhook`. |
| Wazuh | `POST /api/wazuh/webhook` ou `/api/wazuh/webhook/{slug}`. |

> [!WARNING]
> **HTTP 200 ne suffit pas à confirmer une ingestion.** Une source désactivée peut répondre `{"status":"ignored"}`. Contrôler le corps de la réponse, les réglages de source et les compteurs du pipeline.

En cas de Wazuh indisponible, la topologie et certaines informations matérielles exposent désormais un état indisponible/vidé ou des valeurs `null`, plutôt que des hôtes fictifs présentés comme réels.

### Découverte et scans Nmap, optionnels

Les scans nécessitent **le binaire système `nmap`** sur l’hôte du worker, pas seulement le paquet Python `python-nmap`. Pour enregistrer la tâche [nmap_tasks.py](backend/app/infrastructure/jobs/nmap_tasks.py), redémarrer le worker en remplaçant son option d’import par `--include app.worker,app.infrastructure.jobs.nmap_tasks` ; `app.worker` seul n’importe pas cette tâche.

Vérifier les permissions et le périmètre réseau avant d’activer la découverte hôte ou de demander un scan. Le succès du test d’envoi d’une tâche Celery ne démontre pas qu’un scan réel a été exécuté.

### Syslog agentless

Dans un terminal supplémentaire, depuis `backend/` avec le venv activé :

```bash
SYSLOG_HOST=127.0.0.1 SYSLOG_PORT=1514 \
  REDIS_URL=redis://127.0.0.1:6379/0 \
  python -m app.infrastructure.syslog.server
```

Le récepteur publie dans un Redis Stream. Avec le worker déjà démarré, traiter un lot en lançant :

```bash
celery -A app.core.celery:celery_app call jobs.syslog.process_batch
```

Le consommateur doit être déclenché régulièrement pour une ingestion continue ; il n’est pas inclus dans la planification Beat actuelle. La réception TCP utilise le framing par longueur prévu dans le récepteur. Pour des équipements distants, choisir explicitement l’interface d’écoute, les mappings IP→tenant et les règles de pare-feu. **Ce service ne fournit pas un transport syslog TLS prêt à l’emploi.**

### Ollama, optionnel

```bash
# Depuis la racine du dépôt : ajoute le service Ollama local.
docker compose --profile ai up -d
docker compose exec ollama ollama pull qwen2.5:1.5b
```

Configurer ensuite `OLLAMA_URL` et `OLLAMA_MODEL` dans le backend. Ollama/HF ne sont pas nécessaires pour lancer l’API ou afficher le dashboard ; ils le sont pour les parcours IA correspondants.

### Threat Intelligence et notifications

- **AbuseIPDB** : activer TI, fournir `THREAT_INTEL_API_KEY` et respecter quotas/confidentialité. Le cache est configurable ; une absence de clé ne doit pas être interprétée comme un verdict « clean ».
- **SMTP / Telegram / webhooks** : configurer les canaux et la clé de chiffrement ; vérifier un envoi de test avant d’en dépendre pour l’alerte opérationnelle.
- **Réponse Wazuh/SSH** : limiter les comptes et commandes autorisées, tester l’approbation et le rollback sur une machine de laboratoire. Ne jamais valider une action destructive sur un système tiers sans autorisation.

<a id="api"></a>

## 08 · API et exemples

Une fois l’API démarrée, les contrats complets sont disponibles dans **`/docs`**, **`/redoc`** et **`/openapi.json`**. Les routes ci-dessous sont un repère, pas un remplacement de l’OpenAPI.

| Méthode | Route | Usage |
| :--- | :--- | :--- |
| `GET` | `/` | Vérifier que l’API répond. |
| `POST` | `/auth/register` | Demande d’inscription, soumise à approbation par défaut. |
| `POST` | `/auth/token` | Connexion SOC, formulaire OAuth2 username/password. |
| `GET` | `/api/auth/me` | Identité et rôle de la session SOC. |
| `POST` | `/api/admin/token` | Connexion privilégiée de la console d’administration. |
| `GET` | `/api/settings/sources` | État des sources dans le contexte tenant. |
| `POST` | `/api/pipeline/ingest` | Injecter un événement dans le pipeline. |
| `GET` | `/api/pipeline/stats` | Compteurs et état du pipeline. |
| `GET` | `/api/suricata/alerts` | Alertes réseau et sévérité normalisée. |
| `GET` / `POST` | `/api/cases` | Dossiers d’incident. |
| `GET` / `POST` | `/api/rules` | Règles de corrélation, sous politique admin. |
| `POST` | `/api/hunts/preview` | Prévisualiser une recherche de hunting. |
| `GET` / `POST` | `/api/playbooks` | Définition des playbooks. |
| `GET` | `/api/intel/status` | Configuration/état du fournisseur TI. |
| `GET` | `/api/reporting/metrics` | Indicateurs calculés à partir des données SOC. |
| `GET` | `/api/alerts/export.csv` | Export CSV des alertes. |
| `GET` | `/api/cases/{case_id}/export.md` | Export Markdown d’un dossier. |
| `POST` | `/api/network-devices/{device_id}/test-connection` | Test TCP réel du port d’administration. |
| `POST` | `/api/network-devices/{device_id}/push-config` | Générer des commandes en dry-run, sans application. |

**WebSocket :** `/ws/status` est distinct de l’OpenAPI. Son handler accepte les credentials prévus par le code ; ne pas publier de token dans une URL de démonstration, un screenshot ou des logs partagés.

### Exemple de lecture authentifiée

Depuis la racine, avec le venv activé, charger sa clé locale sans l’imprimer :

```bash
export API_KEY="$(
  python -c 'from dotenv import dotenv_values; print(dotenv_values("backend/.env")["API_KEY"])'
)"

curl --fail-with-body http://127.0.0.1:8001/api/pipeline/stats \
  --header "X-API-Key: ${API_KEY:?charger la cle locale}" \
  --header "X-Tenant-ID: default"
```

### Exemple d’événement synthétique — laboratoire uniquement

```bash
curl --fail-with-body http://127.0.0.1:8001/api/pipeline/ingest \
  --header "X-API-Key: ${API_KEY:?charger la cle locale}" \
  --header "X-Tenant-ID: default" \
  --header "Content-Type: application/json" \
  --data '{
    "source": "manual",
    "severity": 5,
    "signature": "Documentation laboratory event",
    "description": "Evenement synthetique de validation du pipeline",
    "src_ip": "198.51.100.10",
    "dest_ip": "203.0.113.10",
    "proto": "tcp"
  }'
```

Les adresses de cet exemple sont réservées à la documentation. Ne pas injecter des événements de démonstration dans les données de production.

<a id="securite"></a>

## 09 · Sécurité, rôles et multi-tenancy

### Modèle d’accès

| Rôle | Intention | Restriction à garder en tête |
| :--- | :--- | :--- |
| `viewer` | Lecture autorisée par les politiques du routeur. | Pas un droit universel de lire toutes les routes. |
| `analyst` | Investigation et écritures métier autorisées. | Certaines opérations exigent des scopes supplémentaires. |
| `admin` | Administration du tenant et fonctions sensibles autorisées. | Les règles, paramètres et certaines écritures sont protégés spécifiquement. |
| `super_admin` | Opérations de plateforme prévues par les endpoints. | Accès privilégié à limiter et tracer. |

- Le JWT SOC porte le contexte tenant ; les contrôles de rôle consultent notamment `TenantUser` en base.
- Le header `X-Tenant-ID` n’est pas une preuve d’identité : il n’est utilisé comme fallback que dans les cas prévus, notamment avec une clé API valide.
- La clé `API_KEY` est **privilégiée**, pas une clé publique à intégrer dans le bundle React.
- Les tokens de la console admin ont leur secret de signature séparé et peuvent être traités comme des credentials d’opérateur très privilégiés.
- Les guards de rôle **et** les dépendances de scopes déterminent les permissions finales ; la hiérarchie seule ne remplace pas les politiques de route.

```mermaid
sequenceDiagram
    actor U as Utilisateur SOC
    participant UI as Interface React
    participant API as FastAPI
    participant DB as TenantUser / données tenant
    U->>UI: Identifiants d’un compte approuvé
    UI->>API: POST /auth/token
    API-->>UI: JWT SOC
    UI->>API: Authorization Bearer + requête métier
    API->>API: Valider JWT et contexte tenant
    API->>DB: Résoudre le rôle / appliquer le périmètre
    DB-->>API: Données autorisées
    API-->>UI: Réponse métier ou refus 401 / 403
```

### Mesures présentes et limites

- Comparaisons constantes des secrets aux endroits corrigés ; JWT et contrôle d’accès côté API.
- Rate-limit de **`/auth/token`** par IP et compte visé ; panne Redis → refus `503` en mode production. **La route admin a un mécanisme distinct qui reste fail-open en cas de connexion Redis indisponible.**
- Middleware tenant : erreur de validation → refus `503` en production, comportement plus permissif en développement.
- Terminal de diagnostic restreint, validation de commandes et accès dépendant du connecteur utilisé.
- L’intégration faciale n’est **pas** une MFA robuste : fallback Haar/histogramme et liveness expérimentale.
- Honeypot désactivé par défaut, mais le service reste dans le processus API lorsqu’il est activé.
- Les hachages et données faciales sont stockés sous `backend/app/face_data/`, ignoré par Git ; leur externalisation et les permissions doivent être traitées avant production.

**Règles opératoires :** pas de scan hors périmètre autorisé, pas de credentials réels dans les issues, pas de captures contenant des tokens ou données biométriques. Examiner ce qui part vers les fournisseurs IA/TI. Signaler une vulnérabilité par un canal privé lorsque disponible, sans publier d’exploit ni de secret dans une issue ouverte.

<a id="migrations"></a>

## 10 · Base de données et migrations

PostgreSQL avec TimescaleDB est la cible de stockage du déploiement. Les tests utilisent aussi SQLite. Le code contient la création de hypertables et des ajustements historiques du schéma ; **`create_all()` ne gère pas une évolution complète et versionnée des colonnes**.

Depuis `backend/`, avec un environnement configuré et le venv activé :

```bash
alembic heads
# Révision attendue dans cet état du dépôt : 0001 (head)

# Base neuve : appliquer la baseline après vérification du DSN.
alembic upgrade head
```

Pour une base existante déjà conforme, `alembic stamp head` peut enregistrer la baseline **sans modifier le schéma**, uniquement après sauvegarde et vérification de sa compatibilité. Les évolutions futures doivent être revues, testées puis versionnées dans [migrations/](backend/migrations/).

> [!CAUTION]
> La baseline `0001` utilise les métadonnées SQLAlchemy courantes, et son `downgrade()` appelle `drop_all()`. **Un downgrade peut donc supprimer les tables.** Ne pas l’utiliser comme bouton « annuler » sur une base de production.

L’image Docker actuelle copie les migrations mais pas `alembic.ini`. Les commandes ci-dessus visent le checkout local ; intégrer cette configuration à une image/outillage de migration avant d’automatiser les migrations en conteneur.

<a id="qualite"></a>

## 11 · Tests, builds et CI

### Reproduire les contrôles

```bash
# Depuis la racine, venv activé. Redis doit être disponible pour la suite complète.
docker compose up -d redis
ruff check backend
(cd backend && python -m pytest --tb=short -q)

npm run build --prefix frontend
npm run build --prefix admin-frontend

# Depuis backend/, avec les huit champs obligatoires déjà configurés :
(cd backend && alembic heads)
```

`backend/tests/conftest.py` fournit des valeurs jetables lorsque l’environnement n’en possède pas. La collecte seule ne démontre pas que les tâches Celery peuvent être publiées : fournir un **vrai Redis** pour une exécution complète. Ne jamais déployer les secrets de test.

| Groupe de tests | Exemples de comportements couverts |
| :--- | :--- |
| Auth / approbation / RBAC | Inscriptions pending, scopes, refus d’écriture pour un utilisateur absent, politiques de rôles. |
| Tenancy et ingestion | Tenant, webhooks, normalisation et pipeline. |
| Investigation | Cases, hunts, correspondances MITRE et playbooks. |
| Intégrations | Syslog, notifications, Threat Intelligence et déclarations TimescaleDB. |
| Régressions sécurité | Allowlist terminal et validation des types DDL admin. |

### Mesures de référence, pas des compteurs automatiques

**Vérification du 14 octobre 2026 sur l’arbre audité**, avec la correction d’isolation de la fixture Threat Intelligence :

| Contrôle | Résultat mesuré |
| :--- | :--- |
| Ruff 0.17.0 | **0 erreur** |
| Suite complète, Redis 7 disponible | **243 tests réussis**, aucun échec ni test ignoré |
| Builds SOC et admin | **Réussis** |
| Alembic, variables de test/configuration présentes | **`0001 (head)`** |
| CI : Python 3.13, deux frontends et image backend | **Contrôles réussis sur la PR d’audit** |
| CI : Compose de développement | **Validation réussie** |
| CI : Compose de production | **En échec** : le checkout CI ne contient pas le `backend/.env` requis |
| Déploiement production sur la PR | **Non exécuté** |

Les badges CI/activité du haut consultent GitHub et se mettent à jour automatiquement ; **le tableau ci-dessus est une mesure datée**, pas un badge de tests en temps réel. Le workflow complet peut être rouge même si les tests sont verts. Voir la [PR d’audit #1](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/pull/1) et les [exécutions Actions](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/actions).

<details>
<summary><strong>Raccourcis Makefile et scripts historiques</strong></summary>

| Commande | Usage |
| :--- | :--- |
| `make help` | Afficher les cibles disponibles. |
| `make install` | Installer le venv `backend/venv` et les deux frontends. |
| `make infra` / `make infra-down` | Démarrer / arrêter l’infrastructure locale. |
| `make test` | Exécuter la suite backend avec le venv attendu par le Makefile. |
| `make lint` | Ruff et builds frontend. |
| `make build` | Produire les deux dossiers `dist/`. |

Les cibles de lancement du worker et les scripts `start.sh` / `start.bat` contiennent des conventions historiques. Pour ce README, utiliser les commandes explicites validant l’entrée `app.core.celery:celery_app`, les ports et les répertoires de travail. Aucun script ne remplace la configuration des services externes.

</details>

<a id="production"></a>

## 12 · Préparer un déploiement

**Le Compose de production est un point de départ, pas une commande de déploiement validée de bout en bout.** Ne pas déduire du succès de la construction Docker que tous les services sont sains ou joignables.

### Points à résoudre avant `up`

| Point actuel | Travail requis |
| :--- | :--- |
| `backend/.env` requis par plusieurs services | Fournir des secrets au déploiement ; préparer une configuration jetable pour la validation CI sans exposer les secrets réels. |
| Service Wazuh avec `build: ./wazuh` | Le répertoire n’existe pas dans ce dépôt : connecter une installation externe ou adapter ce service. |
| Worker utilisant `app.worker.celery_app` | Adapter l’entrée Celery et vérifier l’enregistrement des tâches. |
| `HEALTHCHECK` Docker pointant sur `/health` | Cette route racine n’est pas implémentée ; définir une vraie sonde adaptée. `/api/sensors/health` est une route différente et protégée. |
| Frontend servi par nginx sans configuration proxy fournie | Configurer le routage SPA et les proxys `/api`, `/auth`, `/ws`, `/devices` et `/logs` selon les usages. |
| Pas de service admin-frontend dans ce Compose | Prévoir sa construction et son hébergement séparés. |
| `read_only` et données faciales/hachages sous `app/` | Prévoir des volumes et permissions dédiés ; ne pas masquer une impossibilité d’écriture. |
| Alembic et schéma | Préparer un job de migration, les sauvegardes et un plan de restauration ; ne pas utiliser la baseline destructive comme rollback automatique. |
| Déploiement Actions via SSH | Configurer `DEPLOY_HOST`, `DEPLOY_SSH_KEY` et, si nécessaire, `DEPLOY_USER` côté GitHub ; sinon le job échoue volontairement. |

### Checklist de durcissement

- [ ] Revue des droits, scopes et accès de console ; remplacer les accès partagés si le contexte exige des comptes nominatifs.
- [ ] Secrets distincts, permissions minimales, stockage sécurisé et politique de rotation.
- [ ] `ENVIRONMENT=production`, origines CORS contrôlées et sources activées explicitement.
- [ ] TLS entrant/sortant, pare-feu, base et broker non exposés publiquement.
- [ ] Reverse proxy de confiance ; ne pas accepter des en-têtes d’IP depuis n’importe quel client.
- [ ] `AUTO_CREATE_SCHEMA=false` une fois le schéma préparé, avec migrations revues et sauvegardes testées.
- [ ] Honeypot isolé et biométrie non utilisée comme unique facteur.
- [ ] Worker, Beat, syslog, volumes persistants et supervision opérationnelle vérifiés.
- [ ] Validation de l’approbation et des effets réels des actions de réponse.
- [ ] Politique de rétention, protection des données sensibles et revue des logos/licences tiers.
- [ ] CI verte pour la révision déployée ; pas de simulation annoncée comme une fonctionnalité réelle.

<a id="depannage"></a>

## 13 · Dépannage

| Symptôme | Vérification / correction |
| :--- | :--- |
| `ValidationError` sur les secrets | Compléter les huit champs obligatoires, notamment `WAZUH_SSH_PASS`, et lancer depuis `backend/`. |
| Erreur de décodage `ALLOWED_ORIGINS` | Fournir une liste JSON valide ; éviter de charger le `.env` comme un script shell. |
| `Connection refused` DB ou Redis | Vérifier `docker compose ps`, les ports et les DSN. Une adresse `localhost` dans un conteneur désigne ce conteneur, pas le service voisin. |
| Erreur d’import `cv2` / OpenCV | Désinstaller la variante GUI puis réinstaller la version headless indiquée dans les instructions. |
| `Module app.worker has no attribute celery_app` | Utiliser `-A app.core.celery:celery_app` et `--include app.worker`. |
| Webhook répondant `ignored` | Vérifier les flags de source, le tenant et les réglages ; HTTP 200 ne garantit pas une ingestion. |
| Alertes Suricata graves affichées faibles | Utiliser `normalized_severity` et le helper Suricata, pas directement la sévérité brute inversée. |
| Connexion répondant `503` en production | Examiner Redis et les contrôles tenant ; ne pas désactiver les protections pour contourner le symptôme. |
| Topologie ou matériel Wazuh indisponible | Vérifier les services et credentials ; ne pas remplacer l’absence de données par de faux agents. |
| Commandes réseau seulement prévisualisées | Comportement attendu : `push-config` est un dry-run, aucun driver de transport réseau n’est présent. |
| `config -q` Compose prod en échec | Vérifier les fichiers d’environnement requis et les points de la section déploiement ; le checkout seul ne suffit pas. |
| Build admin sur un autre OS / CPU | Examiner la dépendance Rollup Linux x64 du manifeste admin avant de modifier un lockfile. |
| Syslog reçu mais aucune alerte ingérée | Vérifier Redis Stream, worker et déclenchement de `jobs.syslog.process_batch`. |
| Requêtes API en 404 après build frontend | Configurer le reverse proxy et le fallback SPA ; le proxy Vite n’existe pas dans les assets compilés. |

<a id="roadmap"></a>

## 14 · Feuille de route

Cette liste expose des priorités techniques, **pas des dates de livraison garanties**.

- [ ] Rendre la validation Compose CI reproductible sans secrets de production.
- [ ] Stabiliser le déploiement : worker, healthcheck, proxy, admin UI, volumes et migrations.
- [ ] Unifier la sévérité du reporting et des jobs IA backend avec le pipeline/frontend.
- [ ] Externaliser les hachages et données biométriques hors de l’arbre applicatif.
- [ ] Harmoniser l’authentification et les protections du rate-limit admin.
- [ ] Isoler le honeypot et revoir les limites de l’authentification faciale.
- [ ] Implémenter des drivers de configuration réseau réels avec tests, approbation et retour d’état vérifiable.
- [ ] Définir une stratégie pour les deux frontends avant toute fusion/refonte.
- [ ] Renforcer les tests d’intégration de déploiement, observabilité et restauration.
- [ ] Revoir les conditions de redistribution des modèles, dépendances et marques tierces.

<a id="contribuer"></a>

## 15 · Contribuer

1. Décrire un besoin ou un bug dans les [issues](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/issues), avec des données synthétiques et un scénario reproductible.
2. Préparer une modification ciblée dans une branche dédiée, sans mélanger refonte UI, schéma et connecteurs non liés.
3. Ajouter des tests de non-régression et exécuter Ruff, Pytest avec Redis et les deux builds.
4. Mettre à jour les contrats API, les migrations et ce README si le comportement change.
5. Ouvrir une PR expliquant le périmètre, la validation, les limites et les impacts de sécurité.

**À ne jamais versionner :** `.env`, credentials, JWT, hachages, embeddings/photos, dumps de production, `node_modules`, `dist/`, environnements Python et état `celerybeat-schedule`.

Une PR de connecteur doit distinguer explicitement **prévisualisation**, **simulation**, **commande envoyée** et **résultat confirmé**. Une nouvelle migration doit documenter les risques et ne pas promettre un rollback sans en démontrer les effets.

<a id="licence"></a>

## 16 · Licence, crédits et liens

Le dépôt contient la **GNU AGPL v3**, avec les conditions et mentions applicables dans [LICENSE](LICENSE) et [NOTICE](NOTICE). La NOTICE emploie aussi le nom **AEGIS Sentinel** pour les mentions d’attribution ; l’API et les interfaces utilisent **Sentinel Bridge**.

Les dépendances, les modèles IA/vision et les logos d’équipement ont leurs **propres conditions d’utilisation**. Les marques sont utilisées pour identifier des constructeurs, sans affiliation ni parrainage revendiqué. Avant redistribution, vérifier les chartes de marques et les licences des composants réellement embarqués. La licence du dépôt ne remplace pas ces vérifications.

| Ressource | Lien |
| :--- | :--- |
| Code source | [saif-infinity/projet-soc-ips-siem-xdr-](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-) |
| Portfolio du projet | [Présentation Sentinel Bridge](https://saif-infinity.github.io/portfolio/projects/sentinel-bridge-soc-ips-siem-xdr) |
| Contributions | [Issues](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/issues) · [Pull requests](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/pulls) |
| Contrôles automatisés | [GitHub Actions](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-/actions) |
| Documentation de référence | [Settings](backend/app/core/config.py) · [API](backend/app/interface/main.py) · [Tests](backend/tests/) |

Aucune démo publique fonctionnelle n’est annoncée ici sans URL validée. Pour découvrir les écrans, lancer le laboratoire local avec des données synthétiques.

---

<div align="center">

**Collecter avec contexte. Investiguer avec méthode. Répondre avec contrôle.**

[Retour en haut](#sentinel-bridge) · [Démarrer](#demarrage) · [État réel des fonctionnalités](#fonctionnalites)

</div>
