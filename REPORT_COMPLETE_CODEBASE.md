# Rapport Complet du Code — Sentinel Bridge SOC/XDR

## Résumé du Projet

**Sentinel Bridge** est un plateau complet de **Security Operations Center (SOC)** intégrant **SIEM (Wazuh)**, **IDS/IPS (Suricata)**, et des capacités **XDR**. Il combine un backend Python/FastAPI, un frontend React, un système de tâches de fond Celery/Redis, et des intégrations avec Ollama (LLM local) pour l'analyse IA des menaces.

**Stack Technologique :**
- **Backend :** Python 3.11+, FastAPI, SQLAlchemy, Celery, Redis, PostgreSQL
- **Frontend :** React 18+, Vite, React Router, TanStack Query
- **Admin Frontend :** React + Vite (panneau d'administration séparé)
- **Services Externes :** Wazuh (SIEM), Suricata (IDS/IPS), Ollama (LLM local), PostgreSQL, Redis
- **Infrastructure :** Docker Compose, Nginx (production), SSH (paramiko)

---

## Architecture Globale

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                         │
│  Dashboard │ Topology │ Suricata │ Inventory │ AI Copilot │ ... │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP/WebSocket
┌────────────────────────────▼────────────────────────────────────┐
│                    BACKEND (FastAPI)                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Routers  │ │ Services │ │ Workers  │ │ Auth/Middleware   │   │
│  │ (API)    │ │ (Logic)  │ │ (Celery) │ │ (JWT/API Key)    │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────────────────┘   │
│       │             │            │                               │
│  ┌────▼─────────────▼────────────▼──────────────────────────┐   │
│  │              PostgreSQL + Redis + File System             │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   ┌─────────┐        ┌──────────┐         ┌──────────┐
   │  Wazuh  │        │ Suricata │         │  Ollama  │
   │  (SIEM) │        │ (IDS/IPS)│         │  (LLM)   │
   └─────────┘        └──────────┘         └──────────┘
```

---

## 1. BACKEND — `backend/app/`

### 1.1 Point d'Entrée & Configuration

#### `main.py` (352 lignes)
**Responsabilité :** Point d'entrée FastAPI, initialisation de l'application, configuration des middlewares, routes principales.

**Éléments clés :**
- Création de l'app FastAPI avec titre "Sentinel Bridge - SOC Dashboard API"
- **Middleware CORS** configuré avec origines autorisées depuis `.env`
- **ActionLogMiddleware** : journalise automatiquement toutes les actions HTTP (GET→view, POST→create, etc.) avec extraction du username depuis le JWT
- **Startup events :**
  - Création des tables PostgreSQL (`Base.metadata.create_all`)
  - Initialisation des configurations par défaut (`system_config_service._init_defaults`)
  - Cache Wazuh (agents + identités réelles)
  - Scanner ARP en arrière-plan (`background_scanner`)
  - Échantillonnage de bande passante
  - Synchronisation continue des alertes Wazuh Indexer (toutes les 60s)
- **Routes incluses :** 15 routers montés via `app.include_router()`
- **WebSocket** `/ws/status` : temps réel des alertes/devices (auth par API key)
- **Webhook** `/webhook` : réception des alertes Suricata
- **Webhook** `/api/wazuh/webhook` : réception des alertes Wazuh
- **Route** `/api/real-alerts` : alertes enrichies avec données asset/device
- **Route** `/api/stats/bandwidth` : bande passante réseau temps réel
- **Route** `/api/wazuh/investigate/{agent_id}` : investigation matérielle/logicielle d'un agent

#### `config.py` (50 lignes)
**Responsabilité :** Configuration centralisée via Pydantic Settings.

**Paramètres :**
- `DATABASE_URL` : PostgreSQL (pg8000 driver)
- `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`
- `API_KEY` : clé API pour les services
- `WAZUH_API_URL`, `WAZUH_USER`, `WAZUH_PASS` : credentials Wazuh API
- `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` : credentials Wazuh Indexer (OpenSearch)
- `SURICATA_HOST`, `SURICATA_PORT`, `SURICATA_USER`, `SURICATA_PASS` : SSH Suricata
- `WAZUH_DOCKER_CONTAINER`, `WAZUH_SSH_PORT/USER/PASS` : accès SSH au container Wazuh
- `REDIS_URL` : broker/result backend Celery
- `OLLAMA_URL`, `OLLAMA_MODEL` : configuration LLM local
- `ADMIN_API_KEY`, `ADMIN_JWT_SECRET` : credentials admin
- `ALLOWED_ORIGINS` : CORS

### 1.2 Base de Données

#### `db.py` (16 lignes)
**Responsabilité :** Configuration SQLAlchemy engine + session factory.

- Engine avec `pool_pre_ping=True` pour la reconnexion automatique
- `SessionLocal` : factory de sessions
- `Base` : classe de base déclarative
- `get_db()` : dependency FastAPI pour injecter les sessions

#### `models.py` (146 lignes)
**Responsabilité :** Définition du modèle de données ORM (14 tables).

**Tables :**
| Table | Description |
|-------|-------------|
| `devices` | Appareils réseau (IP, MAC, is_online, is_wazuh_agent) |
| `connection_logs` | Historique de connexion des appareils |
| `suricata_alerts` | Alertes Suricata (timestamp, event_type, src/dest IP, severity, payload) |
| `anomalies` | Anomalies détectées (severity, category, src/dst IP) |
| `assets` | Mapping IP→Employé (ip, employee_name, department) |
| `alerts` | Alertes Wazuh synchronisées (description, severity, src_ip, agent_id) |
| `ia_reports` | Rapports générés par l'IA (report_type, content) |
| `access_logs` | Logs de connexion utilisateurs (login/logout, face_verified, session_duration) |
| `action_logs` | Journal d'audit des actions (username, action, resource, ip_address) |
| `system_config` | Configuration système persistée (section, key, value, is_secret) |
| `network_sensors` | Mesures de bande passante par analyste |
| `network_devices` | Appareils réseau configurables (switch/router, brand, SSH credentials) |

**Relations :**
- `Device` → `ConnectionLog` (one-to-many, back_populates)

**Index importants :**
- `ix_logs_time_range` : index composé sur (start_time, end_time) pour les logs de connexion
- Index sur toutes les colonnes de filtrage fréquent (timestamp, severity, ip, etc.)

#### `schemas.py` (178 lignes)
**Responsabilité :** Schémas Pydantic pour la validation des requêtes/réponses API.

**Schémas principaux :**
- `DeviceBase/Create/Read` : CRUD appareils
- `ScanResult` : résultat de scan Nmap
- `ThreatAnalysisRequest/Response` : analyse de menaces
- `SuricataAlertRead` : lecture alertes Suricata
- `TaskResponse` : statut tâche Celery
- `CommandRequest` : exécution commande SSH
- `IaReportRead` : rapport IA
- `AssetBase/Create/Read` : inventaire assets
- `AccessLogCreate/Read/Status` : logs de surveillance
- `SurveillanceStats` : statistiques de surveillance
- `ActionLogCreate/Read` : logs d'audit
- `AdminStats` : statistiques administrateur
- `NetworkSensorCreate/Read` : capteurs réseau

### 1.3 Authentification & Autorisation

#### `auth.py` (150 lignes)
**Responsabilité :** Système d'authentification multi-méthodes (JWT, API Key, scopes).

**Mécanismes :**
- **OAuth2PasswordBearer** : extraction du token depuis le header Authorization
- **API Key** : header `X-API-Key` pour les services machine-to-machine
- **Auth combinée** `get_api_key_or_jwt()` : accepte soit API Key soit JWT
- **Scope-based authorization** `has_scopes(scopes)` : vérifie les permissions dans le token
- **Auth combinée scopes+API key** `has_scopes_or_api_key(scopes)` : API Key a tous les droits
- **Token from request** : supporte header Authorization OU query parameter `token`

#### `admin_auth.py` (55 lignes)
**Responsabilité :** Authentification admin séparée.

- Token admin avec rôle "admin" et expiration 8h
- Secret JWT séparé (`ADMIN_JWT_SECRET`)
- Vérification du mot de passe admin via `password_manager`
- `get_current_admin` : dependency pour les routes admin

#### `jwt_utils.py` (31 lignes)
**Responsabilité :** Création et vérification des tokens JWT.

- `create_access_token(data, expires_delta)` : crée un JWT avec expiration
- `verify_token(token)` : décode et valide un JWT, retourne `{username, scopes}`

### 1.4 Routers (API Endpoints)

#### `routers/auth.py` (136 lignes)
**Préfixe :** `/auth`
**Responsabilité :** Inscription et connexion des utilisateurs.

- `POST /auth/register` : inscription avec validation de force du mot de passe (8+ chars, majuscule, minuscule, chiffre), rate limiting Redis (3 tentatives/5min)
- `POST /auth/token` : connexion OAuth2, rate limiting (5 tentatives/min)
- **Rôles :** admin, analyst (scopes étendus), viewer (lecture seule)
- **Stockage :** hash bcrypt dans `password_hashes.json` + rôle dans le même fichier

#### `routers/devices.py` (127 lignes)
**Préfixe :** `/devices`
**Responsabilité :** Gestion des appareils et inventaire.

- `GET /devices` : liste tous les appareils
- `POST /devices` : création d'un appareil (vérifie IP/MAC unique)
- `GET /devices/inventory` : inventaire enrichi combinant Device + Asset + bande passante Suricata (calculée depuis les flows)
- `POST /devices/assets` : création/mise à jour d'un asset (mapping IP→employé)

#### `routers/scan.py` (204 lignes)
**Préfixe :** `/api/scan-network`
**Responsabilité :** Scan réseau via Nmap.

- `GET /api/scan-network` : scan Nmap avec 5 modes :
  - `fast` : découverte ARP + TCP/UDP probes
  - `ports` : scan de ports 1-1000
  - `services` : détection de services/versions
  - `os` : détection d'OS
  - `vuln` : scan de vulnérabilités (script Nmap)
- Validation de sous-réseau (pref /16 à /30)
- Détection automatique du sous-réseau local
- Résultats enrichis : vendor, OS, ports, statut connu/inconnu

#### `routers/wazuh.py` (104 lignes)
**Préfixe :** `/api/wazuh`
**Responsabilité :** Intégration Wazuh SIEM.

- `GET /api/wazuh/topology` : topologie réseau dynamique basée sur les agents Wazuh
- `GET /api/wazuh/agents` : liste des agents avec IPs réelles (Syscollector)
- `POST /api/wazuh/refresh-cache` : force le rechargement du cache des identités
- `GET /api/wazuh/alerts` : alertes Wazuh actives depuis la DB
- `GET /api/wazuh/active-responses` : historique des réponses actives défensives
- `GET /api/wazuh/ai-report/{agent_id}` : rapport IA comportemental (streaming)
- `GET /api/wazuh/ai-report-global` : rapport sécurité global (streaming)

#### `routers/suricata.py` (181 lignes)
**Préfixe :** `/api/suricata`
**Responsabilité :** Intégration Suricata IDS/IPS.

- `GET /api/suricata/alerts` : alertes Suricata (priorise les alerts vs flow/stats)
- `POST /api/suricata/webhook` : réception des événements Suricata (NDJSON ou JSON)
  - Parse le format eve.json de Suricata
  - Extrait event_type, alert signature, severity, IPs
  - Simplifie les payloads stats pour éviter la troncation
  - Stocke dans `suricata_alerts` avec verdict (pass/drop/alert)

#### `routers/analyse.py` (121 lignes)
**Préfixe :** `/api/analyse`
**Responsabilité :** Analyse de menaces IA (streaming).

- `POST /api/analyse/analyze-threat` : analyse IA des alertes Wazuh critiques (level >= 7) via Ollama, streaming token par token
- `GET /api/analyse/history` : historique des rapports IA générés
- Sauvegarde automatique des rapports dans `ia_reports`

#### `routers/tasks.py` (74 lignes)
**Préfixe :** `/api/tasks`
**Responsabilité :** Tâches de fond Celery.

- `POST /api/tasks/analyze-threat` : déclenche l'analyse IA en arrière-plan
- `POST /api/tasks/analyze-network-global` : analyse réseau globale en arrière-plan
- `GET /api/tasks/status/{task_id}` : vérifie le statut d'une tâche
- `POST /api/tasks/nmap-scan` : scan Nmap approfondi en arrière-plan

#### `routers/terminal.py` (169 lignes)
**Préfixe :** `/api/terminal`
**Responsabilité :** Exécution de commandes distantes (SSH/Docker).

- `POST /api/terminal/exec` : exécute une commande sur Wazuh (docker exec) ou Suricata (SSH)
- **Sécurité :** whitelist de commandes autorisées par cible
- **Restrictions :** `cat/tail/head` limités aux répertoires sûrs
- **Validation :** pas de pipe, backtick, $, parentheses, etc.
- **Wazuh :** exécution via `docker exec` dans le container
- **Suricata :** connexion SSH avec paramiko (RejectPolicy pour les host keys)

#### `routers/faces.py` (92 lignes)
**Préfixe :** `/api/faces`
**Responsabilité :** Biométrie faciale.

- `POST /api/faces/register` : enregistrement du visage (base64 image)
- `POST /api/faces/verify` : vérification du visage
- `GET /api/faces/status/{username}` : vérifie si un visage est enregistré
- **Sécurité :** un utilisateur ne peut enregistrer/vérifier que son propre visage

#### `routers/surveillance.py` (87 lignes)
**Préfixe :** `/api/surveillance`
**Responsabilité :** Surveillance des sessions utilisateurs.

- `POST /api/surveillance/login` : enregistre une connexion
- `POST /api/surveillance/logout` : enregistre une déconnexion
- `GET /api/surveillance/online` : utilisateurs en ligne avec images faciales
- `GET /api/surveillance/logs` : historique des connexions (paginé)
- `GET /api/surveillance/stats` : statistiques (logins aujourd'hui, sessions moyennes, % face auth)

#### `routers/admin.py` (300 lignes)
**Préfixe :** `/api/admin`
**Responsabilité :** Panneau d'administration.

- `POST /api/admin/token` : connexion admin (rate limité, rôle "admin" uniquement)
- `POST /api/admin/actions/log` : journalise une action
- `GET /api/admin/actions` : liste des actions (filtrable par username/action)
- `GET /api/admin/analysts` : analystes en ligne avec détails
- `GET /api/admin/analysts/{username}/actions` : actions d'un analyste
- `GET /api/admin/analysts/{username}/sessions` : sessions d'un analyste
- `GET /api/admin/stats` : statistiques globales (analysts, sessions, actions, activité horaire)
- `POST /api/admin/analysts/{username}/force-logout` : déconnexion forcée
- `GET /api/admin/face/status` : statut biométrie admin
- `POST /api/admin/change-password` : changement de mot de passe admin

#### `routers/settings.py` (35 lignes)
**Préfixe :** `/api/settings`
**Responsabilité :** Configuration système persistante.

- `GET /api/settings` : lit toutes les configurations (initialise les défauts si nécessaire)
- `PUT /api/settings` : met à jour une section de configuration + recharge la config Wazuh

#### `routers/sensors.py` (428 lignes)
**Préfixe :** `/api/sensors`
**Responsabilité :** Capteurs réseau et santé système.

- `POST /api/sensors/record` : enregistre une mesure de bande passante
- `GET /api/sensors/analyst/{username}` : bande passante d'un analyste
- `GET /api/sensors/analysts` : snapshot bande passante de tous les analystes + serveur
- `GET /api/sensors/health` : **endpoint de santé complet** incluant :
  - Ressources système (CPU, RAM, disque, réseau, uptime)
  - Statut des services (PostgreSQL, Redis, Celery, Ollama)
  - Statistiques de la base (alertes, Suricata, utilisateurs, actions)
  - Alertes récentes, actions récentes, erreurs récentes

#### `routers/database.py` (643 lignes)
**Préfixe :** `/api/admin/database`
**Responsabilité :** Navigateur de base de données admin (introspection + CRUD).

- `GET /api/admin/database/stats` : statistiques complètes (taille DB, connexions, tables, scan stats)
- `GET /api/admin/database/tables` : liste des tables avec compteurs
- `GET /api/admin/database/tables/{name}/columns` : métadonnées de colonnes
- `GET /api/admin/database/tables/{name}/rows` : données paginées avec recherche texte
- `PUT /api/admin/database/tables/{name}/rows/{id}` : mise à jour de ligne
- `DELETE /api/admin/database/tables/{name}/rows/{id}` : suppression de ligne
- `POST /api/admin/database/tables/{name}/rows` : insertion de ligne
- `DELETE /api/admin/database/tables/{name}` : suppression de table (protégée)
- `POST /api/admin/database/tables` : création de table
- **Tables protégées :** les tables système ne peuvent pas être supprimées

#### `routers/network_config.py` (700+ lignes)
**Préfixe :** `/api/network-devices`
**Responsabilité :** Configuration à distance des équipements réseau.

- Templates de configuration pour 12 marques : Cisco, MikroTik, Huawei, Juniper, Arista, Aruba, Dell, Fortinet, Ubiquiti, Extreme, Netgear, D-Link, TP-Link, Zyxel
- Support switch et router avec champs spécifiques (VLANs, ports, sécurité, système, terminal, labels)
- **Note :** Ce fichier est très long principalement à cause des templates de configuration JSON pour chaque marque

### 1.5 Services

#### `services/__init__.py` (26 lignes)
**Responsabilité :** Broadcaster WebSocket pour le temps réel.

- `Broadcaster` : gestion des connexions WebSocket (connect/disconnect/broadcast)
- Thread-safe avec `asyncio.Lock`

#### `services/wazuh_service.py` (1010 lignes)
**Responsabilité :** Service complet d'intégration Wazuh.

**Fonctionnalités :**
- **Authentification Wazuh API** avec token Basic, cache 15min, backoff exponentiel
- **Rate limiting** avec backoff exponentiel sur 429
- **Récupération des agents** avec IPs réelles via Syscollector (netaddr + netiface)
- **Récupération des utilisateurs OS** via Syscollector
- **Cache des identités** : agent_id → {ip, mac, user}
- **Synchronisation des alertes** depuis Wazuh Indexer (OpenSearch) vers PostgreSQL
- **Enrichissement automatique** : crée/met à jour Device et Asset pour chaque agent
- **Topologie réseau** : génère les nœuds/edges pour ReactFlow (groupés par sous-réseau)
- **Rapports IA** : streaming via Ollama pour analyse comportementale par agent et rapport global
- **Historique des réponses actives** : query des alertes active_response dans l'Indexer

#### `services/face_service.py` (278 lignes)
**Responsabilité :** Biométrie faciale avec détection de spoofing.

- **Détection de visage** : Haar cascade avec 5 passes (gamma, gray, equalize, CLAHE, upscaled)
- **Extraction d'encodage** : histogramme LBP + histogramme de contour (Canny)
- **Vérification** : corrélation d'histogrammes (seuil 0.78)
- **Détection de vivacité** : analyse de texture FFT (seuil 0.15) pour rejeter les photos
- **Stockage** : fichiers .npy pour les encodages, .jpg pour les visages, mapping JSON

#### `services/surveillance_service.py` (182 lignes)
**Responsabilité :** Gestion des sessions de surveillance.

- Enregistrement login/logout avec durée de session
- Sauvegarde des images faciales (hash SHA256 → fichier JPG)
- Statistiques : logins/jour, utilisateurs en ligne, durée moyenne, % face auth
- Historique horaire des connexions

#### `services/password_manager.py` (71 lignes)
**Responsabilité :** Gestion des mots de passe hashés (bcrypt).

- Stockage dans `password_hashes.json` (fichier JSON)
- `store_password_hash()` : hash bcrypt + stockage
- `check_password()` : vérification
- `user_exists()` : vérification d'existence
- Fonctions utilitaires de hash (SHA256)

#### `services/system_config_service.py` (129 lignes)
**Responsabilité :** Configuration système persistante dans PostgreSQL.

- **Sections :** wazuh_api, wazuh_indexer, suricata_ssh, wazuh_ssh, ollama, redis
- Initialisation des défauts au démarrage
- Lecture/écriture avec fallback vers les variables d'environnement
- Gestion des secrets (masquage en lecture)

#### `services/action_logger.py` (31 lignes)
**Responsabilité :** Journalisation simplifiée des actions.

- `log_action()` : écrit dans `action_logs` avec username, action, resource, ip

#### `services/msev.py` (797 lignes)
**Responsabilité :** MSEV (Multi-Spectral & Electro-Vascular) — système avancé de détection de vivacité biométrique.

**Modules :**
1. **SecureFramePipeline** : vérification cryptographique des frames (HMAC-SHA256)
2. **SpectralAnalyzer** : analyse de réflectance spectrale (peau humaine vs silicone/latex/écran)
3. **RPPGEngine** : photopléthysmographie distante (détection de pouls par FFT)
4. **PupilChallenge** : test de constriction pupillaire (réponse à flash lumineux)
5. **MSEVValidator** : orchestrateur combinant tous les modules (AND logique)

**Note :** Ce module est un prototype avancé avec des tests auto-validés. Il n'est pas encore intégré au pipeline de production.

### 1.6 Workers (Celery)

#### `worker.py` (238 lignes)
**Responsabilité :** Tâches de fond pour l'analyse IA.

- **Celery app** avec broker Redis, timeout 600s
- **`_call_ollama()`** : appel à Ollama avec lock Redis non-bloquant (timeout 300s)
- **`analyze_threat_task`** : analyse des 5 alertes Wazuh critiques (level >= 7) via Ollama
- **`analyze_network_global_task`** : audit réseau exécutif basé sur les alertes Suricata critiques
- **Sauvegarde** automatique des rapports dans `ia_reports`

#### `nmap_worker.py` (62 lignes)
**Responsabilité :** Scan Nmap approfondi en arrière-plan.

- Tâche Celery dédiée avec timeout 3600s
- Scan avec résultats : IP, MAC, ports, OS
- Queue dédiée `nmap_queue`

### 1.7 Utilitaires

#### `scanner.py` (157 lignes)
**Responsabilité :** Scanner ARP réseau en arrière-plan.

- `get_active_interfaces()` : détecte les interfaces physiques actives
- `scan_network()` : scan ARP via Scapy (requiert root/admin)
- `background_scanner()` : boucle de scan avec mise à jour DB :
  - Détecte les nouveaux appareils
  - Gère les conflits d'IP (MAC comme identifiant stable)
  - Met à jour le statut online/offline
  - Crée les logs de connexion
  - Broadcaster les changements via WebSocket

#### `logging_filter.py` (15 lignes)
**Responsabilité :** Filtre de logging pour masquer les secrets.

- `SecretScrubber` : remplace les valeurs de password/secret/key/token par `***`

---

## 2. FRONTEND — `frontend/src/`

### 2.1 Architecture React

#### `App.jsx` (128 lignes)
**Responsabilité :** Racine de l'application React.

- **React Router** avec 15 routes (lazy loading)
- **QueryClientProvider** (TanStack Query)
- **AuthProvider** + **DataProvider** pour le state global
- **ErrorBoundary** pour la gestion d'erreurs
- **Suspense** avec loader personnalisé

**Routes :**
| Path | Composant |
|------|-----------|
| `/` | DashboardPage |
| `/topology` | TopologyPage |
| `/surveillance` | SurveillancePage |
| `/inventory` | InventoryPage |
| `/radar` | RadarPage |
| `/tasks` | TasksPage |
| `/terminal` | TerminalPage |
| `/remediation` | RemediationPage |
| `/alerts` | TerminalAlertsPage |
| `/suricata` | SuricataPage |
| `/network-control` | NetworkControlPage |
| `/network-devices` | NetworkDevicesPage |
| `/ai` | AICopilotPage |
| `/ai-history` | AIHistoryPage |
| `/settings` | SettingsPage |

#### `main.jsx` (10 lignes)
**Responsabilité :** Point d'entrée React (ReactDOM.createRoot).

### 2.2 Contextes

#### `contexts/AuthContext.jsx` (103 lignes)
**Responsabilité :** Gestion de l'authentification et du token JWT.

- Stockage du token dans localStorage
- Auto-login en développement (bypass avec `dev_user`)
- `createFetchWithAuth()` : wrapper fetch avec token automatique
- Gestion du 401 (redirection vers login)
- Gestion du 429 (retry après `Retry-After`)
- Surveillance login/logout via `/api/surveillance/`

#### `contexts/DataContext.jsx`
**Responsabilité :** Partage de données globales (alerts, devices, etc.)

### 2.3 Librairies

#### `lib/api.js` (52 lignes)
**Responsabilité :** Client HTTP avec authentification.

- `apiGet()`, `apiPost()` : requêtes basiques
- `createFetchWithAuth(getToken, onUnauthorized)` : wrapper avec :
  - Injection automatique du token Bearer
  - Redirection sur 401
  - Retry automatique sur 429 avec `Retry-After`

### 2.4 Composants

#### `components/Layout.jsx`
**Responsabilité :** Layout principal avec sidebar de navigation.

#### `components/LoginPage.jsx`
**Responsabilité :** Page de connexion.

#### `components/AlertRow.jsx`
**Responsabilité :** Ligne d'alerte individuelle.

#### `components/TopologyView.jsx`
**Responsabilité :** Visualisation de topologie réseau (ReactFlow).

#### `components/SurveillanceDashboard.jsx`
**Responsabilité :** Tableau de bord de surveillance.

### 2.5 Pages

| Page | Description |
|------|-------------|
| `DashboardPage.jsx` | Tableau de bord principal (KPIs, alertes récentes, graphiques) |
| `TopologyPage.jsx` | Topologie réseau Wazuh (ReactFlow) |
| `SurveillancePage.jsx` | Surveillance des sessions utilisateurs |
| `InventoryPage.jsx` | Inventaire des appareils et assets |
| `RadarPage.jsx` | Vue radar des menaces |
| `TasksPage.jsx` | Gestion des tâches IA et Nmap |
| `TerminalPage.jsx` | Terminal distant (Wazuh/Suricata) |
| `RemediationPage.jsx` | Actions de remédiation |
| `TerminalAlertsPage.jsx` | Alertes en temps réel |
| `SuricataPage.jsx` | Alertes et statistiques Suricata |
| `NetworkControlPage.jsx` | Contrôle réseau |
| `NetworkDevicesPage.jsx` | Configuration des équipements réseau |
| `AICopilotPage.jsx` | Copilote IA pour l'analyse de menaces |
| `AIHistoryPage.jsx` | Historique des rapports IA |
| `SettingsPage.jsx` | Configuration système |
| `AlertHistoryModal.jsx` | Modal d'historique des alertes |
| `InvestigationModal.jsx` | Modal d'investigation d'agent |

### 2.6 Styles

| Fichier | Description |
|---------|-------------|
| `styles/global.css` | Styles globaux |
| `styles/layout.css` | Layout et sidebar |
| `styles/dashboard.css` | Tableau de bord |
| `styles/login.css` | Page de connexion |
| `styles/components.css` | Composants réutilisables |
| `styles/suricata.css` | Page Suricata |
| `styles/surveillance.css` | Page surveillance |
| `styles/ai.css` | Page IA |

### 2.7 Internationalisation

#### `i18n/translations.js`
**Responsabilité :** Traductions (FR/EN).

---

## 3. ADMIN FRONTEND — `admin-frontend/src/`

### `App.jsx`
**Responsabilité :** Panneau d'administration séparé.

- Interface dédiée pour les administrateurs
- Gestion des analystes, actions, statistiques
- Navigateur de base de données

### `vite.config.js`
**Responsabilité :** Configuration Vite pour l'admin frontend.

---

## 4. INFRASTRUCTURE

### `docker-compose.yml` (10 lignes)
**Responsabilité :** Configuration de développement (Redis uniquement).

### `docker-compose.prod.yml` (105 lignes)
**Responsabilité :** Stack de production complète.

**Services :**
| Service | Image | Port | Sécurité |
|---------|-------|------|----------|
| `backend` | Build từ ./backend | 8000 | read_only, no-new-privileges |
| `worker` | Build từ ./backend | - | Celery solo pool |
| `frontend` | nginx:alpine | 80 | read_only |
| `postgres` | postgres:16 | 5432 | no-new-privileges |
| `redis` | redis:7 | 6379 | requirepass |
| `ollama` | ollama/ollama | 11434 | no-new-privileges |
| `wazuh` | Build từ ./wazuh | 1514/1515/55000 | no-new-privileges |

### `Makefile` (73 lignes)
**Responsabilité :** Commandes de développement (Windows-centric).

**Cibles :**
- `install` : installation des dépendances
- `dev` : lance tous les services en développement
- `dev-backend/frontend/worker/wazuh/ollama` : services individuels
- `build` : build frontend pour production
- `prod/prod-down` : gestion Docker Compose production
- `clean` : nettoyage
- `lint` : linters (ruff, eslint)

### `start.sh` / `start.bat`
**Responsabilité :** Scripts de démarrage multi-plateformes.

### `.github/workflows/ci.yml`
**Responsabilité :** Pipeline CI/CD GitHub Actions.

---

## 5. FLUX DE DONNÉES PRINCIPAUX

### 5.1 Alerte Wazuh → Dashboard
```
Wazuh Agent → Wazuh Manager → Wazuh Indexer (OpenSearch)
    ↓ (toutes les 60s)
wazuh_service.sync_alerts() → PostgreSQL (alerts table)
    ↓
GET /api/real-alerts → Frontend Dashboard
```

### 5.2 Alerte Suricata → Dashboard
```
Suricata IDS → eve.json → Script d'forwarding
    ↓
POST /api/suricata/webhook → PostgreSQL (suricata_alerts table)
    ↓
GET /api/suricata/alerts → Frontend SuricataPage
```

### 5.3 Analyse IA
```
Frontend → POST /api/tasks/analyze-threat
    ↓
Celery Worker → query alerts (level >= 7)
    ↓
Ollama LLM → Streaming response
    ↓
POST /api/analyse/analyze-threat → Frontend (SSE)
    ↓
Sauvegarde dans ia_reports
```

### 5.4 Scan Réseau
```
Frontend → GET /api/scan-network?subnet=X&type=fast
    ↓
Nmap PortScanner → ARP/TCP/UDP/OS/Vuln scan
    ↓
Résultats enrichis (vendor, OS, ports) → Frontend
```

### 5.5 Temps Réel (WebSocket)
```
Scanner ARP / Wazuh Sync / Suricata Webhook
    ↓
broadcaster.broadcast(payload)
    ↓
WebSocket /ws/status → Frontend (Dashboard, Alerts)
```

---

## 6. SÉCURITÉ

### Authentification
- **JWT** pour les utilisateurs (expiry configurable)
- **API Key** pour les services machine-to-machine
- **Admin JWT** séparé avec secret distinct
- **Rate limiting** Redis sur les endpoints d'authentification

### Autorisation
- **Scope-based** : devices:read, alerts:read, terminal:exec, ai:generate, admin:manage, etc.
- **Rôles :** admin (tous droits), analyst (majorité), viewer (lecture seule)
- **Tables protégées :** les tables système ne peuvent pas être supprimées via l'admin

### Validation
- **Commande whitelist** pour le terminal (pas d'injection possible)
- **Validation de sous-réseau** pour les scans Nmap
- **Input validation** Pydantic sur tous les endpoints
- **SecretScrubber** : masquage des secrets dans les logs

### Biométrie
- **Détection de spoofing** : analyse FFT de texture (photo vs visage réel)
- **MSEV** (prototype) : signature cryptographique + réflectance spectrale + rPPG + constriction pupillaire

---

## 7. DÉPENDANCES PRINCIPALES

### Backend (Python)
- `fastapi` : framework web async
- `sqlalchemy` : ORM
- `celery` : tâches de fond
- `redis` : broker/cache
- `httpx` : client HTTP async
- `paramiko` : client SSH
- `nmap` : scanner réseau (python-nmap)
- `scapy` : packets réseau (ARP scan)
- `psutil` : monitoring système
- `opencv-python` : traitement d'images (biométrie)
- `numpy` : calcul numérique
- `bcrypt` : hashage mots de passe
- `python-jose` : JWT
- `pydantic-settings` : configuration

### Frontend (JavaScript)
- `react` : UI framework
- `react-router-dom` : routing
- `@tanstack/react-query` : data fetching
- `react-toastify` : notifications
- `reactflow` : visualisation de topologie (TopologyView)

---

## 8. NOTES TECHNIQUES

### Points Forts
1. **Architecture modulaire** : séparation claire routers/services/models
2. **Temps réel** : WebSocket pour les mises à jour live
3. **IA intégrée** : Ollama pour l'analyse de menaces sans dépendance cloud
4. **Biométrie avancée** : MSEV comme prototype de liveness detection de nouvelle génération
5. **Multi-brand** : support de 12+ marques d'équipements réseau
6. **Sécurité** : rate limiting, command whitelist, secret scrubbing

### Points d'Attention
1. **Stockage des passwords** : `password_hashes.json` en fichier JSON (pas en DB)
2. **Face data** : stockage filesystem (pas en DB)
3. **Login bypass** : activé en développement dans AuthContext
4. **Makefile** : Windows-centric (pas cross-platform)
5. **network_config.py** : très long à cause des templates JSON (pourrait être externalisé)

### État du Développement
- Le projet est fonctionnel avec un pipeline complet : scan → alerte → analyse → remédiation
- Le MSEV est un prototype non intégré
- L'admin frontend semble être un projet séparé en cours de développement
