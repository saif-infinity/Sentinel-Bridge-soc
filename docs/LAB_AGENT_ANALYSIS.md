# Sentinel Bridge — Analyse existant & Plan Agent Natif (Lab Wi-Fi local)

**Date:** 2026-10-18 — branche `arena/9a8706e8-projet-soc-ips-siem-xdr`  
**Contexte:** lab local, Wi-Fi partagé, 1 PC serveur + N PC Windows/Linux, pas d'exposition Internet.

---

## 1. Existant examiné

### Backend
| Fichier | État actuel | Limite pour le lab |
|---|---|---|
| `backend/app/interface/api/agent.py` | Routes `/register`, `/telemetry`, `/orders`, `/status`, `/processes`, `/events`, auth via `API_KEY` global | Pas d'identité par agent, pas de révocation, pas de heartbeat explicite, pas d'ack fiable. |
| `backend/app/domain/models.py` | `Agent(agent_id, hostname, os, arch, version, tenant_id, registered_at, last_seen, seq, capabilities)` + `AgentTelemetryEvent` + `AgentOrder` | Manque `last_ip`, `status`, `enrolled_at`, table de tokens. |
| `backend/app/interface/api/sources.py` | Toggles `host_agent / wazuh / suricata` via `SystemConfig` + `source_control.is_source_enabled()` | OK, reste combinable. Déjà prévu pour désactiver Wazuh/Suricata. |
| `backend/app/application/normalization.py` | Mappers `suricata`, `wazuh`, `syslog`, `generic` | Pas de mapper `host-agent` dédié (actuellement passe par `generic`). |
| `backend/app/application/pipeline.py` | `ingest_alert` → déduplication (sha256 sur src_ip|dest_ip|signature), suppression, normalisation sévérité, persistance `Alert`/`SuricataAlert`/`PipelineEvent`, puis `evaluate_normalized_alert` | Déduplication in-memory par process, pas de tenant dans la clé (risque collision multi-tenant). OK pour lab mono-process. |
| `backend/app/application/rules/` | `correlator.py` (séquence + count fenêtrés persistés), `engine.py` (cache règles + MITRE), `evaluator.py` (MITRE table 40+ techniques, mapping sévérité) | Réutilisable tel quel. MITRE est déjà contextual, pas verdict auto. |
| `backend/app/application/investigations/` | Orchestrateur : quotas, dedup 24h, 6 collecteurs (`ti_src`, `ti_dest`, `host:wazuh`, `asset`, `related_alerts`, `mitre_context`), scoring pondéré, synthèse LLM ou template, recommandations | Déjà lié au pipeline via `CHANNEL_RULE_MATCH`. TI est `lookup_ip` AbuseIPDB. |
| `backend/app/infrastructure/threat_intel/client.py` | `fetch_abuseipdb`, `_upsert_cache`, `lookup_ip`, `ensure_intel_columns`, cache TTL 1h, dialect-aware | Pas de filtre IP privée, un seul provider, pas de quotas. |
| `frontend/src/pages/HostAgentsPage.jsx` | Liste agents, processus, événements, misconfigs dédupliquées, commandes + historique | Pas de vue enrollment / révocation, pas de heartbeat détaillé. |

### Docs & Config
- `backend/app/core/config.py` : `Settings` avec `ENABLE_HOST_AGENT_SOURCE=True` par défaut, `THREAT_INTEL_ENABLED=True`, `ALLOWED_ORIGINS`, `DATABASE_URL`, `REDIS_URL`.
- `backend/app/application/system_config.py` : section `host_agent` avec `api_url`, `api_key`, `tenant_id`, `agent_id`, `telemetry_interval_secs`, `orders_interval_secs`, etc.
- `docker-compose.yml` : Postgres `127.0.0.1:5432`, Redis `127.0.0.1:6379`, FastAPI `127.0.0.1:8001` — **jamais exposer Postgres/Redis aux agents**, seul `/api/agent/*` est exposé sur LAN.

---

## 2. Objectif prioritaire — Agent natif

> Recevoir directement les événements des PC via un agent natif Windows/Linux, sans imposer Wazuh/Suricata. Wazuh/Suricata restent activables en parallèle.

### Principes retenus pour le lab
- **Sans cloud/SaaS** : tout reste sur le Wi-Fi local.
- **Agent Python** (choix utilisateur) : `psutil` + collecteurs stdlib, config file JSON, file locale bornée, reprise après coupure.
- **Adresse serveur = IP LAN** du PC serveur (ex: `192.168.1.50:8001`), jamais `localhost` depuis les clients.
- **Collecte uniquement volontaire** : pas de scan réseau, pas de shell distant arbitraire hors ordres explicites approuvés.
- **TLS conservé si HTTPS** : `verify=True` par défaut, documenter le mode HTTP lab.

### Fonctionnalités à implémenter
1. **Identité & auth révocable** : table `agent_tokens` (token_hash, tenant_id, revoked, expires_at). Endpoint `POST /api/agent/enroll` (admin) génère token unique par agent. Auth agent = `X-Agent-Token: <token>` ou `Authorization: Bearer <token>` vérifié en constant-time vs hash. `POST /api/agent/revoke` révoque.
2. **Adresse serveur configurable** : `agent/config.json` avec `server_url`, `agent_id`, `token`, `tenant_id`, `verify_tls`.
3. **Heartbeat & état** : `POST /api/agent/heartbeat` toutes les 30s, `last_seen`, `online` si <90s, `last_ip`, `collectors_status`.
4. **Collecte configurable** : `enable_system_logs`, `enable_auth_logs`, `enable_processes`, `enable_network` (bool + intervalles) côté serveur `SystemConfig/host_agent` et fichier local.
5. **Envoi par lots, file bornée, reprise** : queue JSONL `queue.jsonl` max 5000 events / 20MB, flush batch 50, retry exponentiel, ack serveur `received_seq`.
6. **Déduplication & ack fiable** : client envoie `seq` monotone, serveur stocke `Agent.last_seq` et `deduplication via pipeline dedup_key`. Réponse telemetry `{ack_seq: N, received: count, deduped: X}`.
7. **Service & doc** : `systemd` (Linux), `nssm` ou `sc` (Windows), désinstallation, pare-feu Windows/Linux, Wi-Fi isolation.

---

## 3. Investigation locale — pipeline existant

```
collecte (agent) → normalisation (map_host_agent) → contextualisation (tenant, MITRE) → déduplication → corrélation (sequence/count) → investigation (6 steps + scoring) → preuves/score → recommandation → décision analyste → réponse autorisée → vérification/clôture → rapport
```

- Réutilise `correlator.py` (fenêtre temporelle), `evaluator.py` (MITRE tactics), `investigations/orchestrator.py`.
- MITRE sert à **contextualiser** (ex: `T1059 → execution`), pas à verdict auto.
- Fonctionnement **sans Internet** : pipeline + règles + scoring local restent actifs. TI est optionnel et fail-open.

### Améliorations prévues
- Nouveau mapper `map_host_agent` normalisant `system_log`, `auth`, `process`, `network_connection` vers `description` + `event.category`.
- `lookup_ip` skip IP privées (RFC1918, loopback, link-local) → verdict `unknown` sans requête.
- Provider abstraction : `providers/abuseipdb.py`, `providers/virustotal.py`, `providers/kaspersky.py` avec interface commune `lookup(ip) → {verdict, score, source, raw}`.

---

## 4. Enrichissement optionnel

- **AbuseIPDB conservé**, **VirusTotal** et **Kaspersky** prévus en `optional` selon API officielles.
- Règles communes :
  - Requêtes **uniquement depuis serveur SOC**, clés en `SystemConfig/threat_intel` ou env `THREAT_INTEL_*`, jamais dans agent/dépôt.
  - Cache `threat_intel_cache` étendu avec colonne `provider` (`abuseipdb|virustotal|kaspersky`), TTL configurable, quotas (ex: AbuseIPDB 1000/j, VT 500/j) avec rate-limit.
  - Résultats sourcés/détés (`checked_at`, `from_cache`, `source_name`).
  - Absence → `unknown`, jamais `clean`.
  - **Pas de requête pour IP privées** (skip + log debug).
  - **Aucun envoi auto de fichiers/logs bruts**.

---

## 5. Interface, tests, doc

- Frontend : nouvelle section enrollment (générer token, copier, révoquer), badge TLS, état heartbeat.
- Tests : unit `test_agent_auth.py`, `test_agent_telemetry.py`, `test_threat_intel_providers.py`, intégration lab non-destructif.
- Docs : `docs/agent/README.md`, `docs/agent/INSTALL_WINDOWS.md`, `docs/agent/INSTALL_LINUX.md`, `docs/agent/TROUBLESHOOTING.md` (pare-feu, isolation client).

---

## 6. Ordre d'implémentation (cette session)

1. **Backend auth** : `AgentToken` + `enroll/revoke/heartbeat` + `verify_tls` doc.
2. **Agent Python** : squelette `agent/` + collecteurs + queue + heartbeat.
3. **Pipeline** : `map_host_agent` + forwarding étendu + TI private-IP skip.
4. **TI providers** : abstraction + VT/Kaspersky stubs.
5. **Frontend** : enrollment UI.
6. **Docs & scripts service**.

Aucunepublication sans accord. Tests exécutables localement fournis.

