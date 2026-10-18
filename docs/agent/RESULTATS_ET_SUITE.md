# Résultats livrés & étapes restantes — Sentinel Bridge Agent Lab

**Branche:** `arena/9a8706e8-projet-soc-ips-siem-xdr` — commit `276b267` + suites  
**Date:** 2026-10-18  
**Lab:** Serveur SOC mix (Windows/Linux) + agents Windows Server/11, HTTP lab, Wi-Fi local, sans cloud/SaaS

---

## 1. Ce qui est implémenté (première étape prioritaire)

### Backend

| Composant | Fichier | Vérification |
|---|---|---|
| **Identité révocable** | `domain/models.AgentToken` + `domain/agent_tokens.py` | `POST /api/agent/enroll` → token `sb_...` unique, `hash_token` sha256, `is_revoked`, rotation auto. `POST /api/agent/revoke` → `status=revoked`. |
| **Auth agent** | `interface/api/agent.py:agent_auth` | `X-Agent-Token` / `Bearer <token>` vérifié vs hash, `X-API-Key` legacy conservé. |
| **Heartbeat** | `POST /api/agent/heartbeat` | `last_seen`, `last_ip`, `collectors` status, `pending_orders` hint. `online` si <90s et non révoqué. |
| **Telemetry batch + ack** | `POST /api/agent/telemetry` | `seq` monotone, `ack_seq` réponse, `deduped` si seq déjà vu. Catégories: `system_logs`, `auth_logs`, `network_connections`, `processes`, `security_events`, etc. File serveur `Agent.seq` + `last_ip`. |
| **Collecte configurable** | `application/system_config:host_agent` | `enable_system_logs/auth/processes/network`, `batch_size`, `queue_max_events`, `verify_tls`, `heartbeat_interval`. |
| **Pipeline** | `application/normalization.map_host_agent` + `api/agent._forward_to_pipeline` | Normalisation ECS-like préserve `category`, `agent_id` fallback host, forwarding 6 catégories vers `ingest_alert`. |
| **TI guard** | `infrastructure/threat_intel/private_ip.py` + `providers.py` + `client.lookup_ip` | Skip IP privées (RFC1918/127/169.254/doc) → `unknown` sans requête. Cache par `provider`, quotas in-memory, fail-open. |
| **Providers** | `providers.py` | AbuseIPDB (actif), VirusTotal & Kaspersky (stubs conformes API officielle, besoin clés `VIRUSTOTAL_API_KEY`/`KASPERSKY_API_KEY` côté serveur). |

### Agent Python (Windows/Linux)

```
agent/
  config.example.json          # LAN template (pas localhost)
  requirements.txt             # psutil + requests + pywin32 (Windows)
  sentinel_agent/
    config.py                  # load JSON, LAN warning, env overrides
    client.py                  # LAN HTTP, TLS verify, retry, --check
    queue.py                   # JSONL bornée 5000/20MB, FIFO, dedup hash
    collectors/
      system_logs.py           # journalctl (Linux) / Win EventLog (pywin32)
      network.py               # psutil.net_connections + auth.log / 4624
      processes.py             # psutil top CPU
    __main__.py                # heartbeat/telemetry/orders loop, seq/ack
    service/
      install_windows.ps1      # NSSM ou Task Scheduler
      install_linux.sh         # systemd
```

- **Aucun scan réseau** : seulement `net_connections` du host, pas de `nmap`.
- **File bornée reprise** : `queue.jsonl` FIFO, `ack_seq` purge.
- **Ordres whitelist** : `block_ip/unblock_ip/kill_process/quarantine_file/terminate_session/restart_service` en dry-run (pas d'exécution destructive auto sans approbation).
- **Service & désinstall** documentés.

### Frontend

- `HostAgentsPage.jsx` → panel **Enroller** (agent_id + label → enroll → token unique à copier → config.json snippet → revoke).
- Backend `status` enrichi: `last_ip`, `status`, `seq`, `token`.

### Réseau / Sécurité

- `start.sh --lan` → `uvicorn --host 0.0.0.0` (agents) vs `127.0.0.1` (dev). Docs insistent: Postgres/Redis restent `127.0.0.1`.
- `docs/agent/README.md` §2, §6, §7, §8: IP LAN, pare-feu `netsh`/`ufw`, Wi-Fi isolation/AP expliquée, TLS conservé si https.

### Tests reproductibles

- `backend/tests/test_agent_lab.py`: enroll→revoke→heartbeat 403, seq ack dedup, private IP guard, host-agent normalization.
- `agent/tests/test_queue.py`: bounded FIFO + dedup.

---

## 2. Investigation locale — deuxième étape (déjà réutilisée)

```
collecte → normalisation (map_host_agent) → contextualisation (tenant) → déduplication (sha256 src|dst|sig, 60s) → corrélation (sequence/count persisté) → investigation (ti_src/dest, host_wazuh, asset, related, mitre) → score 0-100 → recommandations → décision analyste → réponse (whitelist) → vérification/clôture/rapport
```

- **Corrélateur** & **MITRE** réutilisés tels quels (`evaluator.MITRE_TECHNIQUES`, `correlator.WindowedCorrelator`).
- MITRE contextualise, ne verdict pas : doc insistée `docs/agent/README.md` §9.
- **Sans Internet** : pipeline+règles+scoring OK, TI `unknown` fail-open.
- Investigations visibles: `Investigations` → `Evidence` → `Recommendations` (déjà UI).
- **Clôture explicite** conservée (`Case.status`), rapports non auto.

### Limites actuelles

- `DedupTracker` in-memory par process (pas distribué) — OK pour lab mono-worker, à durcir en prod multi-worker via Redis.
- `related_alerts` step utilise seulement `Alert` (pas encore `SuricataAlert` joint) — à compléter.

---

## 3. Enrichissement optionnel — troisième étape

| Principe | Statut |
|---|---|
| Requêtes uniquement serveur SOC | ✅ `client.lookup_ip` côté serveur, jamais agent |
| Clés serveur uniquement | ✅ `SystemConfig/threat_intel` ou env `VIRUSTOTAL_API_KEY`, jamais agent/dépôt |
| Cache + TTL | ✅ `threat_intel_cache` provider-scoped, TTL `THREAT_INTEL_CACHE_TTL_SECONDS` |
| Quotas | ✅ in-memory 1000 (AbuseIPDB) / 500 (VT) par jour, log warning, fail-open |
| Sourcé/daté | ✅ `checked_at`, `from_cache`, `source_name`, `raw_json`, `provider` |
| Unknown jamais clean | ✅ `unknown` affiché "Inconnu", pas "Sain" |
| Pas de requête IP privée | ✅ `is_private_or_reserved` → skip avant fetch |
| Aucun envoi fichier/logs | ✅ seules IPs requêtées, jamais payload agent |

- AbuseIPDB conservé, VT/Kaspersky stubs prêts (tests sans clé réelle).
- Frontend `Intel` déjà montre `enabled/provider/cache`.

---

## 4. Vérifications à faire dans votre lab (je ne peux pas tester vos PCs)

```powershell
# 1. Serveur IP LAN
ipconfig  # Windows | ip addr (Linux)

# 2. Lancer backend LAN
./start.sh --lan
# ou: cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8001

# 3. Pare-feu serveur (Windows Admin)
netsh advfirewall firewall add rule name="Sentinel SOC 8001" dir=in action=allow protocol=TCP localport=8001 profile=private

# 4. Enroll agent
curl ... /api/agent/enroll → token sb_...

# 5. Sur chaque PC agent: copier token → config.json → python -m sentinel_agent --check
# Attendu: Register OK + Heartbeat OK + Test-NetConnection 192.168.1.50 8001 réussit

# 6. Si échec: ping 192.168.1.50 → si KO, revoir §7 Wi-Fi isolation/AP sur box admin 192.168.1.1

# 7. Voir dans SOC: Host Agents → agent online, Processes/Events, Investigations si règle matchée
```

---

## 5. Limites & étapes restantes

| Limite | Prochaine action (après votre accord) |
|---|---|
| Frontend enroll ok, mais pas encore `Investigations → filtre par agent_id` | Ajouter filtre agent dans `InvestigationsPage` |
| TI VT/Kaspersky stubs non testés avec vraies clés (besoin accès API) | Tester avec vos clés si vous avez accès, documenter quotas réels |
| Agent Windows EventLog nécessite `pywin32` (optionnel) | Tester sur votre Windows Server avec `pip install pywin32` |
| Pas de package `.exe` one-file | Si besoin, ajouter `PyInstaller` build |
| Tests CI sans dépendance Postgres/Redis complets via SQLite passent, mais lint/build frontends non exécutés ici | Lancer `make lint` + `pytest` + `npm run build` dans CI avant merge |

---

## 6. Avant publication/fusion

- Aucune publication sans votre accord (votre consigne).
- Secrets non commis (`.gitignore` agent/config.json, queue.jsonl).
- Cette doc + `LAB_AGENT_ANALYSIS.md` + `docs/agent/README.md` constituent la preuve de travail.

**Proposez votre IP LAN serveur et confirmez si vous voulez que je lance la prochaine PR (agent→investigations filter) ou si vous préférez tester d'abord chez vous.**
