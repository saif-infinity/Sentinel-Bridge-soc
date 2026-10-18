# Agent Sentinel Bridge — Lab Wi-Fi local

> **Objectif :** recevoir directement les événements de vos PCs Windows/Linux sur le serveur SOC, sans Wazuh/Suricata, en restant combinable avec eux.

---

## Sommaire
- [1. Architecture](#1-architecture)
- [2. Prérequis réseau](#2-prérequis-réseau)
- [3. Enroller un agent](#3-enroller-un-agent)
- [4. Installer — Windows Server / Windows 11](#4-installer--windows-server--windows-11)
- [5. Installer — Linux (si présent)](#5-installer--linux-si-présent)
- [6. Vérifications & pare-feu](#6-vérifications--pare-feu)
- [7. Wi-Fi invité / isolation client](#7-wi-fi-invité--isolation-client)
- [8. TLS / HTTP lab](#8-tls--http-lab)
- [9. Pipeline → Investigation](#9-pipeline--investigation)
- [10. Enrichissement optionnel (AbuseIPDB / VT / Kaspersky)](#10-enrichissement-optionnel-abuseipdb--vt--kaspersky)
- [11. Dépannage rapide](#11-dépannage-rapide)

---

## 1. Architecture

```
[PC agent Windows/Linux]  --(HTTPS/HTTP, X-Agent-Token)-->  [PC Serveur: backend:8001 /api/agent/*]
        | collectors: system_logs, auth, processes, network       | pipeline → règles → investigations
        | queue.jsonl bornée, seq + ack                           | Postgres + Redis (NON exposés aux agents)
        | heartbeat 30s                                            | Frontend HostAgentsPage
[Wazuh] --------------------(webhook/api)----------------------->  même pipeline (combinable)
[Suricata] ---------------(webhook/ssh)------------------------>  même pipeline
```

- **Seul le backend** est exposé aux agents, sur l'**IP LAN** du serveur (ex: `192.168.1.50:8001`).
- **Postgres (5432) et Redis (6379) restent en `127.0.0.1:5432/6379` ou en conteneur interne**, jamais ouverts au Wi-Fi.
- **Pas de scan automatique** : l'agent ne collecte que le host où il est installé. Aucune découverte réseau.

---

## 2. Prérequis réseau

| Élément | Valeur recommandée |
|---|---|
| Serveur | IP fixe ou réservation DHCP (ex: `192.168.1.50`). Noter `ipconfig` (Windows) ou `ip addr` (Linux). |
| PC agents | Même sous-réseau Wi-Fi que serveur. Tester `ping 192.168.1.50` depuis l'agent. |
| Box / AP | **Désactiver "Isolation client" / "AP isolation" / "Wi-Fi invité"** : ces modes empêchent les clients Wi-Fi de se voir entre eux — l'agent ne pourra jamais joindre le serveur. |
| Ports | Serveur: ouvrir `TCP 8001` inbound depuis le subnet. Agents: autoriser outbound vers serveur:8001 (par défaut autorisé). |
| DNS (optionnel) | `sentinel.local` → 192.168.1.50 via `/etc/hosts` ou DNS local, mais **IP directe suffit et est plus simple**. |

> **À faire avant d'installer :** trouvez l'IP LAN du serveur (voir §6). Ne jamais configurer `localhost` ou `127.0.0.1` dans `agent/config.json` sur une autre machine — localhost désigne la machine elle-même, pas le serveur.

---

## 3. Enroller un agent

L'enroll crée **une identité propre + token révocable** par agent (répond à l'exigence "sans scan").

### Depuis le serveur (PowerShell / Bash)

```bash
# Charger la clé admin (depuis backend/.env)
export API_KEY=$(python -c 'from dotenv import dotenv_values; print(dotenv_values("backend/.env")["API_KEY"])')

curl -X POST http://192.168.1.50:8001/api/agent/enroll \
  -H "X-API-Key: $API_KEY" -H "X-Tenant-ID: default" -H "Content-Type: application/json" \
  -d '{"agent_id":"pc-bureau-01","label":"PC Bureau Win11","expires_days":365}'

# Réponse: {"status":"ok","agent_id":"pc-bureau-01","token":"sb_...","token_id":"...","message":"Token à copier ..."}
```

- `token` affiché **une seule fois** — copiez-le dans `agent/config.json` (`"token": "sb_..."`).
- Rotation : refaire `enroll` avec même `agent_id` → anciens tokens révoqués automatiquement.
- Révocation manuelle :

```bash
curl -X POST http://192.168.1.50:8001/api/agent/revoke \
  -H "X-API-Key: $API_KEY" -H "X-Tenant-ID: default" -H "Content-Type: application/json" \
  -d '{"agent_id":"pc-bureau-01"}'
# L'agent passe en status=revoked, heartbeat rejeté en 403
```

### Via l'UI SOC

`Host Agents` → bouton **Enroller** (à venir, sinon API). Voir `HostAgentsPage.jsx` pour l'état.

---

## 4. Installer — Windows Server / Windows 11

> Réponse à la question installation : vous avez un lab mix (serveur variable, agents Windows 10/11 + Windows Server). Les commandes ci-dessous sont valables pour tous. **Ne remplacez pas `192.168.1.x` par `localhost`**.

### 4.1 Préparer la config

Sur le **PC agent** (ex: `pc-bureau-01`) :

```powershell
git clone https://github.com/saif-infinity/projet-soc-ips-siem-xdr-.git
cd projet-soc-ips-siem-xdr-\agent
copy config.example.json config.json
notepad config.json
# Éditer:
#  "server_url": "http://192.168.1.50:8001"   # IP LAN du SERVEUR
#  "agent_id": "pc-bureau-01"
#  "token": "sb_...du-enroll..."
#  "verify_tls": false   # si http:// lab, mettre false pour éviter warning TLS
```

### 4.2 Vérifier avant service

```powershell
pip install -r requirements.txt
python -m sentinel_agent --check
# Doit afficher "Register OK" + "Heartbeat OK". Sinon voir §6.
```

### 4.3 Installer comme service

**Option A — NSSM (recommandé, vrai service Windows)**

```powershell
# Télécharger NSSM https://nssm.cc/download -> nssm.exe dans PATH
powershell -ExecutionPolicy Bypass -File sentinel_agent\service\install_windows.ps1
# Vérifier
nssm status SentinelAgent
Get-Content .\data\queue.jsonl  # file bornée
```

**Option B — Task Scheduler (fallback, sans NSSM)**

Le même script détecte l'absence de NSSM et crée une tâche planifiée au démarrage (`SYSTEM`).

**Logs :** `data\queue.jsonl` (file locale), `Event Viewer` ou console. Arrêt : `nssm stop SentinelAgent` ou Task Scheduler.

**Désinstaller (Admin PowerShell)**

```powershell
powershell -ExecutionPolicy Bypass -File sentinel_agent\service\uninstall_windows.ps1
```

### 4.4 Pare-feu Windows (serveur)

Sur le **PC serveur** (celui qui héberge `uvicorn :8001`) :

```powershell
# En Admin PowerShell sur le SERVEUR:
netsh advfirewall firewall add rule name="Sentinel SOC 8001" dir=in action=allow protocol=TCP localport=8001 profile=private
# Vérifier
netsh advfirewall firewall show rule name="Sentinel SOC 8001"
# Alternative GUI: pare-feu Windows → Règles de trafic entrant → nouvelle règle TCP 8001
```

Si les deux `Frontend` Vite tournent aussi sur le serveur et que vous voulez y accéder depuis le LAN, ajoutez 5173/5174 mais **pas nécessaire pour les agents** (agents ne parlent qu'au backend).

---

## 5. Installer — Linux (si présent)

Vous avez indiqué "pas de Linux pour l'instant", mais pour complétude (future VM ou serveur Linux) :

```bash
# Sur le PC agent Linux:
git clone https://github.com/... && cd projet-soc-ips-siem-xdr-/agent
cp config.example.json config.json && nano config.json
# server_url = http://192.168.1.50:8001

pip install -r requirements.txt
python -m sentinel_agent --check

# Service systemd:
sudo ./sentinel_agent/service/install_linux.sh
systemctl status sentinel-agent
journalctl -u sentinel-agent -f
# Désinstaller:
sudo ./sentinel_agent/service/uninstall_linux.sh
```

**Pare-feu Linux (serveur si Linux)**

```bash
# Debian/Ubuntu ufw
sudo ufw allow from 192.168.1.0/24 to any port 8001 proto tcp comment "Sentinel SOC"
sudo ufw status
# firewalld (Fedora/RHEL)
sudo firewall-cmd --permanent --add-port=8001/tcp --zone=internal
sudo firewall-cmd --reload
```

---

## 6. Vérifications & pare-feu

### Trouver l'IP LAN du serveur

```powershell
# Windows serveur:
ipconfig
# → IPv4 Address: 192.168.1.50  (pas 127.0.0.1, pas 169.254.x.x)
# Linux serveur:
ip addr show | grep 192.168
# Test depuis un agent:
ping 192.168.1.50
Test-NetConnection -ComputerName 192.168.1.50 -Port 8001  # Windows
curl http://192.168.1.50:8001/  # doit répondre {"detail": ...} ou 200
```

### Si `ping` OK mais `curl` KO (port 8001 refusé)

1. Vérifier que le backend écoute bien sur `0.0.0.0`, pas `127.0.0.1` :
   ```bash
   # Dans start.sh / commande uvicorn — utiliser --host 0.0.0.0 pour LAN
   uvicorn app.main:app --host 0.0.0.0 --port 8001
   # Conteneur Docker: ports: "8001:8001" expose déjà en 0.0.0.0
   ```
2. Vérifier le pare-feu serveur (voir ci-dessus `netsh`/`ufw`).
3. Tester depuis serveur lui-même `curl http://127.0.0.1:8001/` — si OK local mais pas LAN → c'est le pare-feu.
4. Vérifier `ALLOWED_ORIGINS` si frontend croisé, mais **pas nécessaire pour agents** (agents ne sont pas CORS).

### Vérifications de l'agent

```bash
python -m sentinel_agent --check          # connectivité + register + heartbeat
python -m sentinel_agent --once           # un batch puis quit (debug)

# Depuis le serveur, vérifier qu'il est vu:
curl -H "X-API-Key: $API_KEY" http://192.168.1.50:8001/api/agent/status | jq
# → agent_id, last_seen, last_ip, online=true
```

---

## 7. Wi-Fi invité / isolation client

Si votre box/point d'accès a **"Isolation client"**, **"AP isolation"** ou **"Wi-Fi invité"** activé :

- Deux clients sur le même SSID **ne peuvent pas communiquer** entre eux. Ping et TCP 8001 échouent même si le serveur est joignable depuis internet.
- Symptôme : `ping 192.168.1.50` → *Request timed out*, `curl` → *Connection timed out*, mais serveur ping internet OK.
- Solution :
  1. Passer le serveur et les agents sur le **réseau principal** (pas invité).
  2. Dans l'admin de la box (ex: 192.168.1.1), désactiver *Isolation AP* / *Client isolation* pour ce SSID.
  3. Alternative : brancher le serveur en **Ethernet** et ouvrir le Wi-Fi isolation uniquement pour invités, pas pour le subnet lab (VLAN si possible).
  4. Vérifier : depuis agent `arp -a` doit lister `192.168.1.50`.

> Note : c'est volontairement **non contourné** par l'agent — votre réseau reste sûr. Documentez le réglage de la box.

---

## 8. TLS / HTTP lab

### Recommandé en production : HTTPS

- Certificat valide (Let's Encrypt pour un domaine interne, ou CA d'entreprise).
- Agent: `server_url: "https://sentinel.local:8001"`, `verify_tls: true` (par défaut).
- Le code **conserve la vérification TLS** (`requests verify=True`).
- Si certificat self-signed en lab : ajoutez le CA dans le trust store OS, ou `verify_tls: "/chemin/ca.pem"`.

### Mode HTTP lab (votre choix actuel)

- `server_url: "http://192.168.1.50:8001"`, `verify_tls: false` ou `verify_tls: true` peu importe (HTTP ignore TLS).
- Documenté comme **"réservé au développement local"** : non chiffré, uniquement sur Wi-Fi de confiance.
- Ne pas exposer ce mode sur internet.

---

## 9. Pipeline → Investigation

Chaque telemetry batch suit :

```
agent telemetry (system_logs/auth/process/network) → AgentTelemetryEvent (DB)
  → _forward_to_pipeline (si host_agent enabled) → normalize_event(host-agent)
  → ingest_alert → dedup → Suricata/Wazuh pipeline identique → Alert
  → evaluate_normalized_alert (rules) → RuleMatchEvent → invest
```

- **Dédup** : `dedup_key = sha256(src_ip|dest_ip|signature)` fenêtre 60s, `suppress_after` 5. Serveur side.
- **Ack fiable** : agent envoie `seq=N`, serveur répond `ack_seq=N` ou `deduped=true`. L'agent purge sa `queue.jsonl` jusqu'à `ack_seq`.
- **File bornée** : `queue_max_events=5000`, `queue_max_bytes=20MB`, FIFO si plein.
- **MITRE** : dans chaque `Rule` (`mitre_attack_ids`, `tactics`), l'investigation collecte `step_mitre_context` → affiche `T1059: Command and Scripting Interpreter (execution)` mais **ne déclare pas auto-malveillant**.
- **Sans Internet** : pipeline + règles + scoring fonctionnent. TI est `fail-open` → `unknown` si offline.

### Voir dans l'UI

- `Host Agents` → agent → processus / événements / misconfigs
- `Investigations` → preuves (ti:src, host:wazuh, mitre:context), score 0-100, level, recommandations
- `Cases` → lien `CaseAlertLink` créé depuis investigation
- `Rules` → `coverage` MITRE

---

## 10. Enrichissement optionnel (AbuseIPDB / VT / Kaspersky)

Tous les appels partent **uniquement du serveur SOC** (jamais de l'agent).

| Fournisseur | Clé côté serveur | Cache | Quota |
|---|---|---|---|
| **AbuseIPDB** (défaut) | `threat_intel.api_key` / `THREAT_INTEL_API_KEY` | 1h (TTL `THREAT_INTEL_CACHE_TTL_SECONDS`) | 1000/j |
| **VirusTotal** | `threat_intel.virustotal_api_key` / `VIRUSTOTAL_API_KEY` | même cache (provider=virustotal) | 500/j |
| **Kaspersky** | `threat_intel.kaspersky_api_key` / `KASPERSKY_API_KEY` | provider=kaspersky | 500/j |

- Config via `Settings` → `Sources` → `Threat Intelligence` → `provider` select.
- **IP privées non requêtées** : `192.168.x.x`, `10.x`, `127.0.0.1`, `169.254.x` → `unknown` sans appel, log `debug`.
- **Clés jamais dans agent/dépôt** : stockées en `SystemConfig` chiffré ou env `VIRUSTOTAL_API_KEY`, `KASPERSKY_API_KEY`.
- **Résultats sourcés/datés** : `checked_at`, `from_cache`, `source_name`, `raw_json`, `provider`.
- **Absence → unknown, jamais clean** : `unknown` affiché "Inconnu — pas d'avis", pas "Sain".
- **Aucun envoi auto de fichiers/logs bruts** : seules les IPs sont requêtées.

---

## 11. Dépannage rapide

| Symptôme | Vérifier |
|---|---|
| `agent: Could not validate credentials` | Token expiré/révoqué ? `curl /api/agent/tokens?agent_id=...` sur serveur. Ré-enroller. |
| `Connection refused` | Serveur lance sur `0.0.0.0` ? pare-feu serveur `netsh`/`ufw` ? Voir §6. |
| `TLS verification failed` | `verify_tls: true` + `https://` mais certificat self-signed ? Passer `verify_tls: false` en HTTP lab ou installer CA. |
| `ping OK, curl timeout` | Wi-Fi isolation / Guest (voir §7). |
| Agent `online=false` | `heartbeat_interval` 90s ? Vérifier `last_seen` via `curl /api/agent/status`. Agent en veille ? |
| `queue.jsonl` grossit | Serveur down longtemps ? File bornée purgera en FIFO (5000). Remettre serveur en ligne → queue se vide. |
| Pas d'investigation créée | `host_agent` enabled ? règle avec `mitre_attack_ids` + `severity>=min_severity` ? Voir `Settings → Investigation`. |
| TI toujours `unknown` | `THREAT_INTEL_ENABLED=true` ? clé configurée ? Tester `curl /api/intel/check?ip=8.8.8.8` (public). IP privée → normal d'être unknown. |

---

## Annexes

- Code agent : `agent/sentinel_agent/` (collectors, queue, client)
- Service : `agent/sentinel_agent/service/install_*.ps1/.sh`
- Modèle config : `agent/config.example.json`
- Tests : `agent/tests/` + `backend/tests/test_agent_*.py`

Avant installation finale, confirmez votre **IP LAN serveur** et vos besoins TI (AbuseIPDB gratuit suffit pour lab ? Besoin VT/Kaspersky ?).
