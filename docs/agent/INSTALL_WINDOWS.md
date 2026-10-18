# Installer l'agent — Windows 11 / Windows Server (lab local)

> **Avant cette page**, confirmez votre **IP LAN serveur** (voir `docs/agent/README.md` §6).  
> Ne remplacez jamais `192.168.1.50` par `localhost` sur un autre PC.

---

## 1. Copier l'agent

Sur le **PC agent** (Windows 11 ou Server) :

```powershell
git clone https://github.com/saif-infinity/projet-soc-ips-siem-xdr-.git
cd projet-soc-ips-siem-xdr-\agent
```

Si vous avez déjà le zip, extrayez `agent/` seul (pas besoin du backend).

---

## 2. Enroller depuis le serveur

Sur le **PC serveur** (celui qui héberge `backend:8001`) :

```powershell
# Depuis backend/.env
$API_KEY = (Get-Content backend\.env | Where-Object { $_ -match "^API_KEY=" } | ForEach-Object { ($_ -split "=",2)[1] }).Trim('"')
Invoke-RestMethod -Method Post -Uri "http://192.168.1.50:8001/api/agent/enroll" `
  -Headers @{ "X-API-Key"=$API_KEY; "X-Tenant-ID"="default"; "Content-Type"="application/json" } `
  -Body '{"agent_id":"pc-bureau-01","label":"PC Bureau Win11"}' | ConvertTo-Json

# Copiez "token": "sb_..." 
```

---

## 3. Configurer l'agent

Sur le **PC agent** :

```powershell
copy config.example.json config.json
notepad config.json
```

Éditez :

```json
{
  "server_url": "http://192.168.1.50:8001",
  "agent_id": "pc-bureau-01",
  "token": "sb_...",
  "tenant_id": "default",
  "verify_tls": false
}
```

- `server_url` = **IP LAN du serveur**, pas `127.0.0.1`.
- `verify_tls: false` car `http://` lab.

---

## 4. Tester sans installer

```powershell
pip install -r requirements.txt
python -m sentinel_agent --check
python -m sentinel_agent --once
```

Attendu :

```
✓ Register OK
✓ Heartbeat OK
```

---

## 5. Service (persistant)

### NSSM (recommandé)

```powershell
# https://nssm.cc/  → nssm.exe dans PATH
powershell -ExecutionPolicy Bypass -File sentinel_agent\service\install_windows.ps1
nssm status SentinelAgent
```

### Task Scheduler (fallback)

Si pas de NSSM, le même script crée une tâche planifiée `SentinelAgent` au démarrage (utilisateur `SYSTEM`).

---

## 6. Pare-feu / logs

- **Serveur** : `netsh advfirewall firewall add rule name="Sentinel SOC 8001" dir=in action=allow protocol=TCP localport=8001 profile=private`
- **Agent** : data dans `.\data\queue.jsonl` (bornée 5000 / 20MB)
- Arrêt : `nssm stop SentinelAgent`
- Désinstaller : `powershell -ExecutionPolicy Bypass -File sentinel_agent\service\uninstall_windows.ps1`

---

## 7. Vérifier côté SOC

```powershell
# Sur serveur:
curl -H "X-API-Key: $API_KEY" http://192.168.1.50:8001/api/agent/status
# Interface SOC: Host Agents → agent → Processus / Événements
```
