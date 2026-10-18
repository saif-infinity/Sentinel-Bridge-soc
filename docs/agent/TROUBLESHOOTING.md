# Dépannage réseau — lab Wi-Fi local

## Tester l'IP LAN du serveur (à faire avant d'installer l'agent)

```powershell
# Windows serveur:
ipconfig
# Cherchez "Adresse IPv4 . . . : 192.168.1.50" (pas 127.0.0.1)
# Linux serveur:
ip addr | grep 192.168
```

Depuis un PC agent :

```powershell
ping 192.168.1.50
Test-NetConnection 192.168.1.50 -Port 8001
curl http://192.168.1.50:8001/
```

## Vérifications pare-feu (Windows Server / 11)

### Serveur (ouvre inbound)

```powershell
netsh advfirewall firewall add rule name="Sentinel SOC 8001" dir=in action=allow protocol=TCP localport=8001 profile=private
netsh advfirewall firewall show rule name="Sentinel SOC 8001"
# GUI: wf.msc → Règles de trafic entrant → TCP 8001
```

### Diagnostic

```powershell
# Serveur écoute bien 0.0.0.0 ?
netstat -ano | findstr :8001
# Doit afficher 0.0.0.0:8001 LISTENING, pas 127.0.0.1:8001
# Si 127.0.0.1 → relancer backend avec:
uvicorn app.main:app --host 0.0.0.0 --port 8001  # ou start.sh --lan

# Test local serveur:
curl http://127.0.0.1:8001/api/agent/status -H "X-API-Key: $API_KEY"

# Test depuis agent:
curl http://192.168.1.50:8001/ --verbose
```

## Wi-Fi invité / isolation client (AP isolation)

Symptôme : ping OK vers internet, ping KO vers serveur local, curl timeout.

```
# Depuis agent:
arp -a
# Si 192.168.1.50 absent, isolation active.
```

Solutions :

1. Passer serveur + agents sur **SSID principal** (pas invité).
2. Box admin (ex: 192.168.1.1) → désactiver `Isolation client` / `AP isolation` / `Client isolation`.
3. Serveur en **Ethernet** si possible.
4. Ne pas contourner par tunnel public (exigence lab non exposé).

## TLS / HTTP lab

- `http://` → `verify_tls: false` (lab local non chiffré, Wi-Fi de confiance).
- `https://` self-signed → ajouter CA: `verify_tls: "C:/chemin/ca.pem"` ou installer CA système.
- Vérif conservée si `https://` (code `requests verify=True`).

## PostgreSQL / Redis

Ils restent sur `127.0.0.1:5432/6379` (docker-compose). Agents n'y accèdent jamais. Seul `8001` exposé.

## Commandes rapides agent

```bash
python -m sentinel_agent --check   # connectivité + register + heartbeat
python -m sentinel_agent --once    # un batch
type data\queue.jsonl              # file locale bornée
```
