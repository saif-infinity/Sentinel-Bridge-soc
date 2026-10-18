# Sentinel Bridge Agent — Windows / Linux (Lab local)

Agent Python léger pour envoyer les événements du PC au serveur SOC sur le Wi-Fi local.

## Principes
- **Un agent = une identité** : `agent_id` unique + token révocable (enroll via API SOC). Pas de scan automatique des autres machines.
- **Adresse serveur = IP LAN** du PC serveur (ex: `http://192.168.1.50:8001`), pas `localhost`.
- **Collecte volontaire** : vous installez l'agent uniquement sur vos PCs. Configurable : journaux système, auth, processus, connexions réseau.
- **Envoi par lots, file bornée** : `queue.jsonl` max 5000 événements / 20 MB, reprise après coupure, `seq` monotone + `ack_seq` serveur.
- **HTTP lab** : par défaut `verify_tls=true` si `https://`, documenté `verify_tls=false` uniquement en développement.
- **Pas de Postgres/Redis exposé** : seul `/api/agent/*` du backend est joignable.

## Démarrage rapide (après enroll)

```bash
# 1. Enroller depuis le serveur (admin) :
curl -H "X-API-Key: $API_KEY" -H "X-Tenant-ID: default" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"pc-bureau-01","label":"PC Bureau Windows"}' \
  http://192.168.1.50:8001/api/agent/enroll

# Réponse: {"token":"sb_..."} — copier ce token.

# 2. Configurer l'agent :
cp config.example.json config.json
# éditer server_url, agent_id, token

# 3. Installer & lancer :
# Windows (PowerShell admin)
.\sentinel_agent\service\install_windows.ps1
# Linux (systemd)
sudo ./sentinel_agent/service/install_linux.sh

# 4. Vérifier connectivité :
python -m sentinel_agent --check
```

Voir `docs/agent/README.md` pour les détails complets (pare-feu, isolation Wi-Fi invitée, TLS).
