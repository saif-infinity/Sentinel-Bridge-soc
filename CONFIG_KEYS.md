# Clés de configuration — tout ce qu'il faut modifier / ajouter

> Source de vérité : `backend/app/core/config.py` (classe `Settings`, pydantic-settings).
> Les clés se définissent dans **`backend/.env`** (copier depuis `backend/.env.example`).
> 🔴 = obligatoire (le backend refuse de démarrer si absent) · 🟡 = nécessaire pour activer une fonctionnalité · ⚪ = optionnel.

---

## 1. Clés obligatoires 🔴

| Clé | Défaut | Où | À faire |
|-----|--------|-----|---------|
| `JWT_SECRET_KEY` | aucun | `.env` | Générer : `openssl rand -hex 32` |
| `API_KEY` | aucun | `.env` | Générer une clé aléatoire |
| `ADMIN_API_KEY` | aucun | `.env` | Clé API de l'admin-frontend (console de supervision) |
| `ADMIN_JWT_SECRET` | aucun | `.env` | JWT dédié admin-frontend (séparé de `JWT_SECRET_KEY`) |

> Défaut possible pour testes : `JWT_SECRET_KEY=dev`, `API_KEY=dev`, `ADMIN_API_KEY=admin`, `ADMIN_JWT_SECRET=admin-jwt` (utilisé en dev).

---

## 2. Clés à MODIFIER pour la prod 🟡

| Clé | Défaut actuel | Pourquoi modifier |
|-----|---------------|-------------------|
| `ENVIRONMENT` | `development` | Passer à `production` |
| `DATABASE_URL` | `postgresql+pg8000://postgres:saif@localhost:5432/postgres` | Credentials réels (le mot de passe `saif` est en clair) |
| `ALLOWED_ORIGINS` | localhost 5173/4173/3000 | Ajouter l'URL réelle de prod des 2 frontends |
| `REDIS_PASSWORD` | `""` | Mot de passe Redis si activé |
| `POSTGRES_PASSWORD` | `""` | Utilisé par `docker-compose.prod.yml` (variable `${POSTGRES_PASSWORD}`) |
| `WAZUH_PASS` | `change-me` | Mot de passe API Wazuh (`wazuh-wui`) |
| `WAZUH_INDEXER_PASS` | `change-me` | Mot de passe indexer OpenSearch |
| `SURICATA_PASS` | `change-me` | Mot de passe SSH Suricata |
| `WAZUH_SSH_PASS` | aucun (absent du `.env.example`) | Mot de passe SSH du conteneur Wazuh |
| `NOTIFICATION_ENCRYPTION_KEY` | `""` (fallback dérivé de JWT) | Clé Fernet pour chiffrer les configs de canaux : `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

---

## 3. Clés NOUVELLES à AJOUTER (fonctions ajoutées cette session) 🟡

### Threat Intelligence (enrichissement IoC auto dans le pipeline)

| Clé | Défaut | À faire |
|-----|--------|---------|
| `THREAT_INTEL_ENABLED` | `true` (config) — **mais `.env.example` dit encore `false`** | **Corriger le `.env.example` → `true`** (sinon l'enrichissement reste désactivé si l'utilisateur copie l'exemple) |
| `THREAT_INTEL_API_KEY` | `""` | **AJOUTER** — clé API AbuseIPDB (gratuite : https://www.abuseipdb.com/account/api). Sans elle → tous les lookups retournent `unknown` sans appel réseau |
| `THREAT_INTEL_PROVIDER` | `abuseipdb` | Changer si autre fournisseur |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | `3600` | OK par défaut |
| `THREAT_INTEL_TIMEOUT_SECONDS` | `10` | OK par défaut |

> Couplage pipeline : `app/application/pipeline.py` → `ingest_alert()` lit `settings.THREAT_INTEL_ENABLED` ; `app/infrastructure/threat_intel/client.py` lit le flag ET la clé API.

### Honeypot (service TCP) — ⚪ optionnel

| Clé | Défaut | À faire |
|-----|--------|---------|
| — | Ports codés en dur : `[23, 2323, 3389, 445]` | Compatible sans clé. **Recommandé** : ajouter `HONEYPOT_PORTS` comme variable dans `config.py` + `bootstrap.py` pour rendre les ports configurables sans toucher au code |

### Métrologie MTTD/MTTR

| Clé | Défaut | À faire |
|-----|--------|---------|
| — | aucune nouvelle clé | Rien à configurer — les métriques se calculent depuis Alert/Case/CaseAlertLink existants |

---

## 4. Clés du `.env.example` manquantes dans `config.py` — À AJOUTER dans le code (⚪ si besoin)

Ces clés sont référencées par la config Docker/scripts mais absentes de `backend/app/core/config.py` :

| Clé | Où | Usage |
|-----|-----|-------|
| `POSTGRES_USER` | docker-compose.prod.yml (`POSTGRES_USER: postgres` en dur) | Utilisateur Postgres |
| `POSTGRES_DB` | docker-compose.prod.yml (en dur) | Nom de la base |

---

## 5. Frontends

| Clé | Fichier | Valeur | Note |
|-----|---------|--------|------|
| `VITE_AUTOLOGIN` | `frontend/.env` | `1` = bypass login en dev, absent/`0` = login obligatoire | ⚠️ Ne jamais mettre `1` en prod |
| `API_BASE` | `frontend/src/lib/api.js:3` → `""` | Vide = proxy Vite | Le proxy Vite pointe vers le backend sur **:8001** (port 8000 = Coolify sur cette machine) |
| Base URL admin | `admin-frontend/src/api.js` | — | Vérifier qu'il pointe sur le backend :8001 |

---

## 6. Checklist de mise en route complète

```bash
cd backend
cp .env.example .env
# 1. 🔴 Générer les secrets
openssl rand -hex 32                  # -> JWT_SECRET_KEY
# 2. 🔴 Mettre ADMIN_API_KEY + ADMIN_JWT_SECRET (distincts)
# 3. 🟡 THREAT_INTEL_ENABLED=true (corriger .env.example aussi)
# 4. 🟡 THREAT_INTEL_API_KEY=<clé AbuseIPDB>  ← NOUVELLE clé essentielle
# 5. 🟡 DATABASE_URL / REDIS_PASSWORD selon l'infra réelle
# 6. 🟡 WAZUH_PASS, WAZUH_INDEXER_PASS, SURICATA_PASS, WAZUH_SSH_PASS
# 7. ⚪ NOTIFICATION_ENCRYPTION_KEY=Fernet
# 8. ⚪ STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET (billing)
# 9. ⚪ SUPER_ADMIN_API_KEY / SUPER_ADMIN_PASSWORD (console super admin)
./start.sh          # ou: make start (backend :8001 + 2 frontends)
```

---

## 7. Clés STRIPE / SUPER_ADMIN (fonctions déjà présentes, ⚪ optionnel)

| Clé | Défaut | Usage |
|-----|--------|-------|
| `STRIPE_SECRET_KEY` | `""` | Paiement (billing multi-tenant) |
| `STRIPE_WEBHOOK_SECRET` | `""` | Webhook Stripe |
| `SUPER_ADMIN_API_KEY` | `""` | Console super admin |
| `SUPER_ADMIN_PASSWORD` | `""` | Mot de passe super admin |

---

## Résumé — les 3 actions concrètes à faire maintenant

1. **`backend/.env`** : ajouter `THREAT_INTEL_API_KEY=<clé AbuseIPDB>` (fonction TI ajoutée)
2. **`backend/.env.example`** : corriger `THREAT_INTEL_ENABLED=false` → `true` (meilleur défaut = le comportement réel du code)
3. **Lancer** : `./start.sh` → vérifier `/api/reporting/metrics` et `/api/honeypot/status` (fonctions ajoutées)