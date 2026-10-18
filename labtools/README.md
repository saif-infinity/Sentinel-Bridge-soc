# LabTools — test-tools-collecter

**Boîte à outils de laboratoire pour la collecte et les tests SOC.**
Scénarios d'événements réalistes, envoi HTTP vers un collecteur, sondes réseau
bornées et inventaire commenté d'outils : tout tient dans une CLI Python sans
dépendance d'exécution.

[![CI](https://github.com/saif-infinity/test-tools-collecter/actions/workflows/ci.yml/badge.svg)](https://github.com/saif-infinity/test-tools-collecter/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%86%92%203.13-3776ab?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-0f766e?style=flat-square)](LICENSE)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances%20d'ex%C3%A9cution-aucune-0f766e?style=flat-square)

> [!NOTE]
> **Emplacement de publication.** Ce projet vit dans `labtools/` du dépôt
> [projet-soc-ips-siem-xdr-](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-)
> en attendant l'ouverture du dépôt dédié
> `test-tools-collecter`. Le workflow `labtools/.github/workflows/ci.yml` est
> conservé pour l'extraction : GitHub n'exécute que les workflows situés à la
> racine d'un dépôt.

> [!WARNING]
> **Périmètre de laboratoire uniquement.**
> LabTools génère des événements synthétiques et sonde des ports. N'utilisez
> `probe`, `scan` et `send` que sur des systèmes dont vous êtes propriétaire ou
> pour lesquels vous disposez d'une autorisation écrite. Les garde-fous refusent
> par défaut toute cible publique, mais ils ne remplacent ni une autorisation ni
> votre jugement.

---

## Sommaire

- [Ce que fait le dépôt](#ce-que-fait-le-dépôt)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Scénarios intégrés](#scénarios-intégrés)
- [Formats de sortie](#formats-de-sortie)
- [Intégration Sentinel Bridge](#intégration-sentinel-bridge)
- [Scénarios personnalisés](#scénarios-personnalisés)
- [Inventaire des outils](#inventaire-des-outils)
- [Garde-fous réseau](#garde-fous-réseau)
- [Architecture](#architecture)
- [Développement](#développement)
- [Limites et non-objectifs](#limites-et-non-objectifs)
- [Licence](#licence)

---

## Ce que fait le dépôt

| Commande | Rôle | Réseau |
|---|---|---|
| `labtools create` | Génère des événements déterministes en JSONL, CEF, syslog ou payload Sentinel | non |
| `labtools send` | Génère puis POSTe vers un collecteur HTTP, unitairement ou en lot | oui (HTTP) |
| `labtools probe` | Teste un port TCP unique (aucune donnée applicative envoyée) | oui (TCP) |
| `labtools scan` | Balaye une liste bornée de ports TCP en parallèle | oui (TCP) |
| `labtools list` | Liste les scénarios intégrés | non |
| `labtools validate` | Valide un scénario JSON personnalisé | non |
| `labtools catalog` | Recherche dans l'inventaire d'outils du laboratoire | non |

Garanties de conception :

- **Zéro dépendance d'exécution** : uniquement la bibliothèque standard
  (Python ≥ 3.10) ;
- **Déterministe** : à graine, date de début et intervalle égaux, deux
  générations produisent exactement les mêmes événements et identifiants ;
- **Non destructif** : aucune exploitation, aucune charge applicative, aucun
  paquet forgé ; les sondes ouvrent puis referment une connexion TCP ;
- **Adresses de documentation** : les IP des scénarios appartiennent aux plages
  RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) et aux plages
  privées, jamais à un système réel ;
- **Garde-fous** : cibles publiques refusées par défaut (voir
  [Garde-fous réseau](#garde-fous-réseau)).

## Installation

Prérequis : Python **3.10 ou plus récent**, `pip` et `git`.

```bash
git clone https://github.com/saif-infinity/test-tools-collecter.git
cd test-tools-collecter

python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -e .

labtools --version               # labtools 0.1.0
```

Sans installation, depuis la racine du dépôt :

```bash
PYTHONPATH=src python3 -m labtools.cli --help
```

Pour le développement (tests + linter) :

```bash
pip install -e ".[dev]"
```

## Démarrage rapide

### 1. Générer des événements

```bash
labtools create -s auth-bruteforce -n 2 --start 2026-01-01T00:00:00Z
```

```json
{"timestamp": "2026-01-01T00:00:00.000Z", "event_id": "6fbe39f8-3d32-565c-a6ff-f6be969ee3fe", "scenario": "auth-bruteforce", "category": "authentication", "action": "ssh_login", "outcome": "failure", "severity": "medium", "host": "bastion-01.lab.local", "message": "Failed password for root from 198.51.100.23 port 49012 ssh2", "source": "labtools", "user": "root", "src_ip": "198.51.100.23", "src_port": 49012, "dst_ip": null, "dst_port": 22, "protocol": "ssh", "mitre": ["T1110"], "tags": ["auth-bruteforce", "ssh", "brute-force", "identity"], "details": {"attempt": 1, "attempts_in_window": 2, "auth_method": "password"}}
{"timestamp": "2026-01-01T00:00:04.000Z", "event_id": "0bf6f28b-cd40-528d-b842-d83fa481965a", "scenario": "auth-bruteforce", "category": "authentication", "action": "ssh_login", "outcome": "success", "severity": "high", "host": "bastion-01.lab.local", "message": "Accepted password for admin from 198.51.100.23 port 47314 ssh2", "source": "labtools", "user": "admin", "src_ip": "198.51.100.23", "src_port": 47314, "dst_ip": null, "dst_port": 22, "protocol": "ssh", "mitre": ["T1110", "T1078"], "tags": ["auth-bruteforce", "ssh", "brute-force", "identity"], "details": {"attempt": 2, "attempts_in_window": 2, "auth_method": "password"}}
```

Écrire dans un fichier (le résumé part sur `stderr`, le contenu sur disque) :

```bash
labtools create -s web-attack -n 50 --interval 1 --format cef -o out/web.cef
```

### 2. Envoyer vers un collecteur

```bash
LABTOOLS_URL=http://localhost:8000/api/pipeline/ingest \
LABTOOLS_API_KEY=change-me \
labtools send -s dns-tunnel -n 20 --delay 0.2
```

Sortie :

```text
send : 20/20 (HTTP 200, 3 ms)
send : 20 événement(s) envoyé(s) vers http://localhost:8000/api/pipeline/ingest en 4.2 s
```

Options utiles :

| Option | Effet |
|---|---|
| `--batch` | Un seul POST contenant un tableau JSON (ou des lignes JSONL) |
| `--delay 0.5` | Pause entre deux envois unitaires |
| `--header "X-API-Key: …"` | En-tête HTTP additionnel, répétable |
| `--dry-run` | Affiche le premier corps et le nombre d'événements, sans réseau |
| `--timeout 5` | Délai d'attente HTTP en secondes |
| `--format jsonl` | POSTe l'événement brut au lieu du payload Sentinel |

`LABTOOLS_URL` et `LABTOOLS_API_KEY` évitent de répéter l'URL et la clé. Une clé
passée en ligne de commande reste visible dans l'historique du shell : préférez
les variables d'environnement.

### 3. Sonder un service

```bash
labtools probe lab-web.local:8080 --timeout 1
```

```text
lab-web.local:8080 : open — 1.2 ms
```

Le code de sortie vaut `0` si le port est ouvert, `1` sinon : utilisable dans un
script de vérification.

```bash
labtools scan 127.0.0.1 --ports 22,80,443,top --open-only
```

```text
HÔTE       PORT   ÉTAT        LATENCE
127.0.0.1  22     open        0.4 ms
127.0.0.1  80     closed      0.2 ms
…
1/39 port(s) ouvert(s) sur 127.0.0.1
```

### 4. Consulter l'inventaire

```bash
labtools catalog --search "windows evtx"
labtools catalog --id scapy
labtools catalog --category collecte --lab-safe
```

## Scénarios intégrés

`labtools list` affiche le catalogue ; chaque scénario possède un intervalle et
des techniques MITRE par défaut.

| Scénario | Ce qu'il simule | Intervalle | MITRE |
|---|---|---:|---|
| `auth-bruteforce` | Échecs SSH répétés puis connexion acceptée | 4 s | T1110, T1078 |
| `port-scan` | Balayage TCP avec quelques ports observés ouverts | 0,5 s | T1046 |
| `web-attack` | SQLi, XSS, traversée de répertoire, injection de commande | 2 s | T1190 |
| `dns-tunnel` | Requêtes TXT longues et encodées vers un domaine suspect | 0,8 s | T1071.004 |
| `beacon` | Sessions TLS périodiques vers un C2 simulé, avec jitter | 60 s | T1071.001 |
| `file-integrity` | Modifications de `/etc/passwd`, `/etc/shadow`, clés SSH, cron | 20 s | T1565.001 |
| `credential-dump` | Accès mémoire à `lsass.exe` (PowerShell, rundll32, procdump) | 8 s | T1003.001 |
| `data-exfil` | Transferts TLS sortants de plusieurs centaines de Mo | 5 s | T1041 |

Chaque événement contient `scenario`, `category`, `action`, `outcome`,
`severity` (`low`, `medium`, `high`, `critical`), `host`, `message`, `mitre`,
`tags`, `details` et un `event_id` UUID déterministe.

Options communes à `create` et `send` :

```text
-s/--scenario NOM        scénario intégré
--scenario-file FICHIER  scénario JSON personnalisé
-n/--count N             nombre d'événements (1 → 100000)
--seed N                 graine (défaut 42)
--host HÔTE              remplace l'hôte de tous les événements
--interval SECONDES      espacement des événements
--start ISO8601          début (défaut : maintenant)
```

## Formats de sortie

### `jsonl` (défaut)

Un objet JSON par ligne, champs stables et documentés ci-dessus. C'est le format
à privilégier pour un parseur maison ou un test de collecte.

### `cef` (ArcSight Common Event Format)

```text
CEF:0|LabTools|test-tools-collecter|0.1.0|dns-tunnel|dns_query|8|externalId=ffcb1e83-1b7a-5f2d-b66b-ae22f97b8e4c rt=1767225600000 cat=network dvchost=ws-042.lab.local src=10.20.30.77 dst=10.20.0.53 dpt=53 suser=j.doe proto=dns act=dns_query outcome=allowed msg=DNS query TXT p4yy…exfil.example (label length 45) cs1Label=MITRE cs1=T1071.004
```

### `syslog` (RFC 5424)

```text
<109>1 2026-01-01T00:00:00.000Z ws-042.lab.local labtools - beacon - category=network action=outbound_connection outcome=success src=10.20.30.77 dst=198.51.100.66 dpt=443 suser=j.doe proto=tls mitre=T1071.001 msg="Periodic TLS session to cdn-sync.example:443 (~60s ± 25s, bytes_out=1656)"
```

La facility est `audit` (13) et la priorité suit la gravité. LabTools *écrit*
du syslog ; il n'ouvre pas de socket syslog. Pour l'envoyer à un SIEM,
dirigez le fichier vers `rsyslog`, `vector` ou `fluent-bit`, ou utilisez `send`
vers son entrée HTTP.

### `sentinel` (payload `POST /api/pipeline/ingest`)

```json
{
  "source": "manual",
  "severity": 9,
  "signature": "web-attack:http_request",
  "description": "POST /login HTTP/1.1 403 — payload: username=admin' OR '1'='1 — UA: sqlmap/1.8.7",
  "category": "web",
  "raw": {"…": "événement complet"}
}
```

Correspondance des gravités : `low` → 3, `medium` → 6, `high` → 9,
`critical` → 12 sur l'échelle 0–15 du pipeline.

## Intégration Sentinel Bridge

LabTools a été conçu pour alimenter le pipeline du laboratoire
[Sentinel Bridge](https://github.com/saif-infinity/projet-soc-ips-siem-xdr-),
qui expose :

- `POST /api/pipeline/ingest` — authentification `X-API-Key` **ou** JWT ;
- `POST /api/suricata/webhook` et `POST /api/wazuh/webhook` — webhooks dédiés.

### Envoi typique

```bash
export LABTOOLS_URL=http://localhost:8000/api/pipeline/ingest
export LABTOOLS_API_KEY="la-clé-API-de-votre-.env"

labtools send -s credential-dump -n 5 --delay 1
labtools send -s data-exfil -n 3 --batch
```

Ordre de test conseillé pour un pipeline qui déduplique :

1. `labtools send -s port-scan -n 18` — bruit de reconnaissance ;
2. `labtools send -s auth-bruteforce -n 12` — force brute puis succès ;
3. `labtools send -s web-attack -n 8` — détections WAF ;
4. `labtools send -s dns-tunnel -n 30 --delay 0.5` — corrélation temporelle ;
5. `labtools send -s data-exfil -n 2` — gravité critique.

Le pipeline pouvant répondre `deduped` ou `suppressed`, un HTTP 200 ne garantit
pas la création d'une alerte : consultez `/api/pipeline/stats` pour vérifier
`received_total`, `deduped_total` et `emitted_total`.

### Vérifier la joignabilité avant d'envoyer

```bash
labtools probe localhost:8000
```

### Envoi vers un webhook Suricata/Wazuh

Le format `sentinel` n'est pas un `eve.json` : pour les webhooks dédiés,
utilisez `--format jsonl` et adaptez le corps côté collecteur, ou passez par
l'ingestion manuelle (`/api/pipeline/ingest`) qui reste le chemin le plus
simple pour des événements synthétiques.

## Scénarios personnalisés

Un fichier JSON décrit un scénario ; les événements sont répétés en boucle
jusqu'au nombre demandé. Voir [`examples/custom-scenario.json`](examples/custom-scenario.json).

```json
{
  "name": "custom-powershell",
  "title": "Exécution PowerShell encodée",
  "description": "Exemple de scénario personnalisé.",
  "mitre": ["T1059.001"],
  "default_host": "win-lab-01.lab.local",
  "default_interval": 15,
  "defaults": {
    "category": "endpoint",
    "action": "process_start",
    "outcome": "detected",
    "severity": "high",
    "user": "CORP\\labuser",
    "tags": ["powershell", "exemple"],
    "details": {"source": "sysmon", "event_id": 1}
  },
  "events": [
    {
      "message": "Encoded PowerShell command line (attempt {index}) on {host}",
      "tags": ["powershell", "obfuscation"],
      "count": 2
    },
    {
      "message": "PowerShell downloaded a script from 198.51.100.77",
      "severity": "critical"
    }
  ]
}
```

Règles de validation :

- `name` : minuscules, chiffres, `.`, `_` ou `-` (2 à 41 caractères) ; il
  identifie le scénario dans les tags et la sortie, et le fichier se charge avec
  `--scenario-file` ;
- `events` : liste non vide ; chaque événement exige `message` et, après fusion
  avec `defaults`, `category` et `action` ;
- `count` : entier ≥ 1 par événement, pour répéter un modèle dans le cycle
  (cycle maximal : 10 000 événements) ;
- placeholders autorisés dans `message` : `{index}`, `{scenario}`, `{host}`,
  `{user}`, `{src_ip}`, `{dst_ip}`, `{dst_port}`, `{category}`, `{action}`,
  `{outcome}`, `{severity}` ;
- champs inconnus, gravité hors `low|medium|high|critical`, tags non textuels et
  JSON invalide sont refusés avec un message précis.

```bash
labtools validate examples/custom-scenario.json
labtools create --scenario-file examples/custom-scenario.json -n 10
```

## Inventaire des outils

Le fichier [`src/labtools/data/inventory.json`](src/labtools/data/inventory.json)
recense 36 outils utilisables dans un laboratoire SOC/réseau, répartis en sept
catégories : `collecte`, `reseau`, `endpoint`, `detection`, `conteneurs`,
`charge`, `soc`.

Chaque fiche contient `id`, `name`, `category`, `purpose`, `homepage`,
`language`, `lab_safe`, `tags` et, le cas échéant, `caution`. `lab_safe: false`
signale un outil puissant (scan actif, C2, émulation d'adversaire) à réserver à
un périmètre explicitement autorisé.

```bash
labtools catalog                          # tout
labtools catalog --category reseau
labtools catalog --search "pcap rejeu"
labtools catalog --lab-safe --json
labtools catalog --id chainsaw
```

Un inventaire alternatif peut être fourni avec `--inventory chemin.json` ; les
identifiants dupliqués, champs manquants et JSON invalides sont rejetés.

## Garde-fous réseau

La politique s'applique à `probe`, `scan` et `send` :

| Cible | Sans option | `--allow-public` | `--allow-public --allow-many-ports` |
|---|---|---|---|
| Boucle locale / privée / lien-local | autorisé | autorisé | autorisé |
| Documentation RFC 5737 (`192.0.2.0/24`, …) | autorisé | autorisé | autorisé |
| Publique, ≤ 20 ports | **refusé** | autorisé | autorisé |
| Publique, > 20 ports | **refusé** | refusé | autorisé |
| Nom non résolvable | **refusé** | autorisé | autorisé |

- `LABTOOLS_ALLOW_PUBLIC=1` équivaut à `--allow-public` ;
- une URL contenant des identifiants (`http://user:motdepasse@…`) est refusée
  pour éviter qu'ils se retrouvent dans les journaux ;
- seules les URL `http` et `https` sont acceptées ;
- un envoi est limité à 8 Mio par requête.

Ces règles sont volontairement simples, testées, et **ne constituent pas une
autorisation** : vérifiez toujours le mandat qui couvre votre cible.

## Architecture

```text
test-tools-collecter/
├── src/labtools/
│   ├── cli.py            # argparse, sous-commandes, codes de sortie
│   ├── events.py         # modèle Event, gravités, horodatage, génération déterministe
│   ├── scenarios.py      # 8 scénarios intégrés + chargeur JSON personnalisé
│   ├── formats.py        # JSONL, CEF, syslog RFC 5424, payload Sentinel
│   ├── sender.py         # POST HTTP via urllib, lots, en-têtes, erreurs
│   ├── probes.py         # test de port, balayage borné, parseur de ports
│   ├── safety.py         # politique de ciblage et validation des URL
│   ├── catalog.py        # inventaire et recherche
│   └── data/inventory.json
├── examples/custom-scenario.json
├── tests/                # 167 tests (pytest)
├── pyproject.toml        # paquet, console script, ruff, pytest
├── Makefile              # test, lint, demo
└── .github/workflows/ci.yml
```

Le flux est linéaire : `scenario → événements → sérialisation → stdout/fichier
ou HTTP`. Aucun état partagé, aucun thread pour la génération ; seuls `scan` et
l'envoi HTTP exploitent des sockets.

## Développement

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

make test      # pytest
make lint      # ruff check
make demo      # affiche quelques événements et l'inventaire
```

Sans `make` :

```bash
pytest
ruff check .
```

La CI GitHub Actions exécute `ruff` et `pytest` sur Python 3.10 à 3.13 à chaque
_push_ et _pull request_ (`.github/workflows/ci.yml`).

Les contributions doivent rester dans le périmètre défensif du dépôt : pas de
charge d'exploitation, pas de contournement des garde-fous, pas de dépendance
d'exécution supplémentaire sans justification.

## Limites et non-objectifs

- **Ce n'est pas un outil offensif** : pas d'exploitation, pas de paquets
  forgés, pas de charge applicative, pas de fuzzing.
- **Pas de démon ni de planificateur** : la génération est ponctuelle ; utilisez
  `cron`, `systemd` ou votre orchestrateur pour des campagnes longues.
- **TCP uniquement** pour les sondes ; pas de scan UDP, ICMP ou de découverte
  de services par bannière.
- **Le format `sentinel` cible Sentinel Bridge** ; l'adaptation à un autre
  collecteur se fait via JSONL ou un scénario personnalisé.
- **Pas de gestion de secrets** : les clés viennent de l'environnement ou des
  en-têtes ; LabTools ne les stocke pas.
- Les adresses IP des scénarios sont fictives. Les similarités avec un système
  réel seraient fortuites.

## Licence

[MIT](LICENSE) — © 2026 saif-infinity.
