"""Scénarios intégrés et chargement de scénarios personnalisés.

Les adresses IP utilisées par les générateurs appartiennent aux plages de
documentation RFC 5737 (``192.0.2.0/24``, ``198.51.100.0/24``,
``203.0.113.0/24``) et aux plages privées : aucun événement ne désigne un
système réel sur Internet.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import re
import string
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .events import SEVERITIES, GenContext, Scenario

DOC_SOURCES = ("198.51.100.23", "198.51.100.47", "203.0.113.19", "203.0.113.88")
USERS = ("root", "admin", "svc_backup", "ubuntu", "oracle")
SCAN_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
    3306, 3389, 5432, 6379, 8080, 8443, 9200,
)

WEB_PAYLOADS: tuple[tuple[str, str, str, int, str], ...] = (
    ("/login", "POST", "username=admin' OR '1'='1", 403, "high"),
    ("/search", "GET", "q=<script>alert(document.cookie)</script>", 403, "medium"),
    ("/download", "GET", "file=../../../../etc/passwd", 403, "high"),
    ("/api/v1/users", "GET", "id=1 UNION SELECT username,password FROM users", 500, "critical"),
    ("/admin", "POST", "cmd=whoami; id; uname -a", 401, "critical"),
)

FIM_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/etc/passwd", "file_modified", "high"),
    ("/etc/shadow", "file_modified", "critical"),
    ("/root/.ssh/authorized_keys", "file_created", "critical"),
    ("/var/www/html/index.php", "file_modified", "high"),
    ("/etc/cron.d/backup", "file_created", "high"),
)

CUSTOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,40}$")
SPEC_KEYS = {
    "category", "action", "outcome", "severity", "host", "user", "src_ip",
    "src_port", "dst_ip", "dst_port", "protocol", "message", "mitre", "tags",
    "details", "count",
}
PLACEHOLDERS = {
    "index", "scenario", "host", "user", "src_ip", "dst_ip", "dst_port",
    "category", "action", "outcome", "severity",
}


def _doc_ip(rng, *, subnet: int = 100) -> str:
    prefix = ("198.51", "203.0")[rng.randrange(2)]
    return f"{prefix}.{subnet}.{rng.randint(2, 250)}"


def _digest(rng) -> str:
    return hashlib.sha256(rng.randbytes(16)).hexdigest()


def _auth_bruteforce(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    attacker = ctx.rng.choice(DOC_SOURCES)
    for index in range(ctx.count):
        success = ctx.count > 1 and index == ctx.count - 1
        user = ctx.rng.choice(USERS)
        source_port = ctx.rng.randint(40000, 60000)
        spec: dict[str, Any] = {
            "category": "authentication",
            "action": "ssh_login",
            "outcome": "success" if success else "failure",
            "severity": "high" if success else "medium",
            "host": "bastion-01.lab.local",
            "user": user,
            "src_ip": attacker,
            "src_port": source_port,
            "dst_port": 22,
            "protocol": "ssh",
            "mitre": ["T1110", "T1078"] if success else ["T1110"],
            "tags": ["ssh", "brute-force", "identity"],
            "details": {
                "attempt": index + 1,
                "attempts_in_window": ctx.count,
                "auth_method": "password",
            },
        }
        if success:
            spec["message"] = (
                f"Accepted password for {user} from {attacker} port {source_port} ssh2"
            )
        else:
            spec["message"] = (
                f"Failed password for {user} from {attacker} port {source_port} ssh2"
            )
        events.append(spec)
    return events


def _port_scan(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    attacker = ctx.rng.choice(DOC_SOURCES)
    for index in range(ctx.count):
        port = SCAN_PORTS[index % len(SCAN_PORTS)]
        opened = ctx.rng.random() < 0.08
        events.append(
            {
                "category": "network",
                "action": "connection_attempt",
                "outcome": "open" if opened else "denied",
                "severity": "medium" if opened else "low",
                "host": "fw-edge-01.lab.local",
                "src_ip": attacker,
                "src_port": ctx.rng.randint(40000, 60000),
                "dst_ip": "10.20.30.10",
                "dst_port": port,
                "protocol": "tcp",
                "mitre": ["T1046"],
                "tags": ["firewall", "reconnaissance", "port-scan"],
                "details": {"scan_index": index, "ports_in_run": ctx.count},
                "message": (
                    f"{'Observed' if opened else 'Blocked'} TCP connection from {attacker} "
                    f"to 10.20.30.10:{port}"
                ),
            }
        )
    return events


def _web_attack(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    user_agents = ("sqlmap/1.8.7", "Mozilla/5.0 (X11; Linux x86_64)", "Nikto/2.5.0")
    for index in range(ctx.count):
        path, method, payload, status, severity = WEB_PAYLOADS[index % len(WEB_PAYLOADS)]
        agent = user_agents[index % len(user_agents)]
        events.append(
            {
                "category": "web",
                "action": "http_request",
                "outcome": "blocked" if status in {401, 403} else "allowed",
                "severity": severity,
                "host": "web-01.lab.local",
                "src_ip": _doc_ip(ctx.rng),
                "src_port": ctx.rng.randint(40000, 60000),
                "dst_ip": "10.20.30.40",
                "dst_port": 443,
                "protocol": "https",
                "mitre": ["T1190"],
                "tags": ["waf", "http", "injection"],
                "details": {
                    "http_method": method,
                    "url": path,
                    "http_status": status,
                    "payload": payload,
                    "user_agent": agent,
                },
                "message": (
                    f"{method} {path} HTTP/1.1 {status} "
                    f'— payload: {payload} — UA: {agent}'
                ),
            }
        )
    return events


def _dns_tunnel(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for _ in range(ctx.count):
        payload = base64.b32encode(ctx.rng.randbytes(ctx.rng.randint(18, 30)))
        label = payload.decode("ascii").rstrip("=").lower()
        query = f"{label}.exfil.example"
        events.append(
            {
                "category": "network",
                "action": "dns_query",
                "outcome": "allowed",
                "severity": "high",
                "host": "ws-042.lab.local",
                "user": "j.doe",
                "src_ip": "10.20.30.77",
                "dst_ip": "10.20.0.53",
                "dst_port": 53,
                "protocol": "dns",
                "mitre": ["T1071.004"],
                "tags": ["dns", "exfiltration", "c2"],
                "details": {
                    "qtype": "TXT",
                    "query_name": query,
                    "label_length": len(label),
                },
                "message": f"DNS query TXT {query} (label length {len(label)})",
            }
        )
    return events


def _beacon(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for _ in range(ctx.count):
        jitter = ctx.rng.randint(5, 25)
        bytes_out = ctx.rng.randint(1200, 4800)
        events.append(
            {
                "category": "network",
                "action": "outbound_connection",
                "outcome": "success",
                "severity": "medium",
                "host": "ws-042.lab.local",
                "user": "j.doe",
                "src_ip": "10.20.30.77",
                "src_port": ctx.rng.randint(40000, 60000),
                "dst_ip": "198.51.100.66",
                "dst_port": 443,
                "protocol": "tls",
                "mitre": ["T1071.001"],
                "tags": ["c2", "beacon", "tls"],
                "details": {
                    "destination_domain": "cdn-sync.example",
                    "jitter_seconds": jitter,
                    "bytes_out": bytes_out,
                    "nominal_interval_seconds": 60,
                },
                "message": (
                    "Periodic TLS session to cdn-sync.example:443 "
                    f"(~60s ± {jitter}s, bytes_out={bytes_out})"
                ),
            }
        )
    return events


def _file_integrity(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index in range(ctx.count):
        path, action, severity = FIM_PATHS[index % len(FIM_PATHS)]
        before = _digest(ctx.rng)
        after = _digest(ctx.rng)
        verb = {
            "file_modified": "modified",
            "file_created": "created",
            "file_deleted": "deleted",
        }[action]
        events.append(
            {
                "category": "endpoint",
                "action": action,
                "outcome": "detected",
                "severity": severity,
                "host": "srv-app-01.lab.local",
                "user": "www-data",
                "mitre": ["T1565.001"],
                "tags": ["fim", "integrity", "linux"],
                "details": {
                    "file_path": path,
                    "sha256_before": before,
                    "sha256_after": after,
                },
                "message": (
                    f"FIM: {path} {verb} (sha256 {before[:12]}… → {after[:12]}…)"
                ),
            }
        )
    return events


def _credential_dump(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    processes = ("powershell.exe", "rundll32.exe", "procdump.exe")
    for index in range(ctx.count):
        process = processes[index % len(processes)]
        command = (
            f"{process} -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAp"
            if process == "powershell.exe"
            else f"{process} /accepteula -ma lsass.exe C:\\Temp\\out.dmp"
        )
        events.append(
            {
                "category": "endpoint",
                "action": "process_access",
                "outcome": "detected",
                "severity": "critical",
                "host": "win-dc-01.lab.local",
                "user": "CORP\\svc_sql",
                "mitre": ["T1003.001"],
                "tags": ["windows", "credential-access", "lsass", "edr"],
                "details": {
                    "process": process,
                    "target_process": "lsass.exe",
                    "command_line": command,
                    "access_rights": "0x1010",
                },
                "message": (
                    f"Suspicious process access to lsass.exe by {process} "
                    "(requested read memory)"
                ),
            }
        )
    return events


def _data_exfil(ctx: GenContext) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for _ in range(ctx.count):
        megabytes = ctx.rng.randint(40, 900)
        duration = ctx.rng.randint(30, 600)
        destination = ctx.rng.choice(("203.0.113.200", "198.51.100.90"))
        events.append(
            {
                "category": "network",
                "action": "outbound_transfer",
                "outcome": "success",
                "severity": "critical",
                "host": "db-01.lab.local",
                "user": "svc_db",
                "src_ip": "10.20.30.55",
                "src_port": ctx.rng.randint(40000, 60000),
                "dst_ip": destination,
                "dst_port": 443,
                "protocol": "tls",
                "mitre": ["T1041"],
                "tags": ["exfiltration", "dlp", "tls"],
                "details": {
                    "destination_domain": "drop.example",
                    "bytes_out": megabytes * 1024 * 1024,
                    "duration_seconds": duration,
                },
                "message": (
                    f"Outbound TLS transfer of {megabytes} MB to {destination}:443 "
                    f"over {duration}s"
                ),
            }
        )
    return events


SCENARIOS: dict[str, Scenario] = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            name="auth-bruteforce",
            title="Force brute SSH puis connexion réussie",
            description=(
                "N échecs d'authentification SSH depuis une même source, suivis "
                "d'une connexion acceptée : idéal pour tester la corrélation et "
                "les règles de seuil."
            ),
            mitre=("T1110", "T1078"),
            default_host="bastion-01.lab.local",
            default_interval=4.0,
            generate=_auth_bruteforce,
        ),
        Scenario(
            name="port-scan",
            title="Balayage de ports depuis une source externe",
            description=(
                "Tentatives de connexion TCP échelonnées sur les ports les plus "
                "courants, avec quelques ports observés ouverts."
            ),
            mitre=("T1046",),
            default_host="fw-edge-01.lab.local",
            default_interval=0.5,
            generate=_port_scan,
        ),
        Scenario(
            name="web-attack",
            title="Attaques web : SQLi, XSS, traversée, injection",
            description=(
                "Requêtes HTTP malveillantes variées avec codes 401/403/500, "
                "agents sqlmap/Nikto et charges utiles reconnaissables."
            ),
            mitre=("T1190",),
            default_host="web-01.lab.local",
            default_interval=2.0,
            generate=_web_attack,
        ),
        Scenario(
            name="dns-tunnel",
            title="Tunnel DNS : requêtes TXT longues et encodées",
            description=(
                "Rafale de requêtes DNS TXT vers des sous-domaines aléatoires "
                "longs, typique d'un canal d'exfiltration ou de C2."
            ),
            mitre=("T1071.004",),
            default_host="ws-042.lab.local",
            default_interval=0.8,
            generate=_dns_tunnel,
        ),
        Scenario(
            name="beacon",
            title="Balise C2 périodique avec jitter",
            description=(
                "Connexions TLS sortantes régulières vers un domaine de C2 "
                "simulé, avec gigue et volume constant."
            ),
            mitre=("T1071.001",),
            default_host="ws-042.lab.local",
            default_interval=60.0,
            generate=_beacon,
        ),
        Scenario(
            name="file-integrity",
            title="Modifications de fichiers sensibles (FIM)",
            description=(
                "Créations et modifications sur /etc/passwd, /etc/shadow, clés "
                "SSH et cron, avec empreintes avant/après."
            ),
            mitre=("T1565.001",),
            default_host="srv-app-01.lab.local",
            default_interval=20.0,
            generate=_file_integrity,
        ),
        Scenario(
            name="credential-dump",
            title="Accès suspect à lsass.exe (dump de credentials)",
            description=(
                "Accès mémoire à lsass.exe par PowerShell, rundll32 ou procdump, "
                "avec lignes de commande suspectes."
            ),
            mitre=("T1003.001",),
            default_host="win-dc-01.lab.local",
            default_interval=8.0,
            generate=_credential_dump,
        ),
        Scenario(
            name="data-exfil",
            title="Exfiltration volumineuse vers Internet",
            description=(
                "Transferts TLS sortants de plusieurs dizaines à plusieurs "
                "centaines de Mo vers une destination de documentation."
            ),
            mitre=("T1041",),
            default_host="db-01.lab.local",
            default_interval=5.0,
            generate=_data_exfil,
        ),
    )
}


def get_scenario(name: str) -> Scenario:
    """Retourne un scénario intégré ou lève une erreur explicite."""

    try:
        return SCENARIOS[name]
    except KeyError:
        close = difflib.get_close_matches(name, SCENARIOS, n=3)
        if close:
            hint = f"Vouliez-vous dire : {', '.join(close)} ?"
        else:
            hint = f"Disponibles : {', '.join(sorted(SCENARIOS))}"
        raise ValueError(f"scénario inconnu « {name} ». {hint}") from None


def _placeholders(message: str) -> set[str]:
    try:
        parsed = list(string.Formatter().parse(message))
    except ValueError as exc:
        raise ValueError(f"accolades invalides dans le message : {message!r}") from exc
    return {field for _, field, _, _ in parsed if field}


def _check_spec(spec: Mapping[str, Any], origin: str) -> None:
    unknown = set(spec) - SPEC_KEYS
    if unknown:
        raise ValueError(
            f"champ(s) inconnu(s) dans {origin} : {', '.join(sorted(unknown))}"
        )
    if not isinstance(spec.get("message", ""), str):
        raise ValueError(f"« message » doit être une chaîne dans {origin}")
    for key in ("mitre", "tags"):
        value = spec.get(key)
        if value is not None and not isinstance(value, list):
            raise ValueError(f"« {key} » doit être une liste dans {origin}")
        if value is not None and not all(isinstance(item, str) for item in value):
            raise ValueError(f"« {key} » ne doit contenir que des chaînes dans {origin}")
    if "details" in spec and not isinstance(spec["details"], dict):
        raise ValueError(f"« details » doit être un objet JSON dans {origin}")


def load_custom_scenario(path: str | Path) -> Scenario:
    """Charge un scénario JSON personnalisé.

    Les événements de ``events`` sont répétés en boucle jusqu'à atteindre le
    nombre demandé sur la ligne de commande.
    """

    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"fichier de scénario introuvable : {source}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source} : JSON invalide ({exc.msg}, ligne {exc.lineno})") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{source} : la racine doit être un objet JSON")
    allowed_top = {
        "name", "title", "description", "mitre", "default_host",
        "default_interval", "defaults", "events",
    }
    unknown = set(data) - allowed_top
    if unknown:
        raise ValueError(
            f"{source} : champ(s) de premier niveau inconnu(s) : "
            f"{', '.join(sorted(unknown))}"
        )

    name = str(data.get("name", "")).strip()
    if not CUSTOM_NAME_RE.match(name):
        raise ValueError(
            f"{source} : « name » doit correspondre à {CUSTOM_NAME_RE.pattern}"
        )
    title = str(data.get("title") or name)
    description = str(data.get("description") or title)

    raw_events = data.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise ValueError(f"{source} : « events » doit être une liste non vide")

    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError(f"{source} : « defaults » doit être un objet JSON")
    if set(defaults) - (SPEC_KEYS - {"count"}):
        unknown = set(defaults) - (SPEC_KEYS - {"count"})
        raise ValueError(
            f"{source} : champ(s) inconnu(s) dans defaults : {', '.join(sorted(unknown))}"
        )
    if "details" in defaults and not isinstance(defaults["details"], dict):
        raise ValueError(f"{source} : « details » doit être un objet JSON")

    cycle: list[dict[str, Any]] = []
    for position, raw in enumerate(raw_events, start=1):
        origin = f"{source} (events[{position}])"
        if not isinstance(raw, dict):
            raise ValueError(f"{origin} : chaque événement doit être un objet JSON")
        _check_spec(raw, origin)
        if not raw.get("message"):
            raise ValueError(f"{origin} : « message » est obligatoire")
        for field_name in _placeholders(str(raw["message"])):
            if field_name not in PLACEHOLDERS:
                raise ValueError(
                    f"{origin} : placeholder inconnu « {{{field_name}}} » ; "
                    f"autorisés : {', '.join(sorted(PLACEHOLDERS))}"
                )
        count = raw.get("count", 1)
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise ValueError(f"{origin} : « count » doit être un entier >= 1")
        template = {key: value for key, value in raw.items() if key != "count"}
        merged_template = {**defaults, **template}
        for required in ("category", "action"):
            if not merged_template.get(required):
                raise ValueError(
                    f"{origin} : « {required} » est obligatoire (dans l'événement "
                    "ou dans defaults)"
                )
        severity = merged_template.get("severity")
        if severity is not None and severity not in SEVERITIES:
            raise ValueError(
                f"{origin} : gravité invalide {severity!r} ; attendu "
                f"{', '.join(SEVERITIES)}"
            )
        cycle.extend(dict(template) for _ in range(count))

    if len(cycle) > 10_000:
        raise ValueError(f"{source} : le cycle dépasse 10 000 événements")

    raw_mitre = data.get("mitre", [])
    if not isinstance(raw_mitre, list) or not all(
        isinstance(item, str) for item in raw_mitre
    ):
        raise ValueError(f"{source} : « mitre » doit être une liste de chaînes")
    default_host = str(data.get("default_host") or "lab-01.lab.local")
    default_interval = float(data.get("default_interval", 2.0))
    if default_interval < 0:
        raise ValueError(f"{source} : « default_interval » doit être positif")

    def generate(context: GenContext) -> list[dict[str, Any]]:
        generated: list[dict[str, Any]] = []
        for index in range(context.count):
            template = dict(cycle[index % len(cycle)])
            merged = {**defaults, **template}
            values: dict[str, Any] = defaultdict(str)
            values.update(merged)
            values["index"] = index + 1
            values["scenario"] = name
            if not values.get("host"):
                values["host"] = context.host
            spec = dict(merged)
            spec["message"] = str(merged["message"]).format_map(values)
            generated.append(spec)
        return generated

    return Scenario(
        name=name,
        title=title,
        description=description,
        mitre=tuple(str(item) for item in raw_mitre),
        default_host=default_host,
        default_interval=default_interval,
        generate=generate,
    )


__all__ = ["SCENARIOS", "get_scenario", "load_custom_scenario"]
