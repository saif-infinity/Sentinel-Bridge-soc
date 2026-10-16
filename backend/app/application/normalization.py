"""R1 — Normalisation d'événements : mappers source → schéma canonique ECS-like.

Chaque mapper produit un dict canonique avec les clés :
  @timestamp, event.kind, event.category, event.type, src_ip, dest_ip,
  host {name, ip}, user {name}, description, severity, payload
(+ proto, agent_id, tenant_id pour le pipeline).

Contrat de tolérance : un champ absent → None (jamais d'exception sur un
payload inconnu). `to_pipeline_payload()` convertit le canonique vers le
payload attendu par `ingest_alert()` (pipeline.py).
"""
import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# Clés canoniques du schéma (contrat R1)
CANONICAL_KEYS = [
    "@timestamp", "event.kind", "event.category", "event.type",
    "src_ip", "dest_ip", "host", "user", "description", "severity",
    "payload", "proto", "agent_id", "tenant_id",
]


def _get(raw: Any, *paths: str) -> Any:
    """Lecture tolérante par chemins (dotted) : None si champ absent."""
    if not isinstance(raw, dict):
        return None
    for path in paths:
        cur = raw
        ok = True
        for part in str(path).split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return None


def _host(raw: dict) -> dict[str, Any]:
    host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
    return {
        "name": host.get("name") or raw.get("hostname"),
        "ip": host.get("ip") or raw.get("host_ip"),
    }


def _user(raw: dict) -> dict[str, Any]:
    user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    return {"name": user.get("name") or raw.get("username")}


def map_suricata(raw: dict) -> dict[str, Any]:
    """Suricata eve.json → canonique.

    Exemple d'entrée : {timestamp, event_type, src_ip, dest_ip, proto,
    alert: {signature, severity}, ...}.
    """
    if not isinstance(raw, dict):
        return {}
    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    event_type = raw.get("event_type") or "alert"
    signature = alert.get("signature")
    return {
        "@timestamp": raw.get("timestamp"),
        "event.kind": "alert",
        "event.category": event_type,
        "event.type": signature or event_type,
        "src_ip": raw.get("src_ip"),
        "dest_ip": raw.get("dest_ip"),
        "host": _host(raw),
        "user": _user(raw),
        "description": signature or f"Suricata {event_type.upper()} Log",
        "severity": alert.get("severity"),
        "payload": raw,
        "proto": raw.get("proto"),
        "agent_id": None,
        "tenant_id": raw.get("tenant_id"),
    }


def map_wazuh(raw: dict) -> dict[str, Any]:
    """Alerte Wazuh (webhook ou hit indexer) → canonique.

    Exemple d'entrée : {timestamp, rule {id, level, description},
    agent {id, name, ip}, ...}.
    """
    if not isinstance(raw, dict):
        return {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    host = _host(raw)
    return {
        "@timestamp": raw.get("timestamp"),
        "event.kind": "alert",
        "event.category": str(rule.get("id") or "security"),
        "event.type": rule.get("description") or "wazuh",
        "src_ip": agent.get("ip") or host["ip"],
        "dest_ip": None,
        "host": host,
        "user": _user(raw),
        "description": rule.get("description") or "Wazuh Alert",
        "severity": rule.get("level"),
        "payload": raw,
        "proto": None,
        "agent_id": agent.get("id"),
        "tenant_id": raw.get("tenant_id"),
    }


def map_generic(raw: dict) -> dict[str, Any]:
    """Source générique → canonique (fallback tolérant, jamais d'exception)."""
    if not isinstance(raw, dict):
        return {}
    return {
        "@timestamp": raw.get("@timestamp") or raw.get("timestamp"),
        "event.kind": raw.get("event.kind") or raw.get("kind") or "alert",
        "event.category": raw.get("event.category") or raw.get("category"),
        "event.type": raw.get("event.type") or raw.get("type"),
        "src_ip": raw.get("src_ip") or raw.get("source_ip") or _get(raw, "source.ip"),
        "dest_ip": raw.get("dest_ip") or raw.get("destination_ip") or _get(raw, "destination.ip"),
        "host": _host(raw),
        "user": _user(raw),
        "description": raw.get("description") or raw.get("message"),
        "severity": raw.get("severity"),
        "payload": raw,
        "proto": raw.get("proto"),
        "agent_id": raw.get("agent_id"),
        "tenant_id": raw.get("tenant_id"),
    }


def map_syslog(raw: dict) -> dict[str, Any]:
    """Syslog (RFC 5424/3164, agentless) → canonique.

    Entrée : dict produit par app.infrastructure.syslog.protocol.parse_syslog()
    enrichi par le receiver (source_ip, tenant_id).
    """
    if not isinstance(raw, dict):
        return {}
    c = {k: None for k in CANONICAL_KEYS}
    c["@timestamp"] = _get(raw, "timestamp") or datetime.now(UTC).isoformat()
    c["event.kind"] = "alert"
    c["event.category"] = "network"
    c["event.type"] = "info"
    c["description"] = _get(raw, "message")
    c["src_ip"] = _get(raw, "source_ip")

    # Severity: syslog severity 0-7 → our normalized scale
    sev = _get(raw, "severity")
    if sev is not None:
        try:
            sev_int = int(sev)
            # Map syslog severity (0=crit, 7=debug) to 1-15 scale
            mapping = {0: 15, 1: 13, 2: 11, 3: 9, 4: 7, 5: 5, 6: 3, 7: 1}
            c["severity"] = mapping.get(sev_int, 5)
        except (ValueError, TypeError):
            c["severity"] = 5

    c["agent_id"] = _get(raw, "appname")
    c["host"] = {"name": _get(raw, "hostname"), "ip": _get(raw, "source_ip")}
    c["payload"] = raw.get("message")

    # Proto: default to "syslog"
    c["proto"] = "syslog"

    return c


def normalize_event(raw: dict, source: str) -> dict[str, Any]:
    """Dispatche vers le mapper de la source (suricata | wazuh | syslog | générique)."""
    src = (source or "generic").lower()
    if src == "suricata":
        return map_suricata(raw)
    if src == "wazuh":
        return map_wazuh(raw)
    if src == "syslog":
        return map_syslog(raw)
    return map_generic(raw)


def to_pipeline_payload(canonical: dict[str, Any], source: str) -> dict[str, Any]:
    """Convertit un événement canonique en payload ingest_alert() (pipeline.py)."""
    return {
        "source": source,
        "timestamp": canonical.get("@timestamp"),
        "severity": canonical.get("severity"),
        "signature": canonical.get("event.type"),
        "description": canonical.get("description"),
        "src_ip": canonical.get("src_ip"),
        "dest_ip": canonical.get("dest_ip"),
        "proto": canonical.get("proto"),
        "agent_id": canonical.get("agent_id"),
        "category": canonical.get("event.category"),
        "raw": canonical.get("payload"),
        "tenant_id": canonical.get("tenant_id"),
    }
