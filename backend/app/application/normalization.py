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
from typing import Any, Dict

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


def _host(raw: dict) -> Dict[str, Any]:
    host = raw.get("host") if isinstance(raw.get("host"), dict) else {}
    return {
        "name": host.get("name") or raw.get("hostname"),
        "ip": host.get("ip") or raw.get("host_ip"),
    }


def _user(raw: dict) -> Dict[str, Any]:
    user = raw.get("user") if isinstance(raw.get("user"), dict) else {}
    return {"name": user.get("name") or raw.get("username")}


def map_suricata(raw: dict) -> Dict[str, Any]:
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


def map_wazuh(raw: dict) -> Dict[str, Any]:
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


def map_generic(raw: dict) -> Dict[str, Any]:
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


def normalize_event(raw: dict, source: str) -> Dict[str, Any]:
    """Dispatche vers le mapper de la source (suricata | wazuh | générique)."""
    src = (source or "generic").lower()
    if src == "suricata":
        return map_suricata(raw)
    if src == "wazuh":
        return map_wazuh(raw)
    return map_generic(raw)


def to_pipeline_payload(canonical: Dict[str, Any], source: str) -> Dict[str, Any]:
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