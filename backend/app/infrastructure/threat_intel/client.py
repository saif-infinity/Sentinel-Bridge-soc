"""F3 — Client Threat Intelligence (AbuseIPDB) + cache dialect-aware.

Dialectes : dev = Postgres, tests = SQLite. Aucun DDL brut hors
ADD COLUMN idempotent (ensure_intel_columns). Ne lève JAMAIS sur le réseau :
échec provider => verdict "unknown".
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

import httpx
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from ...config import settings
from ...domain.intel import ThreatIntelCache

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_UNKNOWN = "unknown"

# Types DDL par dialecte (uniquement pour ADD COLUMN sur tables existantes)
_INTEL_TYPE_SQL = {
    "postgresql": {
        "intel_score": "INTEGER",
        "intel_verdict": "VARCHAR(20)",
        "intel_source": "VARCHAR(64)",
        "intel_checked_at": "TIMESTAMPTZ",
    },
    "sqlite": {
        "intel_score": "INTEGER",
        "intel_verdict": "VARCHAR(20)",
        "intel_source": "VARCHAR(64)",
        "intel_checked_at": "TIMESTAMP",
    },
}


def _verdict_from_score(score: int) -> str:
    if score >= 80:
        return VERDICT_MALICIOUS
    if score >= 40:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def fetch_abuseipdb(ip: str, api_key: str, timeout: int = 10) -> Dict[str, Any]:
    """Appel HTTP réel — remplacé par un mock dans les tests."""
    with httpx.Client(timeout=timeout) as client:
        r = client.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "verdict": _verdict_from_score(int(d.get("abuseConfidenceScore") or 0)),
            "risk_score": int(d.get("abuseConfidenceScore") or 0),
            "source_name": "AbuseIPDB",
            "raw_json": json.dumps(d, default=str),
        }


def _aware(ts) -> datetime:
    """SQLite stocke les DateTime(timezone=True) en naïf — normalise."""
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def _upsert_cache(db, tenant_id: str, ip: str, data: Dict[str, Any]):
    row = (
        db.query(ThreatIntelCache)
        .filter(
            ThreatIntelCache.tenant_id == tenant_id,
            ThreatIntelCache.ip == ip,
            ThreatIntelCache.provider == "abuseipdb",
        )
        .first()
    )
    if row is None:
        row = ThreatIntelCache(tenant_id=tenant_id, ip=ip, provider="abuseipdb")
        db.add(row)
    row.verdict = data["verdict"]
    row.risk_score = data["risk_score"]
    row.source_name = data["source_name"]
    row.raw_json = data["raw_json"]
    row.checked_at = datetime.now(timezone.utc)
    db.commit()


def lookup_ip(db, tenant_id: str, ip: str, force: bool = False) -> Dict[str, Any]:
    """Vérifie une IP : cache frais sinon provider. Ne lève JAMAIS."""
    if not ip:
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False}

    cached = (
        db.query(ThreatIntelCache)
        .filter(ThreatIntelCache.tenant_id == tenant_id, ThreatIntelCache.ip == ip)
        .order_by(ThreatIntelCache.checked_at.desc())
        .first()
    )
    if cached and not force:
        age = (datetime.now(timezone.utc) - _aware(cached.checked_at)).total_seconds()
        if age < int(settings.THREAT_INTEL_CACHE_TTL_SECONDS):
            return {
                "verdict": cached.verdict, "risk_score": cached.risk_score,
                "source_name": cached.source_name, "raw_json": cached.raw_json,
                "checked_at": _aware(cached.checked_at).isoformat(), "from_cache": True,
            }

    if not settings.THREAT_INTEL_ENABLED or not settings.THREAT_INTEL_API_KEY.get_secret_value():
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False}

    try:
        data = fetch_abuseipdb(ip, settings.THREAT_INTEL_API_KEY.get_secret_value(),
                               int(settings.THREAT_INTEL_TIMEOUT_SECONDS))
        _upsert_cache(db, tenant_id, ip, data)
        data["checked_at"] = datetime.now(timezone.utc).isoformat()
        data["from_cache"] = False
        return data
    except Exception as e:
        logger.warning("Threat intel échec pour %s: %s", ip, e)
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False}


def ensure_intel_columns(db) -> int:
    """Ajoute intel_* à alerts et suricata_alerts (idempotent, dialect-aware).

    Les définitions SQLAlchemy des modèles (modif §2.4 — PASS 2) couvrent les bases
    neuves (create_all) ; ici on migre les bases existantes (dev Postgres)."""
    dialect = db.get_bind().dialect.name
    type_map = _INTEL_TYPE_SQL.get(dialect)
    if type_map is None:
        logger.warning("Dialecte %s non supporté pour ensure_intel_columns", dialect)
        return 0
    added = 0
    for table in ("alerts", "suricata_alerts"):
        inspector = sa_inspect(db.get_bind())
        existing = {c["name"] for c in inspector.get_columns(table)}
        for col_name, col_sql in type_map.items():
            if col_name not in existing:
                db.execute(sa.text(f'ALTER TABLE "{table}" ADD COLUMN {col_name} {col_sql}'))
                added += 1
    if added:
        db.commit()
    return added
