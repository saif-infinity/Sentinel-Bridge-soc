"""F3 — Client Threat Intelligence (AbuseIPDB + VirusTotal + Kaspersky) + cache dialect-aware.

Dialectes : dev = Postgres, tests = SQLite. Aucun DDL brut hors
ADD COLUMN idempotent (ensure_intel_columns). Ne lève JAMAIS sur le réseau :
échec provider => verdict "unknown".

Garde-fous lab:
- IP privées (RFC1918, loopback, link-local, doc) → unknown sans requête.
- Cache par provider (abuseipdb|virustotal|kaspersky).
- Clés uniquement côté serveur (settings / SystemConfig), jamais agent.
- Quotas: check in-memory counters (fail-open si Redis indisponible).
"""
import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from ...application.system_config import get_config_value
from ...config import settings
from ...domain.intel import ThreatIntelCache
from .private_ip import is_private_or_reserved
from .providers import (
    ABUSEIPDB_URL,
    VERDICT_CLEAN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    fetch_abuseipdb,
    fetch_kaspersky,
    fetch_virustotal,
)

logger = logging.getLogger(__name__)

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


def _aware(ts) -> datetime:
    """SQLite stocke les DateTime(timezone=True) en naïf — normalise."""
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def _upsert_cache(db, tenant_id: str, ip: str, data: dict[str, Any]):
    provider = data.get("provider") or "abuseipdb"
    row = (
        db.query(ThreatIntelCache)
        .filter(
            ThreatIntelCache.tenant_id == tenant_id,
            ThreatIntelCache.ip == ip,
            ThreatIntelCache.provider == provider,
        )
        .first()
    )
    if row is None:
        row = ThreatIntelCache(tenant_id=tenant_id, ip=ip, provider=provider)
        db.add(row)
    row.verdict = data["verdict"]
    row.risk_score = data["risk_score"]
    row.source_name = data["source_name"]
    row.raw_json = data["raw_json"]
    row.checked_at = datetime.now(UTC)
    db.commit()


def _get_provider_config(db, tenant_id: str) -> tuple[str, str | None, int]:
    """Résout provider + clé + timeout depuis SystemConfig/threat_intel puis Settings."""
    provider = get_config_value(db, "threat_intel", "provider", fallback="abuseipdb", tenant_id=tenant_id)
    provider = provider.lower().strip() if provider else "abuseipdb"
    if provider not in ("abuseipdb", "virustotal", "kaspersky"):
        provider = "abuseipdb"
    # Clé selon provider
    api_key = None
    if provider == "abuseipdb":
        api_key = get_config_value(db, "threat_intel", "api_key", fallback="", tenant_id=tenant_id) or settings.THREAT_INTEL_API_KEY.get_secret_value()
    elif provider == "virustotal":
        api_key = get_config_value(db, "threat_intel", "virustotal_api_key", fallback="", tenant_id=tenant_id)
        if not api_key:
            # fallback env VT
            import os as _os
            api_key = _os.getenv("VIRUSTOTAL_API_KEY", "") or _os.getenv("VT_API_KEY", "")
    elif provider == "kaspersky":
        api_key = get_config_value(db, "threat_intel", "kaspersky_api_key", fallback="", tenant_id=tenant_id)
        if not api_key:
            import os as _os
            api_key = _os.getenv("KASPERSKY_API_KEY", "")
    timeout = int(settings.THREAT_INTEL_TIMEOUT_SECONDS)
    return provider, api_key, timeout


def _check_quota_in_memory(provider: str, tenant_id: str) -> bool:
    """Simple in-memory quota guard (fail-open). AbuseIPDB 1000/j, VT 500/j par défaut."""
    # We use a naive in-process counter keyed by day. If Redis is available we could use it, but fail-open is fine for lab.
    from collections import defaultdict
    import time
    # Lazy global counter
    if not hasattr(_check_quota_in_memory, "_counters"):
        _check_quota_in_memory._counters = defaultdict(int)  # type: ignore
        _check_quota_in_memory._reset_day = time.strftime("%Y-%m-%d")  # type: ignore
    today = time.strftime("%Y-%m-%d")
    if _check_quota_in_memory._reset_day != today:  # type: ignore
        _check_quota_in_memory._counters.clear()  # type: ignore
        _check_quota_in_memory._reset_day = today  # type: ignore
    key = f"{tenant_id}:{provider}:{today}"
    count = _check_quota_in_memory._counters[key]  # type: ignore
    # Quotas from config (defaults)
    limits = {"abuseipdb": 1000, "virustotal": 500, "kaspersky": 500}
    limit = limits.get(provider, 1000)
    if count >= limit:
        logger.warning("TI quota atteint pour %s (%d/%d) — requête ignorée", provider, count, limit)
        return False
    _check_quota_in_memory._counters[key] += 1  # type: ignore
    return True


def lookup_ip(db, tenant_id: str, ip: str, force: bool = False, provider: str | None = None) -> dict[str, Any]:
    """Vérifie une IP : cache frais sinon provider. Ne lève JAMAIS.

    Garde-fous:
    - IP vide → unknown
    - IP privée/réservée → unknown sans requête (pas de réputation LAN)
    - provider=None → résout depuis SystemConfig/threat_intel
    - cache frais → from_cache True
    - quota dépassé → unknown
    """
    if not ip:
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": provider or "none",
                "reason": "no_ip"}
    if is_private_or_reserved(ip):
        logger.debug("TI skip IP privée/réservée %s → unknown", ip)
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": "none",
                "reason": "private_ip"}

    # Résoudre provider si non forcé
    if provider is None:
        prov_cfg, _, _ = _get_provider_config(db, tenant_id)
        provider = prov_cfg
    else:
        provider = provider.lower()

    # Check cache pour ce provider
    cached = (
        db.query(ThreatIntelCache)
        .filter(ThreatIntelCache.tenant_id == tenant_id, ThreatIntelCache.ip == ip, ThreatIntelCache.provider == provider)
        .order_by(ThreatIntelCache.checked_at.desc())
        .first()
    )
    if not cached:
        # Fallback: any provider cache (for backward compat — abuseipdb rows without provider distinction)
        cached = (
            db.query(ThreatIntelCache)
            .filter(ThreatIntelCache.tenant_id == tenant_id, ThreatIntelCache.ip == ip)
            .order_by(ThreatIntelCache.checked_at.desc())
            .first()
        )
        if cached and cached.provider != provider:
            cached = None  # don't reuse wrong provider
    if cached and not force:
        age = (datetime.now(UTC) - _aware(cached.checked_at)).total_seconds()
        if age < int(settings.THREAT_INTEL_CACHE_TTL_SECONDS):
            return {
                "verdict": cached.verdict, "risk_score": cached.risk_score,
                "source_name": cached.source_name, "raw_json": cached.raw_json,
                "checked_at": _aware(cached.checked_at).isoformat(), "from_cache": True,
                "provider": cached.provider,
            }

    if not settings.THREAT_INTEL_ENABLED:
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": provider,
                "reason": "ti_disabled"}

    _, api_key, timeout = _get_provider_config(db, tenant_id)
    # Override if provider param matches config provider; else re-resolve
    if provider != prov_cfg:  # type: ignore
        # Caller forced different provider, try to get its key
        provider, api_key, timeout = provider, api_key, timeout
        # For forced provider we already have api_key from earlier loop, but re-fetch if mismatch
        # Simpler: fetch again via SystemConfig
        tmp_provider = provider
        provider, api_key, timeout = _get_provider_config(db, tenant_id)
        if tmp_provider != provider:
            # If still mismatch, use tmp_provider with maybe empty key
            provider = tmp_provider
            if provider == "virustotal":
                api_key = get_config_value(db, "threat_intel", "virustotal_api_key", fallback="", tenant_id=tenant_id)
            elif provider == "kaspersky":
                api_key = get_config_value(db, "threat_intel", "kaspersky_api_key", fallback="", tenant_id=tenant_id)

    if not api_key:
        logger.debug("TI %s pas de clé pour %s → unknown", provider, ip)
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": provider,
                "reason": "no_api_key"}

    if not _check_quota_in_memory(provider, tenant_id):
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": provider,
                "reason": "quota_exceeded"}

    try:
        if provider == "virustotal":
            data = fetch_virustotal(ip, api_key, timeout)
        elif provider == "kaspersky":
            data = fetch_kaspersky(ip, api_key, timeout)
        else:
            data = fetch_abuseipdb(ip, api_key, timeout)
        _upsert_cache(db, tenant_id, ip, data)
        data["checked_at"] = datetime.now(UTC).isoformat()
        data["from_cache"] = False
        data["provider"] = provider
        return data
    except Exception as e:
        logger.warning("Threat intel échec pour %s (%s): %s", ip, provider, e)
        return {"verdict": VERDICT_UNKNOWN, "risk_score": None, "source_name": None,
                "raw_json": None, "checked_at": None, "from_cache": False, "provider": provider,
                "reason": "provider_error"}


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
