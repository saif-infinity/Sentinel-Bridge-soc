"""R3 — Déduplication des notifications (fenêtre temporelle par canal).

Insertion atomique ON CONFLICT DO NOTHING : rowcount==0 => doublon.
Fonctionne sur PostgreSQL ET SQLite (unique index (fingerprint, channel_id)).
"""
import hashlib
import logging
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, sqlite

from ...domain.models import NotificationDedup

logger = logging.getLogger(__name__)


def _dedup_insert(db):
    """Insert dialect-aware (ON CONFLICT DO NOTHING dispo sur PG et SQLite)."""
    if db.get_bind().dialect.name == "postgresql":
        return postgresql.insert(NotificationDedup)
    return sqlite.insert(NotificationDedup)


def compute_fingerprint(tenant_id: str, src_ip, dest_ip, signature, rule_id) -> str:
    """Empreinte sha256 déterministe et normalisée (None -> "", minuscules, strip)."""
    parts = [
        str(tenant_id or "").strip().lower(),
        str(src_ip or "").strip().lower(),
        str(dest_ip or "").strip().lower(),
        str(signature or "").strip().lower(),
        str(rule_id or "").strip().lower(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def is_duplicate(db, tenant_id: str, fingerprint: str, channel_id: int,
                 window_seconds: int) -> bool:
    """True si la notification est un doublon dans la fenêtre.

    - window_seconds <= 0 => déduplication désactivée (toujours False).
    - Purge opportuniste des entrées expirées du fingerprint avant l'insert.
    - INSERT ... ON CONFLICT DO NOTHING : rowcount==0 => doublon.
    """
    if window_seconds <= 0:
        return False
    cutoff = datetime.now(UTC) - timedelta(seconds=window_seconds)
    db.execute(
        sa.delete(NotificationDedup).where(
            NotificationDedup.fingerprint == fingerprint,
            NotificationDedup.channel_id == channel_id,
            NotificationDedup.first_seen < cutoff,
        )
    )
    stmt = _dedup_insert(db).values(
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        channel_id=channel_id,
        first_seen=datetime.now(UTC),
    ).on_conflict_do_nothing(index_elements=["fingerprint", "channel_id"])
    result = db.execute(stmt)
    db.commit()
    return (result.rowcount or 0) == 0


def prune_dedup(db, max_age_hours: int = 24) -> int:
    """Supprime les entrées de déduplication plus vieilles que max_age_hours."""
    cutoff = datetime.now(UTC) - timedelta(hours=max_age_hours)
    result = db.execute(
        sa.delete(NotificationDedup).where(NotificationDedup.first_seen < cutoff)
    )
    db.commit()
    return result.rowcount or 0
