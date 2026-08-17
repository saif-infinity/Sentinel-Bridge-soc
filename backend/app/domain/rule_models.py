"""F1 — Modèles de domaine du moteur de règles (additif : ne modifie aucun modèle existant)."""
import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import String, Boolean, DateTime, Index, Integer, Text
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base

logger = logging.getLogger(__name__)


def _utcnow():
    return datetime.now(timezone.utc)


class Rule(Base):
    """Règle de corrélation. tenant_id NULL (None) = règle globale visible par tous les tenants."""
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    severity: Mapped[int] = mapped_column(Integer, default=5)      # sévérité normalisée 0-15 attribuée au match
    tags: Mapped[str] = mapped_column(Text, default="[]")          # JSON : liste de tags MITRE ATT&CK
    conditions: Mapped[str] = mapped_column(Text, default="[]")    # JSON : [{field, op, value}]
    correlation: Mapped[str] = mapped_column(Text, default="{}")   # JSON : {window_seconds, sequence, require_same_src, require_same_dest, count, threshold_window_seconds}
    action_flags: Mapped[str] = mapped_column(Text, default="{}")  # JSON : {notify, log, block}
    # ── R2 MITRE ATT&CK (additif) ──
    mitre_attack_ids: Mapped[str] = mapped_column(Text, default="[]")  # JSON : ["T1059.001", "T1078"]
    tactics: Mapped[str] = mapped_column(Text, default="[]")           # JSON : ["execution", "defense-evasion"]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class RuleMatchOutbox(Base):
    """Outbox durable des RuleMatchEvent — moitié persistante du contrat d'événements F1."""
    __tablename__ = "rule_match_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    channel: Mapped[str] = mapped_column(String(50), default="rules.match")
    payload: Mapped[str] = mapped_column(Text)                     # JSON du RuleMatchEvent
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending/consumed/failed
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (
        Index("ix_rule_match_events_tenant_created", "tenant_id", "created_at"),
    )


class CorrelationState(Base):
    """R13 — État persistant du corrélateur (remplace le deque in-memory).

    Les fenêtres de séquence et les compteurs de seuil survivent au restart.
    kind :
      - "sequence_event" : événement satisfaisant ≥1 étape d'une séquence
        (payload = alerte normalisée JSON, window_start = timestamp de l'événement).
      - "sequence_fired" : marqueur "déjà déclenché" d'une séquence pour une fenêtre.
      - "count"          : compteur d'agrégat (count / threshold_window_seconds).
    """
    __tablename__ = "correlation_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    rule_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)
    correlation_key: Mapped[str] = mapped_column(String(255), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (
        Index("ix_correlation_state_rule_kind_key", "rule_id", "kind", "correlation_key"),
    )


# Types DDL par dialecte (ADD COLUMN idempotent sur bases existantes)
_MITRE_TYPE_SQL = {
    "postgresql": {
        "mitre_attack_ids": "TEXT DEFAULT '[]'",
        "tactics": "TEXT DEFAULT '[]'",
    },
    "sqlite": {
        "mitre_attack_ids": "TEXT DEFAULT '[]'",
        "tactics": "TEXT DEFAULT '[]'",
    },
}


def ensure_mitre_columns(db) -> int:
    """R2 — Ajoute mitre_attack_ids/tactics à rules (idempotent, dialect-aware).

    Les définitions SQLAlchemy du modèle couvrent les bases neuves (create_all) ;
    ici on migre les bases existantes (dev Postgres) sans jamais lever.
    """
    dialect = db.get_bind().dialect.name
    type_map = _MITRE_TYPE_SQL.get(dialect)
    if type_map is None:
        logger.warning("Dialecte %s non supporté pour ensure_mitre_columns", dialect)
        return 0
    added = 0
    inspector = sa_inspect(db.get_bind())
    existing = {c["name"] for c in inspector.get_columns("rules")}
    for col_name, col_sql in type_map.items():
        if col_name not in existing:
            db.execute(sa.text(f'ALTER TABLE "rules" ADD COLUMN {col_name} {col_sql}'))
            added += 1
    if added:
        db.commit()
    return added
