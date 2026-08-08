"""F1 — Modèles de domaine du moteur de règles (additif : ne modifie aucun modèle existant)."""
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base


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
    correlation: Mapped[str] = mapped_column(Text, default="{}")   # JSON : {window_seconds, sequence, require_same_src, require_same_dest}
    action_flags: Mapped[str] = mapped_column(Text, default="{}")  # JSON : {notify, log, block}
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
