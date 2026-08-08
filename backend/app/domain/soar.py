"""F3 — Mini-SOAR : modèles Playbook / PlaybookRun / PlaybookStepResult.

Consomme le contrat F1 (RuleMatchEvent / RuleMatchOutbox) — ne possède AUCUN
modèle d'outbox. L'outbox appartient à F1 (app.domain.rule_models).
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from ..db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(64), nullable=True, index=True)  # NULL = global
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    trigger_rule_ids = Column(JSON, nullable=True, default=list)     # ["rule_001", ...]
    trigger_min_severity = Column(Integer, nullable=True)            # 0-15, NULL = tout
    trigger_sources = Column(JSON, nullable=True, default=list)      # ["wazuh", "suricata", "pipeline"]
    requires_approval = Column(Boolean, default=False, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    steps = Column(JSON, nullable=False)  # [{"type": ..., "params": {...}, "timeout_seconds": ...}]
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("name", "tenant_id", name="uq_playbook_name_tenant"),
    )


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id = Column(Integer, primary_key=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(64), nullable=False)                    # event_id F1 (idempotence)
    tenant_id = Column(String(64), nullable=False, index=True)
    triggered_by = Column(String(255), nullable=True)                # rule_id déclencheur
    event_payload = Column(JSON, nullable=True)                      # snapshot normalized_alert (rendu {{...}})
    status = Column(String(32), nullable=False, default="approved", index=True)
    # pending_approval | approved | running | success | failed | skipped | cancelled
    current_step_index = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    playbook = relationship("Playbook")
    steps = relationship(
        "PlaybookStepResult", back_populates="run",
        cascade="all, delete-orphan", order_by="PlaybookStepResult.step_index",
    )

    __table_args__ = (
        UniqueConstraint("event_id", "playbook_id", name="uq_run_event_playbook"),
    )


class PlaybookStepResult(Base):
    __tablename__ = "playbook_step_results"

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("playbook_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    step_type = Column(String(32), nullable=False)   # notify | log | sleep | run_task | block_ip
    status = Column(String(16), nullable=False, default="success")  # success | failed | skipped
    output = Column(Text, nullable=True)             # JSON string
    error = Column(Text, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    run = relationship("PlaybookRun", back_populates="steps")

    __table_args__ = (
        Index("ix_playbook_step_results_run_step", "run_id", "step_index"),
    )
