"""F5 — Automated Investigation Subsystem : models.

Multi-tenant tables: investigations, investigation_evidence,
investigation_recommendations. All queries filter by tenant_id.
"""
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from .soar import _utcnow


class Investigation(Base):
    """Investigation created from a RuleMatchEvent. Multi-tenant."""
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    event_id: Mapped[str] = mapped_column(String(36), index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True, nullable=True)
    trigger_alert_type: Mapped[str] = mapped_column(String(20))  # "alert" | "suricata"
    trigger_alert_id: Mapped[int] = mapped_column(Integer, index=True)
    dedup_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    # queued | running | scoring | summarizing | awaiting_response | complete | cancelled | failed
    completion: Mapped[str] = mapped_column(String(10), default="full")  # full | partial
    missing_steps: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0-100
    risk_level: Mapped[str | None] = mapped_column(String(10), nullable=True)  # low|medium|high|critical
    score_breakdown: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), default="investigation")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_investigations_tenant_status_created", "tenant_id", "status", "created_at"),
        Index("ix_investigations_tenant_dedup_created", "tenant_id", "dedup_fingerprint", "created_at"),
    )


class InvestigationEvidence(Base):
    """Evidence collected during investigation steps. Multi-tenant."""
    __tablename__ = "investigation_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    step_key: Mapped[str] = mapped_column(String(120))
    evidence_type: Mapped[str] = mapped_column(String(30), index=True)
    # threat_intel | host | asset | correlation | related_alerts | mitre | llm | linked_alert
    source: Mapped[str] = mapped_column(String(40))
    # abuseipdb | wazuh | assets | rules.engine | ollama | correlation | pipeline
    status: Mapped[str] = mapped_column(String(10), default="success")  # success | failed | skipped
    summary: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    __table_args__ = (
        UniqueConstraint("investigation_id", "step_key", name="uq_evid_inv_step"),
        Index("ix_evidence_tenant_inv_created", "tenant_id", "investigation_id", "collected_at"),
    )


class InvestigationRecommendation(Base):
    """Response-phase recommendations from an investigation. Multi-tenant."""
    __tablename__ = "investigation_recommendations"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(30), index=True)
    # block_ip | isolate_agent | notify | run_playbook | monitor | quarantine
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=3)  # 1-5
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0-1
    rationale: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(10), default="rule_based")  # rule_based | llm
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    # pending | accepted | executed | dismissed | failed
    response_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_rec_tenant_inv_status", "tenant_id", "investigation_id", "status"),
    )
