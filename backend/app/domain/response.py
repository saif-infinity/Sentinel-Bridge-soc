"""F5 — Automated Response Agent : models.

Multi-tenant tables: response_runs, response_action_results, response_rollbacks.
All queries filter by tenant_id.
"""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
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


class ResponseRun(Base):
    """An approved/auto-approved response action against an investigation recommendation."""
    __tablename__ = "response_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=True)
    recommendation_id: Mapped[int | None] = mapped_column(ForeignKey("investigation_recommendations.id"), index=True, nullable=True)
    action_type: Mapped[str] = mapped_column(String(30), index=True)
    # block_ip | isolate_agent | quarantine | restart_service | escalate | notify | monitor | run_playbook | unblock_ip | restore_agent | unquarantine_file
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    params: Mapped[str] = mapped_column(Text, default="{}")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(20), default="pending_approval", index=True)
    # pending_approval | approved | rejected | running | success | failed | cancelled
    rollback_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(100), default="response_agent")
    approved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        UniqueConstraint("recommendation_id", name="uq_run_rec"),
        Index("ix_response_runs_tenant_status_created", "tenant_id", "status", "created_at"),
    )


class ResponseActionResult(Base):
    """Result of executing a single response action (supports retries)."""
    __tablename__ = "response_action_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    run_id: Mapped[int] = mapped_column(ForeignKey("response_runs.id"), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(10), default="success")
    # success | failed | skipped
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("ix_result_run_attempt", "run_id", "attempt"),
    )


class ResponseRollback(Base):
    """Rollback record for a reversed response action."""
    __tablename__ = "response_rollbacks"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    run_id: Mapped[int] = mapped_column(ForeignKey("response_runs.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(30))
    # unblock_ip | restore_agent | unquarantine_file
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    params: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    # pending | running | success | failed
    initiated_by: Mapped[str] = mapped_column(String(100), default="response_agent")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_rollback_tenant_run", "tenant_id", "run_id"),
    )
