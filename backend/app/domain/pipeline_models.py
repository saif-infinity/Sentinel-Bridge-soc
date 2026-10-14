"""F1 — PipelineEvent : persistance optionnelle (opt-in) des événements du pipeline."""
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


def _utcnow():
    return datetime.now(UTC)


class PipelineEvent(Base):
    __tablename__ = "pipeline_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    source: Mapped[str] = mapped_column(String(30), index=True)
    signature: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    severity: Mapped[int] = mapped_column(Integer, default=5)
    normalized_severity: Mapped[int] = mapped_column(Integer, default=5, index=True)
    dedup_key: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    deduped: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
