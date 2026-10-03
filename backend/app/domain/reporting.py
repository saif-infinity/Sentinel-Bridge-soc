"""F5 — Reporting Subsystem : models.

Multi-tenant tables: reports, report_templates, report_schedules,
report_recipients, report_logs. All queries filter by tenant_id.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Index, Integer, String, Text, DateTime, Float, ForeignKey, Boolean,
    Enum, JSON,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base
from .soar import _utcnow


class Report(Base):
    """Generated report (ad-hoc or scheduled)."""
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    report_type: Mapped[str] = mapped_column(String(30), index=True)
    # daily | trends | case_closure | investigation_summary | custom
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    # pending | generating | generated | failed | cancelled
    format: Mapped[str] = mapped_column(String(10), default="html")
    # html | csv | pdf
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    params: Mapped[str] = mapped_column(Text, default="{}")
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("report_schedules.id"), index=True, nullable=True)
    generated_by: Mapped[str] = mapped_column(String(100), default="system")
    # system | user | scheduled
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True, nullable=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_reports_tenant_type_created", "tenant_id", "report_type", "created_at"),
        Index("ix_reports_tenant_status", "tenant_id", "status"),
    )


class ReportTemplate(Base):
    """Reusable report template definition."""
    __tablename__ = "report_templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    report_type: Mapped[str] = mapped_column(String(30), index=True)
    # daily | trends | case_closure | investigation_summary | custom
    params_schema: Mapped[str] = mapped_column(Text, default="{}")
    # JSON schema for template parameters
    default_params: Mapped[str] = mapped_column(Text, default="{}")
    html_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_templates_tenant_type", "tenant_id", "report_type"),
    )


class ReportSchedule(Base):
    """Scheduled report generation configuration."""
    __tablename__ = "report_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    name: Mapped[str] = mapped_column(String(200))
    report_type: Mapped[str] = mapped_column(String(30), index=True)
    template_id: Mapped[int | None] = mapped_column(ForeignKey("report_templates.id"), index=True, nullable=True)
    cron_expr: Mapped[str] = mapped_column(String(50), default="0 0 * * *")
    format: Mapped[str] = mapped_column(String(10), default="html")
    recipients: Mapped[str] = mapped_column(Text, default="[]")
    params: Mapped[str] = mapped_column(Text, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_schedules_tenant_active", "tenant_id", "is_active"),
    )


class ReportRecipient(Base):
    """Recipient configuration for report delivery."""
    __tablename__ = "report_recipients"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("report_schedules.id"), index=True, nullable=True)
    report_id: Mapped[int | None] = mapped_column(ForeignKey("reports.id"), index=True, nullable=True)
    channel: Mapped[str] = mapped_column(String(20), default="email")
    # email | webhook | telegram | slack
    destination: Mapped[str] = mapped_column(String(255))
    # Email address, webhook URL, or chat ID
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending | sent | failed
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    __table_args__ = (
        Index("ix_recipients_tenant_report", "tenant_id", "report_id"),
    )


class ReportLog(Base):
    """Audit log for report generation and delivery."""
    __tablename__ = "report_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    report_id: Mapped[int] = mapped_column(ForeignKey("reports.id"), index=True)
    action: Mapped[str] = mapped_column(String(30), index=True)
    # generated | sent | failed | cancelled
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    __table_args__ = (
        Index("ix_logs_tenant_report_action", "tenant_id", "report_id", "action"),
    )
