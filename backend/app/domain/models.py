import uuid
import json
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index, Integer, Text, Float, LargeBinary, PrimaryKeyConstraint, BigInteger, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timezone
from ..db import Base

def _utcnow():
    return datetime.now(timezone.utc)

def _gen_id():
    """Génère un id 31-bit unique pour les tables hypertables (composite PK (id, timestamp)).

    SQLite ne supporte pas l'auto-increment sur une PK composite ; PostgreSQL non plus
    via SQLAlchemy pour ce schéma. On génère donc côté Python un entier positif 31-bit
    (compatible INTEGER PostgreSQL 32-bit) — la PK composite (id, timestamp) rend la
    collision effective quasi impossible.
    """
    return int(uuid.uuid4().int & 0x7FFFFFFF)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    mac: Mapped[str] = mapped_column(String(32), index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    is_wazuh_agent: Mapped[bool] = mapped_column(Boolean, default=False)
    logs = relationship("ConnectionLog", back_populates="device")
    __table_args__ = (
        Index("ix_devices_tenant_mac", "tenant_id", "mac", unique=True),
    )

class ConnectionLog(Base):
    __tablename__ = "connection_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    status: Mapped[bool] = mapped_column(Boolean, index=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    device = relationship("Device", back_populates="logs")

Index("ix_logs_time_range", ConnectionLog.start_time, ConnectionLog.end_time)

class SuricataAlert(Base):
    __tablename__ = "suricata_alerts"
    id: Mapped[int] = mapped_column(default=_gen_id)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    proto: Mapped[str | None] = mapped_column(String(20))
    alert_msg: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[int] = mapped_column(Integer, default=3)
    payload: Mapped[str | None] = mapped_column(String(3000), nullable=True)
    # ── F1 Pipeline (additif) ──
    normalized_severity: Mapped[int] = mapped_column(Integer, default=5, index=True)
    pipeline_source: Mapped[str | None] = mapped_column(String(30), nullable=True)
    pipeline_processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    # ── F3 Threat Intel (additif) — miroir de ensure_intel_columns ──
    intel_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    intel_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    intel_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    intel_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # R4 — TimescaleDB hypertable : PK composite (id, timestamp)
    __table_args__ = (
        PrimaryKeyConstraint("id", "timestamp"),
    )

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    ip: Mapped[str] = mapped_column(String(45), index=True)
    employee_name: Mapped[str] = mapped_column(String(100))
    department: Mapped[str] = mapped_column(String(100))
    __table_args__ = (
        Index("ix_assets_tenant_ip", "tenant_id", "ip", unique=True),
    )

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(default=_gen_id)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=_utcnow)
    description: Mapped[str] = mapped_column(String(500))
    severity: Mapped[int] = mapped_column(Integer, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(10), nullable=True)
    # ── F1 Pipeline (additif) ──
    normalized_severity: Mapped[int] = mapped_column(Integer, default=5, index=True)
    pipeline_source: Mapped[str | None] = mapped_column(String(30), nullable=True)
    pipeline_processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    # ── F3 Threat Intel (additif) — miroir de ensure_intel_columns ──
    intel_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    intel_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    intel_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    intel_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # R4 — TimescaleDB hypertable : PK composite (id, timestamp)
    __table_args__ = (
        PrimaryKeyConstraint("id", "timestamp"),
    )

class IaReport(Base):
    __tablename__ = "ia_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    report_type: Mapped[str] = mapped_column(String(50), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(10), nullable=True)
    content: Mapped[str] = mapped_column(Text)

class AccessLog(Base):
    __tablename__ = "access_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str] = mapped_column(String(100), index=True)
    login_time: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    logout_time: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    face_image: Mapped[str | None] = mapped_column(Text, nullable=True)
    face_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    login_method: Mapped[str] = mapped_column(String(50), default="password")
    session_duration: Mapped[int | None] = mapped_column(Integer, nullable=True)

class ActionLog(Base):
    __tablename__ = "action_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str] = mapped_column(String(100), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    face_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)

class SystemConfig(Base):
    __tablename__ = "system_config"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    section: Mapped[str] = mapped_column(String(50), index=True)
    key: Mapped[str] = mapped_column(String(100), index=True)
    value: Mapped[str] = mapped_column(Text, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    label: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

class NetworkSensor(Base):
    __tablename__ = "network_sensors"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str] = mapped_column(String(100), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_recv: Mapped[int] = mapped_column(Integer, default=0)
    bandwidth_mbps: Mapped[float] = mapped_column(Float, default=0.0)
    interface: Mapped[str | None] = mapped_column(String(50), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)

class NetworkDevice(Base):
    __tablename__ = "network_devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    name: Mapped[str] = mapped_column(String(100), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    device_type: Mapped[str] = mapped_column(String(20), index=True)  # switch, router
    brand: Mapped[str] = mapped_column(String(50), default="cisco")  # cisco, mikrotik, huawei, hp
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    username: Mapped[str] = mapped_column(String(100), default="admin")
    password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    port: Mapped[int] = mapped_column(Integer, default=22)
    protocol: Mapped[str] = mapped_column(String(10), default="ssh")  # ssh, telnet
    status: Mapped[str] = mapped_column(String(20), default="offline", index=True)  # online, offline, error
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # saved config as JSON
    last_connected: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_configured: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    company_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    plan: Mapped[str] = mapped_column(String(20), default="trial")  # trial/basic/pro/enterprise
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)  # active/suspended/canceled
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    subscription_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    max_agents: Mapped[int] = mapped_column(Integer, default=5)
    max_endpoints: Mapped[int] = mapped_column(Integer, default=10)
    retention_days: Mapped[int] = mapped_column(Integer, default=7)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

class TenantUser(Base):
    __tablename__ = "tenant_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), index=True)
    username: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20), default="analyst")  # viewer/analyst/admin/super_admin
    email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    face_encoding: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # binary face data
    face_image: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # binary image
    face_registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_tenant_users_tenant_username", "tenant_id", "username", unique=True),
    )


# ── F2 — Gestion des affaires (cases) + triage + timeline + hunting ──

class Case(Base):
    """Affaire d'investigation SOC. created_by/assignee = username STRING (pas de FK User)."""
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    title: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open/in_progress/resolved/closed
    severity: Mapped[int] = mapped_column(Integer, default=5, index=True)        # 0-15, échelle normalisée F1
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(100), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class CaseAlertLink(Base):
    """Lien affaire ↔ alerte. LE STATUT DE TRIAGE VIT ICI (jamais sur Alert/SuricataAlert)."""
    __tablename__ = "case_alert_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    alert_type: Mapped[str] = mapped_column(String(20))   # "alert" | "suricata"
    alert_id: Mapped[int] = mapped_column(Integer, index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open/in_progress/resolved/dismissed
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    __table_args__ = (
        Index("ix_case_alert_links_case_alert", "case_id", "alert_type", "alert_id"),
    )


class TimelineEvent(Base):
    """Audit trail d'une affaire : création, changements de statut, liens, triage, notes."""
    __tablename__ = "timeline_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(30), index=True)
    actor: Mapped[str] = mapped_column(String(100), default="unknown")
    message: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON optionnel
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (
        Index("ix_timeline_events_case_created", "case_id", "created_at"),
    )


class Hunt(Base):
    """Chasse : jeu de conditions enregistré + infos de dernière exécution."""
    __tablename__ = "hunts"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[str] = mapped_column(String(10), default="both")  # alert/suricata/both
    conditions: Mapped[str] = mapped_column(Text, default="[]")      # JSON : [{field, op, value}]
    created_by: Mapped[str] = mapped_column(String(100), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    last_run_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_run_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


# ── R3 — Notifications : canaux + déduplication ──

class NotificationChannel(Base):
    """Canal de notification (email/webhook/telegram/slack) configuré par tenant.

    config = JSON chiffré (Fernet) ; les clés secrètes finissent par "_secret".
    """
    __tablename__ = "notification_channels"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    name: Mapped[str] = mapped_column(String(100))
    channel_type: Mapped[str] = mapped_column(String(20), index=True)
    config: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=10)
    dedup_window_seconds: Mapped[int] = mapped_column(Integer, default=300)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    __table_args__ = (Index("ix_channels_tenant_name", "tenant_id", "name", unique=True),)


class NotificationDedup(Base):
    """Empreinte de notification déjà envoyée (fenêtre de déduplication par canal)."""
    __tablename__ = "notification_dedup"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    channel_id: Mapped[int] = mapped_column(Integer, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    __table_args__ = (Index("ix_dedup_fp_channel", "fingerprint", "channel_id", unique=True),)


class FaceLoginRequest(Base):
    """Demande d'approbation de connexion faciale — analyste requiert validation admin."""
    __tablename__ = "face_login_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class UnverifiedFaceAttempt(Base):
    """Capture silencieuse d'un visage inconnu lors d'une tentative de connexion faciale."""
    __tablename__ = "unverified_face_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    face_image: Mapped[str | None] = mapped_column(Text, nullable=True)
    capture_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_unverified_face_attempts_tenant_capture", "tenant_id", "capture_time"),
    )


class RegistrationRequest(Base):
    """Demande d'inscription — l'analyste requiert validation admin avant activation du compte."""
    __tablename__ = "registration_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    username: Mapped[str] = mapped_column(String(100), index=True)
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    face_image: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    payload_preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    __table_args__ = (Index("ix_honeypot_tenant_port", "tenant_id", "port"),)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os: Mapped[str | None] = mapped_column(String(128), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    seq: Mapped[int] = mapped_column(BigInteger, default=0)
    capabilities: Mapped[str | None] = mapped_column(Text, nullable=True)


class AgentTelemetryEvent(Base):
    __tablename__ = "agent_telemetry_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[str] = mapped_column(Text)
    ts: Mapped[str | None] = mapped_column(String(64), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AgentOrder(Base):
    __tablename__ = "agent_orders"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    action_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    params: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentAiAnalysis(Base):
    __tablename__ = "agent_ai_analyses"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), index=True, default="default")
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    severity_count: Mapped[int] = mapped_column(Integer)
    alert_ids: Mapped[str] = mapped_column(Text)  # JSON array serialized
    model: Mapped[str] = mapped_column(String(255))
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def alert_ids_parse(self) -> list[int]:
        try:
            return json.loads(self.alert_ids) if self.alert_ids else []
        except (json.JSONDecodeError, TypeError):
            return []


def ensure_agent_ai_analyses(db):
    """Idempotent: verify agent_ai_analyses table columns exist."""
    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(db.bind)
    if "agent_ai_analyses" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("agent_ai_analyses")}
    for col in ["tenant_id", "agent_id", "severity_count", "alert_ids", "model",
                 "response", "status", "error", "created_at", "analyzed_at"]:
        if col not in existing:
            try:
                with db.bind.begin() as conn:
                    conn.execute(text(f"ALTER TABLE agent_ai_analyses ADD COLUMN {col} TEXT"))
            except Exception:
                pass
    db.commit()
