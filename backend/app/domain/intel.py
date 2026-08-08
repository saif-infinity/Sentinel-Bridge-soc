"""F3 — Threat intelligence : cache des verdicts par IP (dialect-aware)."""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, UniqueConstraint

from ..db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    provider = Column(String(32), nullable=False, default="abuseipdb")
    verdict = Column(String(16), nullable=False, default="unknown")  # malicious|suspicious|clean|unknown
    risk_score = Column(Integer, nullable=True)                      # 0-100
    source_name = Column(String(64), nullable=True)
    raw_json = Column(Text, nullable=True)
    checked_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "ip", "provider", name="uq_intel_tenant_ip_provider"),
    )
