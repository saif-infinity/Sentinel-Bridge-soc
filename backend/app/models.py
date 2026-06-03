from sqlalchemy import String, Boolean, DateTime, ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from .db import Base

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str | None] = mapped_column(String(45), unique=True, index=True, nullable=True)
    mac: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=False)
    is_wazuh_agent: Mapped[bool] = mapped_column(Boolean, default=False)
    logs = relationship("ConnectionLog", back_populates="device")

class ConnectionLog(Base):
    __tablename__ = "connection_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    status: Mapped[bool] = mapped_column(Boolean, index=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    device = relationship("Device", back_populates="logs")

class SuricataAlert(Base):
    __tablename__ = "suricata_alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    proto: Mapped[str | None] = mapped_column(String(20))
    alert_msg: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[int] = mapped_column(Integer, default=3)
    payload: Mapped[str | None] = mapped_column(String(1000), nullable=True)

class AnomalyModel(Base):
    __tablename__ = "anomalies"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=datetime.utcnow)
    severity: Mapped[int] = mapped_column(Integer, index=True) # 1, 2, 3
    category: Mapped[str] = mapped_column(String(50), index=True)
    title: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(String(500))
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    employee_name: Mapped[str] = mapped_column(String(100))
    department: Mapped[str] = mapped_column(String(100))

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=datetime.utcnow)
    description: Mapped[str] = mapped_column(String(500))
    severity: Mapped[int] = mapped_column(Integer, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(10), nullable=True)

class IaReport(Base):
    __tablename__ = "ia_reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    report_type: Mapped[str] = mapped_column(String(50), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(10), nullable=True)
    content: Mapped[str] = mapped_column(Text)

Index("ix_logs_time_range", ConnectionLog.start_time, ConnectionLog.end_time)