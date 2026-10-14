import asyncio
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import psutil
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id, query_with_tenant
from ...models import AccessLog, ActionLog, Alert, NetworkSensor, SuricataAlert
from ...schemas import NetworkSensorCreate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sensors", tags=["sensors"])


@router.post("/record", dependencies=[Depends(get_api_key_or_jwt)])
async def record_bandwidth(request: Request, data: NetworkSensorCreate, db: Session = Depends(get_db)):
    """Record a bandwidth reading for an analyst station."""
    sensor = NetworkSensor(
        username=data.username,
        ip_address=data.ip_address,
        bytes_sent=data.bytes_sent,
        bytes_recv=data.bytes_recv,
        bandwidth_mbps=data.bandwidth_mbps,
        interface=data.interface,
        tenant_id=get_tenant_id(request),
    )
    db.add(sensor)
    db.commit()
    return {"status": "recorded", "id": sensor.id}


@router.get("/analyst/{username}")
async def get_analyst_bandwidth(
    request: Request,
    username: str,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    _user: Any = Depends(has_scopes_or_api_key(["devices:read"])),
):
    """Get bandwidth readings for a specific analyst over the last N hours."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    readings = (
        query_with_tenant(NetworkSensor, request, db)
        .filter(NetworkSensor.username == username, NetworkSensor.timestamp >= since)
        .order_by(desc(NetworkSensor.timestamp))
        .limit(200)
        .all()
    )
    return [
        {
            "id": r.id,
            "username": r.username,
            "ip_address": r.ip_address,
            "bytes_sent": r.bytes_sent,
            "bytes_recv": r.bytes_recv,
            "bandwidth_mbps": r.bandwidth_mbps,
            "interface": r.interface,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in readings
    ]


@router.get("/analysts")
async def get_all_bandwidth(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    _user: Any = Depends(has_scopes_or_api_key(["devices:read"])),
):
    """Get the latest bandwidth snapshot for each online analyst + system."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    online_users = (
        query_with_tenant(AccessLog, request, db)
        .with_entities(AccessLog.username, AccessLog.ip_address)
        .filter(AccessLog.is_online == True)
        .all()
    )
    usernames = [(u, ip) for u, ip in online_users]

    system_latest = (
        query_with_tenant(NetworkSensor, request, db)
        .filter(
            NetworkSensor.username == "__server__",
            NetworkSensor.timestamp >= since,
        )
        .order_by(desc(NetworkSensor.timestamp))
        .first()
    )

    results = []

    if system_latest:
        sys_count = (
            query_with_tenant(NetworkSensor, request, db)
            .filter(NetworkSensor.username == "__server__", NetworkSensor.timestamp >= since)
            .count()
        )
        results.append({
            "username": "Serveur SOC",
            "ip_address": "127.0.0.1",
            "latest_bandwidth_mbps": system_latest.bandwidth_mbps,
            "latest_bytes_sent": system_latest.bytes_sent,
            "latest_bytes_recv": system_latest.bytes_recv,
            "latest_interface": system_latest.interface,
            "latest_timestamp": system_latest.timestamp.isoformat(),
            "reading_count": sys_count,
        })

    for username, ip_address in usernames:
        latest = (
            query_with_tenant(NetworkSensor, request, db)
            .filter(
                NetworkSensor.username == username,
                NetworkSensor.timestamp >= since,
            )
            .order_by(desc(NetworkSensor.timestamp))
            .first()
        )
        count = (
            query_with_tenant(NetworkSensor, request, db)
            .filter(
                NetworkSensor.username == username,
                NetworkSensor.timestamp >= since,
            )
            .count()
        )
        results.append({
            "username": username,
            "ip_address": ip_address,
            "latest_bandwidth_mbps": latest.bandwidth_mbps if latest else 0.0,
            "latest_bytes_sent": latest.bytes_sent if latest else 0,
            "latest_bytes_recv": latest.bytes_recv if latest else 0,
            "latest_interface": latest.interface if latest else None,
            "latest_timestamp": latest.timestamp.isoformat() if latest else None,
            "reading_count": count,
        })

    return results


# ──────────────────────────────────────────────────────────
#  COMPREHENSIVE SYSTEM HEALTH ENDPOINT
# ──────────────────────────────────────────────────────────

@router.get("/health")
async def get_system_health(
    request: Request,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    """Full system health: resources, services, alerts, errors, actions."""

    now = datetime.now(UTC)
    today_start = datetime(now.year, now.month, now.day)

    # ── System Resources (psutil) ──
    cpu_percent = psutil.cpu_percent(interval=0.3)
    cpu_count = psutil.cpu_count()
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    net_io = psutil.net_io_counters()
    load_avg = os.getloadavg()

    # Process count
    proc_count = len(psutil.pids())

    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    # ── Service Status ──
    # Check PostgreSQL
    pg_running = False
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.laddr.port == 5432 and conn.status == "LISTEN":
                    pg_running = True
                    break
            except AttributeError:
                pass
    except (psutil.AccessDenied, PermissionError):
        pg_running = True

    # Check Redis
    redis_running = False
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.laddr.port == 6379 and conn.status == "LISTEN":
                    redis_running = True
                    break
            except AttributeError:
                pass
    except (psutil.AccessDenied, PermissionError):
        redis_running = True

    # Check Ollama
    ollama_running = False
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.laddr.port == 11434 and conn.status == "LISTEN":
                    ollama_running = True
                    break
            except AttributeError:
                pass
    except (psutil.AccessDenied, PermissionError):
        pass
    except Exception:
        pass

    # Check Celery
    celery_running = False
    try:
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or [])
                if "celery" in cmdline.lower():
                    celery_running = True
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass

    # ── Database Counts ──
    today_alerts = query_with_tenant(Alert, request, db).filter(Alert.timestamp >= today_start).count()
    critical_alerts = query_with_tenant(Alert, request, db).filter(Alert.severity >= 7).count()
    total_alerts = query_with_tenant(Alert, request, db).count()

    today_suricata = query_with_tenant(SuricataAlert, request, db).filter(SuricataAlert.timestamp >= today_start).count()
    critical_suricata = query_with_tenant(SuricataAlert, request, db).filter(SuricataAlert.severity <= 1).count()

    online_users = query_with_tenant(AccessLog, request, db).filter(AccessLog.is_online == True).count()
    today_logins = query_with_tenant(AccessLog, request, db).filter(AccessLog.login_time >= today_start).count()

    today_actions = query_with_tenant(ActionLog, request, db).filter(ActionLog.timestamp >= today_start).count()

    # ── Recent Errors (from ActionLog with delete or failure patterns) ──
    recent_errors = (
        query_with_tenant(ActionLog, request, db)
        .filter(
            ActionLog.timestamp >= now - timedelta(hours=1),
            ActionLog.action.like("%delete%"),
        )
        .order_by(desc(ActionLog.timestamp))
        .limit(10)
        .all()
    )

    error_list = [
        {
            "username": e.username,
            "action": e.action,
            "details": e.details,
            "timestamp": e.timestamp.isoformat(),
        }
        for e in recent_errors
    ]

    # ── Recent Alerts (latest 10 critical) ──
    recent_alerts_q = (
        query_with_tenant(Alert, request, db)
        .order_by(desc(Alert.timestamp))
        .limit(10)
        .all()
    )
    recent_alerts = [
        {
            "description": a.description,
            "severity": a.severity,
            "src_ip": a.src_ip,
            "agent_id": a.agent_id,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in recent_alerts_q
    ]

    # ── Recent Suricata Alerts ──
    recent_suricata_q = (
        query_with_tenant(SuricataAlert, request, db)
        .order_by(desc(SuricataAlert.timestamp))
        .limit(10)
        .all()
    )
    recent_suricata_alerts = [
        {
            "event_type": s.event_type,
            "src_ip": s.src_ip,
            "dest_ip": s.dest_ip,
            "alert_msg": s.alert_msg,
            "severity": s.severity,
            "timestamp": s.timestamp.isoformat(),
        }
        for s in recent_suricata_q
    ]

    # ── Recent Actions (latest 15) ──
    recent_actions_q = (
        query_with_tenant(ActionLog, request, db)
        .order_by(desc(ActionLog.timestamp))
        .limit(15)
        .all()
    )
    recent_actions = [
        {
            "username": a.username,
            "action": a.action,
            "resource": a.resource,
            "ip_address": a.ip_address,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in recent_actions_q
    ]

    return {
        "timestamp": now.isoformat(),
        "resources": {
            "cpu_percent": round(cpu_percent, 1),
            "cpu_count": cpu_count,
            "cpu_freq_mhz": round(cpu_freq.current, 0) if cpu_freq else None,
            "load_avg_1m": round(load_avg[0], 2),
            "load_avg_5m": round(load_avg[1], 2),
            "load_avg_15m": round(load_avg[2], 2),
            "memory_percent": round(mem.percent, 1),
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "swap_percent": round(swap.percent, 1),
            "disk_percent": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "net_sent_gb": round(net_io.bytes_sent / (1024**3), 2),
            "net_recv_gb": round(net_io.bytes_recv / (1024**3), 2),
            "net_mbps": round(
                (net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024), 2
            ),
            "process_count": proc_count,
            "uptime_seconds": uptime_seconds,
        },
        "services": {
            "postgresql": pg_running,
            "redis": redis_running,
            "celery": celery_running,
            "ollama": ollama_running,
        },
        "stats": {
            "online_users": online_users,
            "today_logins": today_logins,
            "today_actions": today_actions,
            "today_alerts": today_alerts,
            "critical_alerts": critical_alerts,
            "total_alerts": total_alerts,
            "today_suricata": today_suricata,
            "critical_suricata": critical_suricata,
        },
        "recent_alerts": recent_alerts,
        "recent_suricata": recent_suricata_alerts,
        "recent_actions": recent_actions,
        "recent_errors": error_list,
    }


async def sample_bandwidth_for_online_analysts(db_factory):
    """Background task: periodically sample server bandwidth and record per-analyst readings."""
    prev_io = psutil.net_io_counters()
    prev_time = datetime.now(UTC).timestamp()

    while True:
        try:
            await asyncio.sleep(10)

            curr_io = psutil.net_io_counters()
            curr_time = datetime.now(UTC).timestamp()
            interval = curr_time - prev_time
            if interval <= 0:
                continue

            total_sent = curr_io.bytes_sent - prev_io.bytes_sent
            total_recv = curr_io.bytes_recv - prev_io.bytes_recv
            total_mbps = ((total_sent + total_recv) / (1024 * 1024)) / interval

            prev_io = curr_io
            prev_time = curr_time

            db = db_factory()
            try:
                online = (
                    db.query(AccessLog.username, AccessLog.ip_address, AccessLog.tenant_id)
                    .filter(AccessLog.is_online == True)
                    .all()
                )

                if online:
                    for username, ip_address, tenant_id in online:
                        per_user_mbps = total_mbps / len(online)
                        sensor = NetworkSensor(
                            username=username,
                            ip_address=ip_address,
                            tenant_id=tenant_id,
                            bytes_sent=int(total_sent / len(online)),
                            bytes_recv=int(total_recv / len(online)),
                            bandwidth_mbps=round(per_user_mbps, 3),
                            interface="all",
                        )
                        db.add(sensor)
                else:
                    sensor = NetworkSensor(
                        username="__server__",
                        ip_address="127.0.0.1",
                        tenant_id="default",
                        bytes_sent=int(total_sent),
                        bytes_recv=int(total_recv),
                        bandwidth_mbps=round(total_mbps, 3),
                        interface="all",
                    )
                    db.add(sensor)

                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning("Bandwidth sampling error: %s", e)
