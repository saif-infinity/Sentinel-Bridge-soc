import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from ...db import get_db, get_tenant_id
from ...domain.models import Agent, AgentTelemetryEvent, AgentOrder
from ...core.config import settings
from ...application.source_control import is_source_enabled
from ...auth import get_api_key_or_jwt
from ...application.system_config import get_all_settings
from ...application.pipeline import ingest_alert
from ...application.normalization import normalize_event, to_pipeline_payload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent"])

_agent_action_types = {"block_ip", "unblock_ip", "kill_process", "quarantine_file", "terminate_session", "restart_service"}

# Max lengths of the corresponding `Agent` columns. Values coming from agents are
# clipped defensively: e.g. the agent sends the full `/proc/version` (~200 chars)
# while `Agent.os` is VARCHAR(128) — an unclipped value makes Postgres raise and
# the endpoint answer 500, so the agent could never register.
_AGENT_FIELD_MAX = {"agent_id": 64, "hostname": 255, "os": 128, "arch": 64, "version": 64}


def _clip(value: Any, max_len: int) -> Optional[str]:
    """Truncate a possibly-oversized value so it fits its DB column (never raises)."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= max_len else text[:max_len]


async def agent_auth(
    api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization"),
):
    if api_key and api_key == settings.API_KEY.get_secret_value():
        return api_key
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token == settings.API_KEY.get_secret_value():
            return token
    raise HTTPException(status_code=403, detail="Could not validate credentials")


# ── READ routes (platform JWT or API key) ──────────────────────

@router.post("/orders", dependencies=[Depends(get_api_key_or_jwt)])
async def create_order(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    agent_id = body.get("agent_id")
    action_type = body.get("action_type")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id est requis")
    if not action_type or action_type not in _agent_action_types:
        raise HTTPException(
            status_code=400,
            detail="action_type invalide. Valeurs autorisées : " + ", ".join(sorted(_agent_action_types)),
        )

    order = AgentOrder(
        id=str(uuid.uuid4()),
        tenant_id=get_tenant_id(request),
        agent_id=agent_id,
        action_type=action_type,
        target=body.get("target"),
        params=json.dumps(body.get("params")) if body.get("params") is not None else None,
        status="pending",
        created_at=datetime.now(timezone.utc),
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    return {
        "status": "ok",
        "order": {
            "id": order.id,
            "agent_id": order.agent_id,
            "action_type": order.action_type,
            "target": order.target,
            "params": json.loads(order.params) if order.params else None,
            "status": order.status,
            "created_at": order.created_at.isoformat(),
        },
    }


@router.get("/orders/history", dependencies=[Depends(get_api_key_or_jwt)])
async def get_orders_history(
    agent_id: str = Query(...),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AgentOrder)
        .filter(AgentOrder.agent_id == agent_id)
        .order_by(desc(AgentOrder.created_at))
        .limit(limit)
        .all()
    )
    result = []
    for row in rows:
        result.append({
            "id": row.id,
            "agent_id": row.agent_id,
            "action_type": row.action_type,
            "target": row.target,
            "params": json.loads(row.params) if row.params else None,
            "status": row.status,
            "output": row.output,
            "error": row.error,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        })
    return {"orders": result}


# ── AGENT routes (X-API-Key / Bearer == API_KEY) ──────────────

@router.post("/register", dependencies=[Depends(agent_auth)])
async def register_agent(
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    agent_id = data.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    now = datetime.now(timezone.utc)
    existing = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if existing:
        existing.hostname = _clip(data.get("hostname", existing.hostname), 255)
        existing.os = _clip(data.get("os", existing.os), 128)
        existing.arch = _clip(data.get("arch", existing.arch), 64)
        existing.version = _clip(data.get("version", existing.version), 64)
        if "capabilities" in data:
            existing.capabilities = json.dumps(data["capabilities"], ensure_ascii=False)
        existing.last_seen = now
        db.commit()
    else:
        agent = Agent(
            agent_id=agent_id,
            hostname=_clip(data.get("hostname"), 255),
            os=_clip(data.get("os"), 128),
            arch=_clip(data.get("arch"), 64),
            version=_clip(data.get("version"), 64),
            registered_at=now,
            last_seen=now,
            capabilities=json.dumps(data["capabilities"], ensure_ascii=False) if data.get("capabilities") else None,
        )
        db.add(agent)
        db.commit()

    # Fetch host_agent config
    try:
        all_settings = get_all_settings(db, tenant_id=get_tenant_id(request))
        host_agent_fields = all_settings.get("host_agent", {}).get("fields", {})
        config = {k: v["value"] for k, v in host_agent_fields.items()}
    except Exception:
        config = {}

    return {"status": "ok", "agent_id": agent_id, "config": config}


@router.post("/telemetry", dependencies=[Depends(agent_auth)])
async def receive_telemetry(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    agent_id = body.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    seq = body.get("seq", 0)
    now = datetime.now(timezone.utc)

    # Upsert Agent row
    existing = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if existing:
        existing.last_seen = now
        existing.seq = max(existing.seq, seq)
        for key in ("hostname", "os", "arch", "version"):
            if key in body:
                setattr(existing, key, _clip(body[key], _AGENT_FIELD_MAX[key]))
    else:
        agent = Agent(
            agent_id=agent_id,
            hostname=_clip(body.get("hostname"), 255),
            os=_clip(body.get("os"), 128),
            arch=_clip(body.get("arch"), 64),
            version=_clip(body.get("version"), 64),
            registered_at=now,
            last_seen=now,
            seq=seq,
        )
        db.add(agent)

    # Process each telemetry category array
    category_map = {
        "system_logs": "system_log",
        "ssh_sessions": "ssh_session",
        "processes": "process",
        "ping_events": "ping_event",
        "security_events": "security_event",
        "misconfigs": "misconfig",
        "errors": "error",
    }
    count = 0
    for cat_key, category in category_map.items():
        items = body.get(cat_key, [])
        if not isinstance(items, list):
            continue
        for item in items:
            event = AgentTelemetryEvent(
                agent_id=agent_id,
                category=category,
                payload=json.dumps(item, ensure_ascii=False),
                ts=item.get("ts") if isinstance(item, dict) else None,
                received_at=now,
            )
            db.add(event)
            count += 1

    # Handle machine_state if present and not null
    machine_state = body.get("machine_state")
    if machine_state is not None:
        event = AgentTelemetryEvent(
            agent_id=agent_id,
            category="machine_state",
            payload=json.dumps(machine_state, ensure_ascii=False),
            ts=None,
            received_at=now,
        )
        db.add(event)
        count += 1

    db.commit()

    # ── Forward security events and misconfigs to SOC pipeline ──
    if is_source_enabled(db, "host_agent", tenant_id=get_tenant_id(request)):
        tenant_id = get_tenant_id(request)
        _forward_to_pipeline(agent_id, body.get("security_events", []), db, "security_event", tenant_id)
        _forward_to_pipeline(agent_id, body.get("misconfigs", []), db, "misconfig", tenant_id)
    # Errors are NOT forwarded to the pipeline: ~99 unique journald error lines
    # per 30s batch would each create a separate alert (~285k/day). They remain
    # stored in agent_telemetry_events and visible in the UI.

    return {"status": "ok", "received": count}


def _forward_to_pipeline(agent_id: str, items: list, db: Session, category: str, tenant_id: str):
    """Forward items to the SOC pipeline (best-effort, never fails telemetry)."""
    if not is_source_enabled(db, "host_agent", tenant_id=tenant_id):
        return
    forwarded = 0
    max_forward = 50
    for item in items:
        if not isinstance(item, dict):
            continue
        # Skip non-detections for security events
        if category == "security_event":
            event_type = item.get("event_type")
            if not event_type or event_type in ("other", "unknown"):
                continue
        # Safety valve: cap forwarded items at 50 per batch
        if forwarded >= max_forward:
            dropped = len(items) - forwarded
            logger.warning("agent: forwarded %d/%d %s items, dropped %d", forwarded, len(items), category, dropped)
            break
        raw = {
            "source": item.get("source", "host-agent"),
            "severity": item.get("severity"),
            "timestamp": item.get("ts") or item.get("timestamp"),
            "description": item.get("detail") or item.get("summary") or item.get("description"),
            "src_ip": item.get("src_ip"),
            "dest_ip": item.get("dest_ip"),
            "proto": item.get("proto"),
            "agent_id": agent_id,
            "category": category,
            "event.type": item.get("event_type") or item.get("check"),
            "type": item.get("event_type") or item.get("check"),
            "raw": item,
            "tenant_id": tenant_id,
        }
        try:
            canonical = normalize_event(raw, "host-agent")
            pipeline_payload = to_pipeline_payload(canonical, "host-agent")
            pipeline_payload["agent_id"] = agent_id
            pipeline_payload["source"] = "host-agent"
            ingest_alert(pipeline_payload, db=db)
            forwarded += 1
        except Exception as e:
            logger.warning("agent: pipeline forward failed for item in %s: %s", item.get("source", "unknown"), str(e))


@router.get("/status", dependencies=[Depends(get_api_key_or_jwt)])
async def get_status(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    agents = (
        db.query(Agent)
        .order_by(desc(Agent.last_seen))
        .all()
    )
    result = []
    for agent in agents:
        online = agent.last_seen is not None and (now - agent.last_seen).total_seconds() < 90
        process_count = (
            db.query(func.count(AgentTelemetryEvent.id))
            .filter(AgentTelemetryEvent.agent_id == agent.agent_id, AgentTelemetryEvent.category == "process")
            .scalar() or 0
        )
        event_count = (
            db.query(func.count(AgentTelemetryEvent.id))
            .filter(AgentTelemetryEvent.agent_id == agent.agent_id, AgentTelemetryEvent.category == "event")
            .scalar() or 0
        )
        result.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "os": agent.os,
            "arch": agent.arch,
            "version": agent.version,
            "tenant_id": agent.tenant_id,
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "capabilities": json.loads(agent.capabilities) if agent.capabilities else None,
            "online": online,
            "process_count": process_count,
            "event_count": event_count,
        })
    return result


@router.get("/processes", dependencies=[Depends(get_api_key_or_jwt)])
async def get_processes(
    limit: int = Query(200, ge=1, le=1000),
    agent_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = (
        db.query(AgentTelemetryEvent)
        .filter(AgentTelemetryEvent.category == "process")
        .order_by(desc(AgentTelemetryEvent.received_at))
    )
    if agent_id:
        query = query.filter(AgentTelemetryEvent.agent_id == agent_id)
    events = query.limit(limit).all()
    result = []
    for ev in events:
        try:
            payload = json.loads(ev.payload)
        except (json.JSONDecodeError, TypeError):
            payload = {}
        result.append({
            "agent_id": ev.agent_id,
            "pid": payload.get("pid"),
            "name": payload.get("name"),
            "user": payload.get("user"),
            "cmdline": payload.get("cmdline"),
            "cpu_pct": payload.get("cpu_pct"),
            "mem_kb": payload.get("mem_kb"),
            "ts": ev.ts,
        })
    return result


@router.get("/events", dependencies=[Depends(get_api_key_or_jwt)])
async def get_events(
    limit: int = Query(100, ge=1, le=500),
    agent_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None, description="Filtre par catégorie, ex. 'misconfig'"),
    db: Session = Depends(get_db),
):
    event_categories = [
        "ping_event", "security_event", "system_log",
        "ssh_session", "misconfig", "error",
    ]
    query = (
        db.query(AgentTelemetryEvent)
        .filter(AgentTelemetryEvent.category.in_(event_categories))
        .order_by(desc(AgentTelemetryEvent.received_at))
    )
    if agent_id:
        query = query.filter(AgentTelemetryEvent.agent_id == agent_id)
    # A single telemetry batch inserts ~900 rows sharing the same received_at, so under
    # LIMIT the newest rows order arbitrarily: without a category filter the handful of
    # `misconfig` rows get truncated away and never reach the UI.
    if category:
        query = query.filter(AgentTelemetryEvent.category == category)
    events = query.limit(limit).all()
    result = []
    for ev in events:
        try:
            payload = json.loads(ev.payload)
        except (json.JSONDecodeError, TypeError):
            payload = {}
        result.append({
            "agent_id": ev.agent_id,
            "category": ev.category,
            "ts": ev.ts,
            "severity": payload.get("severity"),
            "source": payload.get("source"),
            # Batch id: every row of one telemetry batch shares it. The UI needs it to
            # separate the CURRENT state (latest scan) from the accumulated history.
            "received_at": ev.received_at.isoformat() if ev.received_at else None,
            "payload": payload,
        })
    return result


@router.get("/orders", dependencies=[Depends(agent_auth)])
async def get_pending_orders(
    agent_id: str = Query(...),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AgentOrder)
        .filter(AgentOrder.agent_id == agent_id, AgentOrder.status == "pending")
        .order_by(desc(AgentOrder.created_at))
        .limit(limit)
        .all()
    )
    now = datetime.now(timezone.utc)
    for row in rows:
        row.status = "dispatched"
        row.dispatched_at = now
    if rows:
        db.commit()

    result = []
    for row in rows:
        result.append({
            "id": row.id,
            "action_type": row.action_type,
            "target": row.target,
            "params": json.loads(row.params) if row.params else None,
            # Required by the agent's OrdersResponse/OrderItem DTO: without it the
            # agent fails to decode ("missing field `created_at`") and the order
            # stays stuck in `dispatched`.
            "created_at": row.created_at.isoformat(),
        })
    return {"orders": result}


@router.post("/orders/{order_id}/result", dependencies=[Depends(agent_auth)])
async def submit_order_result(
    order_id: str,
    body: dict,
    db: Session = Depends(get_db),
):
    row = db.query(AgentOrder).filter(AgentOrder.id == order_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Ordre introuvable")

    status = body.get("status", "done")
    if status not in ("done", "error"):
        status = "done"

    row.status = status
    row.output = body.get("output")
    row.error = body.get("error")
    row.completed_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "ok"}
