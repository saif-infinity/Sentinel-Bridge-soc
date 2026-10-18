import hashlib
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from ...application.normalization import normalize_event, to_pipeline_payload
from ...application.pipeline import ingest_alert
from ...application.source_control import is_source_enabled
from ...application.system_config import get_all_settings
from ...auth import get_api_key_or_jwt
from ...core.config import settings
from ...db import get_db, get_tenant_id
from ...domain.agent_tokens import generate_token, hash_token, verify_token
from ...domain.models import Agent, AgentOrder, AgentTelemetryEvent, AgentToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent"])

_agent_action_types = {"block_ip", "unblock_ip", "kill_process", "quarantine_file", "terminate_session", "restart_service"}

# Max lengths of the corresponding `Agent` columns.
_AGENT_FIELD_MAX = {"agent_id": 64, "hostname": 255, "os": 128, "arch": 64, "version": 64}


def _clip(value: Any, max_len: int) -> str | None:
    """Truncate a possibly-oversized value so it fits its DB column (never raises)."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= max_len else text[:max_len]


def _client_ip(request: Request) -> str | None:
    """Resolve client IP respecting proxy config."""
    # Check X-Forwarded-For if TRUST_PROXY_HEADERS
    if settings.TRUST_PROXY_HEADERS:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()[:45]
    try:
        return request.client.host if request.client else None
    except Exception:
        return None


# ── Agent auth: API_KEY global (legacy) OR per-agent token (hash) ──────

async def agent_auth(
    request: Request,
    api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization"),
    x_agent_token: str = Header(None, alias="X-Agent-Token"),
    db: Session = Depends(get_db),
):
    # 1. X-Agent-Token header → per-agent token
    if x_agent_token:
        token_hash = hashlib.sha256(x_agent_token.encode()).hexdigest()
        row = db.query(AgentToken).filter(
            AgentToken.token_hash == token_hash,
            AgentToken.is_revoked == False,  # noqa: E712
        ).first()
        if row:
            # Update last_used
            row.last_used_at = datetime.now(UTC)
            row.last_ip = _client_ip(request)
            db.commit()
            # Optionally also set tenant context
            request.state.tenant_id = row.tenant_id
            return x_agent_token
        raise HTTPException(status_code=403, detail="Token agent invalide ou révoqué")

    # 2. Authorization Bearer <token> → try per-agent token first, then global API_KEY
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            # Try per-agent token
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            row = db.query(AgentToken).filter(
                AgentToken.token_hash == token_hash,
                AgentToken.is_revoked == False,  # noqa: E712
            ).first()
            if row:
                row.last_used_at = datetime.now(UTC)
                row.last_ip = _client_ip(request)
                db.commit()
                request.state.tenant_id = row.tenant_id
                return token
            # Fallback global API_KEY
            if secrets.compare_digest(token, settings.API_KEY.get_secret_value()):
                return token

    # 3. X-API-Key legacy
    if api_key and secrets.compare_digest(api_key, settings.API_KEY.get_secret_value()):
        return api_key

    raise HTTPException(status_code=403, detail="Could not validate credentials")


# ── ADMIN routes (platform JWT or API key) ──────────────────────

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
        created_at=datetime.now(UTC),
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


# ── Agent enrollment (admin only) ──────────────────────────────────

@router.post("/enroll", dependencies=[Depends(get_api_key_or_jwt)])
async def enroll_agent(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Crée ou régénère un token pour un agent.
    Body: {agent_id (required), label?, expires_days?}
    Seul un admin/analyste du tenant peut enroller (gardé par ROUTER_POLICIES).
    Retourne le token en clair **une seule fois**.
    """
    agent_id = body.get("agent_id")
    if not agent_id or not isinstance(agent_id, str) or len(agent_id.strip()) == 0:
        raise HTTPException(status_code=400, detail="agent_id est requis (ex: pc-bureau-01)")
    agent_id = _clip(agent_id.strip(), 64)
    label = body.get("label") or body.get("hostname") or ""
    label = _clip(str(label), 100) if label else None
    tenant_id = get_tenant_id(request)

    # Révoquer anciens tokens actifs pour cet agent (rotation)
    existing_tokens = db.query(AgentToken).filter(
        AgentToken.agent_id == agent_id,
        AgentToken.tenant_id == tenant_id,
        AgentToken.is_revoked == False,  # noqa: E712
    ).all()
    for tok in existing_tokens:
        tok.is_revoked = True
        tok.revoked_at = datetime.now(UTC)
        tok.revoked_by = getattr(request.state, "user", None) or "enroll-rotation"

    # Générer nouveau token
    raw_token = generate_token(48)
    token_hash_val = hash_token(raw_token)
    expires_days = body.get("expires_days")
    expires_at = None
    if expires_days:
        try:
            days = int(expires_days)
            if 1 <= days <= 3650:
                from datetime import timedelta
                expires_at = datetime.now(UTC) + timedelta(days=days)
        except Exception:
            pass

    new_token = AgentToken(
        agent_id=agent_id,
        tenant_id=tenant_id,
        token_hash=token_hash_val,
        label=label,
        created_by=getattr(request.state, "user", None) or "api",
        expires_at=expires_at,
    )
    db.add(new_token)

    # Ensure Agent row exists (placeholder)
    existing_agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not existing_agent:
        agent = Agent(
            agent_id=agent_id,
            hostname=label,
            tenant_id=tenant_id,
            registered_at=datetime.now(UTC),
            last_seen=None,
            token_id=new_token.id,
            status="active",
        )
        db.add(agent)
    else:
        existing_agent.token_id = new_token.id
        existing_agent.status = "active"

    db.commit()

    return {
        "status": "ok",
        "agent_id": agent_id,
        "token": raw_token,  # à copier immédiatement, non stocké en clair
        "token_id": new_token.id,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "message": "Token à copier dans agent/config.json — il ne sera plus affiché.",
    }


@router.post("/revoke", dependencies=[Depends(get_api_key_or_jwt)])
async def revoke_agent(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    """Révoque un agent (tous ses tokens) et marque status=revoked."""
    agent_id = body.get("agent_id")
    token_id = body.get("token_id")
    tenant_id = get_tenant_id(request)

    if not agent_id and not token_id:
        raise HTTPException(status_code=400, detail="agent_id ou token_id requis")

    revoked_count = 0
    if token_id:
        row = db.query(AgentToken).filter(AgentToken.id == token_id).first()
        if row:
            row.is_revoked = True
            row.revoked_at = datetime.now(UTC)
            row.revoked_by = getattr(request.state, "user", None) or "api"
            revoked_count = 1
    else:
        rows = db.query(AgentToken).filter(
            AgentToken.agent_id == agent_id,
            AgentToken.tenant_id == tenant_id,
            AgentToken.is_revoked == False,  # noqa: E712
        ).all()
        for row in rows:
            row.is_revoked = True
            row.revoked_at = datetime.now(UTC)
            row.revoked_by = getattr(request.state, "user", None) or "api"
            revoked_count += 1
        # Mark agent revoked
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if agent:
            agent.status = "revoked"

    db.commit()
    return {"status": "ok", "revoked": revoked_count}


@router.get("/tokens", dependencies=[Depends(get_api_key_or_jwt)])
async def list_tokens(
    agent_id: str | None = Query(None),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Liste les tokens (sans valeur claire) pour audit."""
    tenant_id = get_tenant_id(request) if request else "default"
    q = db.query(AgentToken).filter(AgentToken.tenant_id == tenant_id)
    if agent_id:
        q = q.filter(AgentToken.agent_id == agent_id)
    rows = q.order_by(desc(AgentToken.created_at)).limit(200).all()
    return {"tokens": [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "label": r.label,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "last_ip": r.last_ip,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
            "is_revoked": r.is_revoked,
        } for r in rows
    ]}


# ── AGENT routes (X-Agent-Token / Bearer == API_KEY or per-agent token) ──────

@router.post("/register", dependencies=[Depends(agent_auth)])
async def register_agent(
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    agent_id = data.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    now = datetime.now(UTC)
    client_ip = _client_ip(request)
    existing = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if existing:
        if existing.status == "revoked":
            raise HTTPException(status_code=403, detail="Agent révoqué — contactez l'admin SOC")
        existing.hostname = _clip(data.get("hostname", existing.hostname), 255)
        existing.os = _clip(data.get("os", existing.os), 128)
        existing.arch = _clip(data.get("arch", existing.arch), 64)
        existing.version = _clip(data.get("version", existing.version), 64)
        if "capabilities" in data:
            existing.capabilities = json.dumps(data["capabilities"], ensure_ascii=False)
        existing.last_seen = now
        existing.last_ip = client_ip
        if "heartbeat_interval" in data:
            try:
                existing.heartbeat_interval = int(data["heartbeat_interval"])
            except Exception:
                pass
        db.commit()
    else:
        agent = Agent(
            agent_id=agent_id,
            hostname=_clip(data.get("hostname"), 255),
            os=_clip(data.get("os"), 128),
            arch=_clip(data.get("arch"), 64),
            version=_clip(data.get("version"), 64),
            tenant_id=get_tenant_id(request),
            registered_at=now,
            last_seen=now,
            last_ip=client_ip,
            capabilities=json.dumps(data["capabilities"], ensure_ascii=False) if data.get("capabilities") else None,
            status="active",
        )
        db.add(agent)
        db.commit()

    # Fetch host_agent config (serveur → agent : collecte configurable)
    try:
        all_settings = get_all_settings(db, tenant_id=get_tenant_id(request))
        host_agent_fields = all_settings.get("host_agent", {}).get("fields", {})
        config = {k: v["value"] for k, v in host_agent_fields.items()}
    except Exception:
        config = {}

    return {"status": "ok", "agent_id": agent_id, "config": config, "server_time": now.isoformat()}


@router.post("/heartbeat", dependencies=[Depends(agent_auth)])
async def heartbeat(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
):
    """Heartbeat léger — met à jour last_seen et retourne la config."""
    agent_id = body.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id required")

    now = datetime.now(UTC)
    client_ip = _client_ip(request)
    existing = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if existing:
        if existing.status == "revoked":
            raise HTTPException(status_code=403, detail="Agent révoqué")
        existing.last_seen = now
        existing.last_ip = client_ip
        if "hostname" in body:
            existing.hostname = _clip(body["hostname"], 255)
        if "version" in body:
            existing.version = _clip(body["version"], 64)
        # Collectors health from agent
        if "collectors" in body:
            try:
                existing.capabilities = json.dumps(body["collectors"], ensure_ascii=False)
            except Exception:
                pass
        db.commit()
    else:
        # Auto-create if enroll was skipped (lab mode with API_KEY)
        agent = Agent(
            agent_id=_clip(agent_id, 64),
            hostname=_clip(body.get("hostname"), 255),
            os=_clip(body.get("os"), 128),
            arch=_clip(body.get("arch"), 64),
            version=_clip(body.get("version"), 64),
            tenant_id=get_tenant_id(request),
            registered_at=now,
            last_seen=now,
            last_ip=client_ip,
            status="active",
        )
        db.add(agent)
        db.commit()

    # Return server config + pending orders count hint
    try:
        all_settings = get_all_settings(db, tenant_id=get_tenant_id(request))
        host_agent_fields = all_settings.get("host_agent", {}).get("fields", {})
        config = {k: v["value"] for k, v in host_agent_fields.items()}
    except Exception:
        config = {}

    pending_count = db.query(func.count(AgentOrder.id)).filter(
        AgentOrder.agent_id == agent_id, AgentOrder.status == "pending"
    ).scalar() or 0

    return {
        "status": "ok",
        "agent_id": agent_id,
        "server_time": now.isoformat(),
        "config": config,
        "pending_orders": pending_count,
    }


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
    try:
        seq = int(seq)
    except Exception:
        seq = 0
    now = datetime.now(UTC)
    client_ip = _client_ip(request)

    # Upsert Agent row
    existing = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if existing:
        if existing.status == "revoked":
            raise HTTPException(status_code=403, detail="Agent révoqué")
        # Déduplication côté agent: si seq déjà vu (>=), on ack sans réinsérer
        # mais on met à jour last_seen pour ne pas marquer offline
        if seq != 0 and seq <= existing.seq:
            return {"status": "ok", "received": 0, "ack_seq": existing.seq, "deduped": True, "message": "seq déjà traité"}
        existing.last_seen = now
        existing.last_ip = client_ip
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
            tenant_id=get_tenant_id(request),
            registered_at=now,
            last_seen=now,
            last_ip=client_ip,
            seq=seq,
            status="active",
        )
        db.add(agent)

    # Process each telemetry category array — étendu pour collecte configurable
    category_map = {
        "system_logs": "system_log",
        "auth_logs": "auth_log",
        "ssh_sessions": "ssh_session",
        "processes": "process",
        "network_connections": "network_connection",
        "network_logs": "network_connection",
        "ping_events": "ping_event",
        "security_events": "security_event",
        "misconfigs": "misconfig",
        "errors": "error",
        "auth_events": "auth_event",
    }
    count = 0
    deduped_skipped = 0  # future: hash-based dedup before insert
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

    # ── Forward to SOC pipeline ──
    forwarded = 0
    if is_source_enabled(db, "host_agent", tenant_id=get_tenant_id(request)):
        tenant_id = get_tenant_id(request)
        # Anciennes catégories
        forwarded += _forward_to_pipeline(agent_id, body.get("security_events", []), db, "security_event", tenant_id)
        forwarded += _forward_to_pipeline(agent_id, body.get("misconfigs", []), db, "misconfig", tenant_id)
        # Nouvelles catégories lab
        forwarded += _forward_to_pipeline(agent_id, body.get("system_logs", []), db, "system_log", tenant_id, source="host-agent")
        forwarded += _forward_to_pipeline(agent_id, body.get("auth_logs", []), db, "auth_log", tenant_id, source="host-agent")
        forwarded += _forward_to_pipeline(agent_id, body.get("auth_events", []), db, "auth_log", tenant_id, source="host-agent")
        forwarded += _forward_to_pipeline(agent_id, body.get("network_connections", []), db, "network_connection", tenant_id, source="host-agent")
        forwarded += _forward_to_pipeline(agent_id, body.get("network_logs", []), db, "network_connection", tenant_id, source="host-agent")
    # Errors are NOT forwarded to the pipeline

    # Ack fiable: le client peut purger sa file locale jusqu'à seq
    # Use current stored seq
    ack_seq = seq
    if existing:
        ack_seq = existing.seq
    return {"status": "ok", "received": count, "ack_seq": ack_seq, "forwarded": forwarded, "deduped": deduped_skipped}


def _forward_to_pipeline(agent_id: str, items: list, db: Session, category: str, tenant_id: str, source: str = "host-agent"):
    """Forward items to the SOC pipeline (best-effort, never fails telemetry)."""
    if not is_source_enabled(db, "host_agent", tenant_id=tenant_id):
        return 0
    if not items:
        return 0
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
        if forwarded >= max_forward:
            dropped = len(items) - forwarded
            logger.warning("agent: forwarded %d/%d %s items, dropped %d", forwarded, len(items), category, dropped)
            break
        # Construire raw normalisé — élargi pour supporter les nouvelles collectes
        raw = {
            "source": item.get("source", source),
            "severity": item.get("severity") or item.get("level") or 5,
            "timestamp": item.get("ts") or item.get("timestamp") or item.get("time"),
            "description": item.get("detail") or item.get("summary") or item.get("description") or item.get("msg") or item.get("message"),
            "src_ip": item.get("src_ip") or item.get("src") or item.get("client_ip"),
            "dest_ip": item.get("dest_ip") or item.get("dst") or item.get("server_ip"),
            "proto": item.get("proto") or item.get("protocol"),
            "agent_id": agent_id,
            "category": category,
            "event.type": item.get("event_type") or item.get("check") or item.get("type"),
            "type": item.get("event_type") or item.get("check") or item.get("type"),
            "host": {"name": item.get("hostname") or item.get("host")},
            "user": {"name": item.get("user") or item.get("username")},
            "raw": item,
            "tenant_id": tenant_id,
        }
        # Enrichir proto pour network
        if category == "network_connection" and not raw["proto"]:
            raw["proto"] = item.get("proto") or "tcp"
        try:
            canonical = normalize_event(raw, "host-agent")
            pipeline_payload = to_pipeline_payload(canonical, "host-agent")
            pipeline_payload["agent_id"] = agent_id
            pipeline_payload["source"] = "host-agent"
            # Preserve category for MITRE mapping in rules
            pipeline_payload["category"] = category
            ingest_alert(pipeline_payload, db=db)
            forwarded += 1
        except Exception as e:
            logger.warning("agent: pipeline forward failed for item in %s: %s", item.get("source", "unknown"), str(e))
    return forwarded


@router.get("/status", dependencies=[Depends(get_api_key_or_jwt)])
async def get_status(db: Session = Depends(get_db), request: Request = None):
    now = datetime.now(UTC)
    tenant_id = get_tenant_id(request) if request else "default"
    # Show only agents of this tenant, plus legacy "default" for migration
    agents = (
        db.query(Agent)
        .filter((Agent.tenant_id == tenant_id) | (Agent.tenant_id == "default"))
        .order_by(desc(Agent.last_seen))
        .all()
    )
    result = []
    for agent in agents:
        online = agent.last_seen is not None and (now - agent.last_seen).total_seconds() < 90
        # Respect revoked status
        if agent.status == "revoked":
            online = False
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
        # token info
        token_info = None
        if agent.token_id:
            tok = db.query(AgentToken).filter(AgentToken.id == agent.token_id).first()
            if tok:
                token_info = {
                    "id": tok.id,
                    "is_revoked": tok.is_revoked,
                    "created_at": tok.created_at.isoformat() if tok.created_at else None,
                    "last_used_at": tok.last_used_at.isoformat() if tok.last_used_at else None,
                }
        result.append({
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "os": agent.os,
            "arch": agent.arch,
            "version": agent.version,
            "tenant_id": agent.tenant_id,
            "registered_at": agent.registered_at.isoformat() if agent.registered_at else None,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "last_ip": agent.last_ip,
            "status": agent.status,
            "capabilities": json.loads(agent.capabilities) if agent.capabilities else None,
            "online": online,
            "process_count": process_count,
            "event_count": event_count,
            "seq": agent.seq,
            "token": token_info,
            "heartbeat_interval": agent.heartbeat_interval,
        })
    return result


@router.get("/processes", dependencies=[Depends(get_api_key_or_jwt)])
async def get_processes(
    limit: int = Query(200, ge=1, le=1000),
    agent_id: str | None = Query(None),
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
    agent_id: str | None = Query(None),
    category: str | None = Query(None, description="Filtre par catégorie, ex. 'misconfig'"),
    db: Session = Depends(get_db),
):
    event_categories = [
        "ping_event", "security_event", "system_log",
        "ssh_session", "misconfig", "error",
        "auth_log", "auth_event", "network_connection", "process",
        "machine_state", "system_log", "network_connection",
    ]
    # dedupe
    event_categories = list(dict.fromkeys(event_categories))
    query = (
        db.query(AgentTelemetryEvent)
        .filter(AgentTelemetryEvent.category.in_(event_categories))
        .order_by(desc(AgentTelemetryEvent.received_at))
    )
    if agent_id:
        query = query.filter(AgentTelemetryEvent.agent_id == agent_id)
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
    now = datetime.now(UTC)
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
    row.completed_at = datetime.now(UTC)
    db.commit()

    return {"status": "ok"}
