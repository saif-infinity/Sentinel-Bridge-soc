"""
Network Device Configuration Router — CRUD + remote config push via SSH/telnet.
Wizard-friendly API: provides config templates per device type/brand.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Body, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import get_db, get_tenant_id, query_with_tenant
from ...models import NetworkDevice
from ...auth import get_api_key_or_jwt
from ...infrastructure.network_device.command_builder import generate_commands, _advanced_cmds

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/network-devices", tags=["network-devices"])


# ─── Config Templates ───────────────────────────────────────────────
# Predefined configuration "puzzle pieces" per device type + brand
from pathlib import Path
_TEMPLATES_PATH = Path(__file__).resolve().parents[2] / "infrastructure" / "data" / "network_config_templates.json"
CONFIG_TEMPLATES = json.loads(_TEMPLATES_PATH.read_text(encoding="utf-8"))


# ─── Schemas ────────────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    name: str
    ip: str
    device_type: str
    brand: str = "cisco"
    model: Optional[str] = None
    username: str = "admin"
    password: Optional[str] = None
    port: int = 22
    protocol: str = "ssh"
    notes: Optional[str] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    ip: Optional[str] = None
    device_type: Optional[str] = None
    brand: Optional[str] = None
    model: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    notes: Optional[str] = None


class ConfigPushRequest(BaseModel):
    config: Dict[str, Any]


class ConfigPushResponse(BaseModel):
    success: bool
    commands_generated: List[str]
    output: Optional[str] = None
    error: Optional[str] = None



# ═══════════════════════════════════════════════════════════════════
# Command Generators — CLI snippets per brand
# ═══════════════════════════════════════════════════════════════════



# ═══════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════

@router.get("")
def list_devices(
    request: Request,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    devices = query_with_tenant(NetworkDevice, request, db).all()
    return [_device_dict(d) for d in devices]


@router.get("/{device_id}")
def get_device(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    return _device_dict(d)


@router.post("")
def create_device(
    request: Request,
    body: DeviceCreate,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    d = NetworkDevice(
        name=body.name, ip=body.ip, device_type=body.device_type,
        brand=body.brand, model=body.model, username=body.username,
        password_encrypted=body.password, port=body.port, protocol=body.protocol,
        notes=body.notes,
        tenant_id=get_tenant_id(request),
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return _device_dict(d)


@router.put("/{device_id}")
def update_device(
    request: Request,
    device_id: int,
    body: DeviceUpdate,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(d, k, v)
    db.commit()
    db.refresh(d)
    return _device_dict(d)


@router.delete("/{device_id}")
def delete_device(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    db.delete(d)
    db.commit()
    return {"ok": True}


@router.get("/config-templates/all")
def config_templates():
    """Return all config templates keyed by device_type + brand."""
    return CONFIG_TEMPLATES


@router.post("/preview-config")
def preview_config(
    body: ConfigPushRequest,
    _user: Any = Depends(get_api_key_or_jwt),
):
    """Generate CLI commands from wizard config, return for preview (no push)."""
    cfg = body.config
    device_type = cfg.get("device_type", "switch")
    brand = cfg.get("brand", "cisco")
    commands = generate_commands(cfg, device_type, brand)
    return {
        "success": True,
        "commands_generated": commands,
        "device_type": device_type,
        "brand": brand,
    }


@router.post("/{device_id}/test-connection")
def test_connection(
    request: Request,
    device_id: int,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    """Simulate testing SSH/telnet connectivity to a device."""
    import time, random
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    # Simulate connection test (demo mode)
    latency = round(random.uniform(2, 50), 1)
    reachable = random.random() > 0.3  # 70% success rate for demo
    if reachable:
        d.status = "online"
        d.last_connected = datetime.now(timezone.utc)
    else:
        d.status = "error"
    db.commit()
    return {
        "status": "online" if reachable else "offline",
        "latency_ms": latency if reachable else None,
        "error": None if reachable else "Connection timeout",
        "device": _device_dict(d),
    }


@router.post("/{device_id}/push-config")
def push_config(
    request: Request,
    device_id: int,
    body: ConfigPushRequest,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
):
    """Generate CLI commands and simulate push (no actual SSH in demo mode)."""
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    cfg = body.config
    brand = getattr(d, "brand", cfg.get("brand", "cisco"))
    device_type = getattr(d, "device_type", cfg.get("device_type", "switch"))
    commands = generate_commands(cfg, device_type, brand)
    logger.info(f"Pushed {len(commands)} commands to {d.name} ({d.ip})")
    return ConfigPushResponse(
        success=True,
        commands_generated=commands,
        output=f"Simulated push of {len(commands)} commands to {d.name}.",
    )


# ─── Helpers ──────────────────────────────────────────────────────

def _device_dict(d: NetworkDevice) -> dict:
    return {
        "id": d.id,
        "name": d.name,
        "ip": d.ip,
        "device_type": d.device_type,
        "brand": getattr(d, "brand", "cisco"),
        "model": d.model,
        "username": d.username,
        "port": d.port,
        "protocol": d.protocol,
        "notes": d.notes,
        "status": getattr(d, "status", None),
        "last_connected": d.last_connected.isoformat() if getattr(d, "last_connected", None) else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }
