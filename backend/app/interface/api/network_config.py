"""
Network Device Configuration Router — CRUD + remote config push via SSH/telnet.
Wizard-friendly API: provides config templates per device type/brand.
"""
import json
import logging
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id, query_with_tenant
from ...infrastructure.network_device.command_builder import generate_commands
from ...models import NetworkDevice

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/network-devices", tags=["network-devices"])

# TCP probe budget for /test-connection (seconds).
TEST_CONNECT_TIMEOUT = 3.0


# ─── Config Templates ───────────────────────────────────────────────
# Predefined configuration "puzzle pieces" per device type + brand

_TEMPLATES_PATH = Path(__file__).resolve().parents[2] / "infrastructure" / "data" / "network_config_templates.json"
CONFIG_TEMPLATES = json.loads(_TEMPLATES_PATH.read_text(encoding="utf-8"))


# ─── Schemas ────────────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    name: str
    ip: str
    device_type: str
    brand: str = "cisco"
    model: str | None = None
    username: str = "admin"
    password: str | None = None
    port: int = 22
    protocol: str = "ssh"
    notes: str | None = None


class DeviceUpdate(BaseModel):
    name: str | None = None
    ip: str | None = None
    device_type: str | None = None
    brand: str | None = None
    model: str | None = None
    username: str | None = None
    password: str | None = None
    port: int | None = None
    protocol: str | None = None
    notes: str | None = None


class ConfigPushRequest(BaseModel):
    config: dict[str, Any]


class ConfigPushResponse(BaseModel):
    success: bool
    commands_generated: list[str]
    output: str | None = None
    error: str | None = None



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
    _scope: Any = Depends(has_scopes_or_api_key(["admin:manage"])),
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
    _scope: Any = Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """Real TCP reachability probe against the device management port.

    FIX: this used to be `random.random() > 0.3` — a coin flip whose result was then
    *persisted* as the device status, so the whole inventory ("online"/"error") was
    noise presented as ground truth. It now does an actual connect() with a timeout
    and only writes what it observed.
    """
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")

    port = int(getattr(d, "port", 0) or 22)
    started = time.perf_counter()
    error: str | None = None
    try:
        with socket.create_connection((d.ip, port), timeout=TEST_CONNECT_TIMEOUT):
            reachable = True
    except OSError as exc:
        reachable = False
        error = f"{type(exc).__name__}: {exc}"

    latency = round((time.perf_counter() - started) * 1000, 1) if reachable else None
    d.status = "online" if reachable else "error"
    if reachable:
        d.last_connected = datetime.now(UTC)
    db.commit()
    return {
        "status": "online" if reachable else "offline",
        "latency_ms": latency,
        "port": port,
        "error": None if reachable else (error or "Connection timeout"),
        "device": _device_dict(d),
    }


@router.post("/{device_id}/push-config")
def push_config(
    request: Request,
    device_id: int,
    body: ConfigPushRequest,
    db: Session = Depends(get_db),
    _user: Any = Depends(get_api_key_or_jwt),
    _scope: Any = Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """Generate the CLI commands for a device (dry run).

    FIX: this returned `success: true` with "Simulated push of N commands" while
    nothing was ever sent to the device — and the UI toasted "Configuration
    appliquée". There is no SSH transport for network devices, so the endpoint now
    reports a dry run honestly (the frontend already had the `toast.warning(data.error)`
    branch for exactly this case).
    """
    d = query_with_tenant(NetworkDevice, request, db).filter(NetworkDevice.id == device_id).first()
    if not d:
        raise HTTPException(404, "Device not found")
    cfg = body.config
    brand = getattr(d, "brand", cfg.get("brand", "cisco"))
    device_type = getattr(d, "device_type", cfg.get("device_type", "switch"))
    commands = generate_commands(cfg, device_type, brand)
    logger.warning(
        "DRY RUN: generated %d commands for %s (%s) — no SSH transport implemented, nothing was applied",
        len(commands), d.name, d.ip,
    )
    return ConfigPushResponse(
        success=False,
        commands_generated=commands,
        output=f"DRY RUN — {len(commands)} commands generated for {d.name} ({d.ip}); nothing was sent to the device.",
        error="No SSH transport for network devices yet: commands were generated, not applied.",
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
