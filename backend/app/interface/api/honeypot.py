import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from ...db import get_db, SessionLocal
from ...models import HoneypotEvent
from ...auth import get_api_key_or_jwt
from ...infrastructure.honeypot.service import HoneypotService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/honeypot", tags=["honeypot"], dependencies=[Depends(get_api_key_or_jwt)])

# Instance globale du service (initialisée au boot)
_honeypot_service: Optional[HoneypotService] = None


def set_honeypot_service(service: HoneypotService):
    global _honeypot_service
    _honeypot_service = service


@router.get("/status")
async def get_honeypot_status(request: Request):
    """Statut du service honeypot."""
    if _honeypot_service is None:
        return {"running": False, "ports": [], "total_events": 0}
    return _honeypot_service.status()


@router.get("/events")
async def get_honeypot_events(
    request: Request,
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Liste des événements honeypot (paginé, tenant-scoped)."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    events = (
        db.query(HoneypotEvent)
        .filter(HoneypotEvent.tenant_id == tenant_id)
        .order_by(desc(HoneypotEvent.timestamp))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        {
            "id": e.id,
            "port": e.port,
            "src_ip": e.src_ip,
            "src_port": e.src_port,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "payload_preview": e.payload_preview,
            "alert_id": e.alert_id,
            "tenant_id": e.tenant_id,
        }
        for e in events
    ]


@router.get("/stats")
async def get_honeypot_stats(request: Request, db: Session = Depends(get_db)):
    """Statistiques: total événements, par port, top 10 IPs."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    total = (
        db.query(func.count(HoneypotEvent.id))
        .filter(HoneypotEvent.tenant_id == tenant_id)
        .scalar() or 0
    )
    per_port = (
        db.query(HoneypotEvent.port, func.count(HoneypotEvent.id).label("cnt"))
        .filter(HoneypotEvent.tenant_id == tenant_id)
        .group_by(HoneypotEvent.port)
        .all()
    )
    top_ips = (
        db.query(HoneypotEvent.src_ip, func.count(HoneypotEvent.id).label("cnt"))
        .filter(HoneypotEvent.tenant_id == tenant_id)
        .group_by(HoneypotEvent.src_ip)
        .order_by(desc(func.count(HoneypotEvent.id)))
        .limit(10)
        .all()
    )
    return {
        "total_events": total,
        "events_per_port": [{"port": p, "count": c} for p, c in per_port],
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
    }
