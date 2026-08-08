"""F3 — Routes API Threat Intelligence (check / statut / cache)."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt
from ...config import settings
from ...db import get_db, get_tenant_id
from ...domain.intel import ThreatIntelCache
from ...infrastructure.threat_intel.client import lookup_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/intel", tags=["intel"])


@router.get("/check", dependencies=[Depends(get_api_key_or_jwt)])
async def check_ip(request: Request, ip: str, force: bool = False, db: Session = Depends(get_db)):
    if not ip:
        raise HTTPException(status_code=422, detail="Paramètre 'ip' requis")
    tenant_id = get_tenant_id(request)
    info = lookup_ip(db, tenant_id, ip, force=force)
    return {"ip": ip, **info}


@router.get("/status", dependencies=[Depends(get_api_key_or_jwt)])
async def intel_status(request: Request):
    return {
        "enabled": settings.THREAT_INTEL_ENABLED,
        "provider": settings.THREAT_INTEL_PROVIDER,
        "cache_ttl_seconds": settings.THREAT_INTEL_CACHE_TTL_SECONDS,
        "api_key_configured": bool(settings.THREAT_INTEL_API_KEY.get_secret_value()),
    }


@router.get("/cache", dependencies=[Depends(get_api_key_or_jwt)])
async def intel_cache(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    rows = (
        db.query(ThreatIntelCache)
        .filter(ThreatIntelCache.tenant_id == tenant_id)
        .order_by(desc(ThreatIntelCache.checked_at))
        .limit(min(limit, 200))
        .all()
    )
    return [{
        "id": r.id, "ip": r.ip, "verdict": r.verdict, "risk_score": r.risk_score,
        "source_name": r.source_name,
        "checked_at": r.checked_at.isoformat() if r.checked_at else None,
    } for r in rows]
