"""F5 — API endpoints pour l'auto-analyse IA (ai-auto)."""
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...application.system_config import get_config_value, update_settings
from ...auth import get_api_key_or_jwt
from ...core.config import settings
from ...db import get_db, get_tenant_id
from ...domain.models import Agent, AgentAiAnalysis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai-auto", tags=["AI Auto-Analyse"])

AI_AUTO_FALLBACKS = {
    "enabled": "false",
    "threshold": "8",
    "send_count": "10",
    "severity_min": "8",
    "window_minutes": "60",
    "model": settings.HF_MODEL,
    "url": settings.HF_ROUTER_URL,
}


def _read_ai_auto_config(db: Session, tenant_id: str) -> dict:
    return {
        "enabled": get_config_value(db, "ai_auto", "enabled", AI_AUTO_FALLBACKS["enabled"], tenant_id).lower() in ("true", "1", "yes", "on"),
        "threshold": int(get_config_value(db, "ai_auto", "threshold", AI_AUTO_FALLBACKS["threshold"], tenant_id)),
        "send_count": int(get_config_value(db, "ai_auto", "send_count", AI_AUTO_FALLBACKS["send_count"], tenant_id)),
        "severity_min": int(get_config_value(db, "ai_auto", "severity_min", AI_AUTO_FALLBACKS["severity_min"], tenant_id)),
        "window_minutes": int(get_config_value(db, "ai_auto", "window_minutes", AI_AUTO_FALLBACKS["window_minutes"], tenant_id)),
        "model": get_config_value(db, "ai_auto", "model", AI_AUTO_FALLBACKS["model"], tenant_id),
        "url": get_config_value(db, "ai_auto", "url", AI_AUTO_FALLBACKS["url"], tenant_id),
    }


class AIAutoSettingsUpdate(BaseModel):
    enabled: bool | None = None
    threshold: int | None = Field(None, ge=1)
    send_count: int | None = Field(None, ge=1)
    severity_min: int | None = Field(None, ge=1, le=15)
    window_minutes: int | None = Field(None, ge=1)
    model: str | None = None
    url: str | None = None

    model_config = {"extra": "forbid"}


class AnalysisOut(BaseModel):
    id: int
    agent_id: str
    hostname: str | None
    severity_count: int
    alert_ids: list[int]
    model: str
    response: str | None
    status: str
    error: str | None
    analyzed_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/settings/ai-auto", dependencies=[Depends(get_api_key_or_jwt)])
def read_ai_auto_settings(request: Request, db: Session = Depends(get_db)):
    """Lire la configuration de l'auto-analyse IA."""
    tenant_id = get_tenant_id(request)
    config = _read_ai_auto_config(db, tenant_id)
    return config


@router.put("/settings/ai-auto", dependencies=[Depends(get_api_key_or_jwt)])
def write_ai_auto_settings(request: Request, body: AIAutoSettingsUpdate, db: Session = Depends(get_db)):
    """Mettre à jour la configuration de l'auto-analyse IA."""
    tenant_id = get_tenant_id(request)
    data = body.model_dump(exclude_unset=True)

    # Validation
    errors = []
    if "threshold" in data and data["threshold"] < 1:
        errors.append("threshold must be >= 1")
    if "send_count" in data and data["send_count"] < 1:
        errors.append("send_count must be >= 1")
    if "window_minutes" in data and data["window_minutes"] < 1:
        errors.append("window_minutes must be >= 1")
    if "severity_min" in data:
        if data["severity_min"] < 1 or data["severity_min"] > 15:
            errors.append("severity_min must be between 1 and 15")
    if "model" in data and not str(data["model"]).strip():
        errors.append("model must be a non-empty string")
    if "url" in data and not str(data["url"]).strip():
        errors.append("url must be a non-empty string")
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    update_settings(db, "ai_auto", data, tenant_id=tenant_id)
    return _read_ai_auto_config(db, tenant_id)


@router.get("/analyses", dependencies=[Depends(get_api_key_or_jwt)])
def list_analyses(
    request: Request,
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Lister les analyses IA du tenant (order by analyzed_at desc)."""
    tenant_id = get_tenant_id(request)
    analyses = (
        db.query(AgentAiAnalysis)
        .filter(AgentAiAnalysis.tenant_id == tenant_id)
        .order_by(desc(AgentAiAnalysis.analyzed_at), desc(AgentAiAnalysis.created_at))
        .limit(limit)
        .all()
    )
    result = []
    for a in analyses:
        hostname = None
        agent_row = db.query(Agent).filter(Agent.agent_id == a.agent_id, Agent.tenant_id == tenant_id).first()
        if agent_row:
            hostname = agent_row.hostname
        alert_ids = []
        try:
            alert_ids = a.alert_ids_parse
        except Exception:
            pass
        result.append({
            "id": a.id,
            "agent_id": a.agent_id,
            "hostname": hostname,
            "severity_count": a.severity_count,
            "alert_ids": alert_ids,
            "model": a.model,
            "response": a.response,
            "status": a.status,
            "error": a.error,
            "analyzed_at": a.analyzed_at,
            "created_at": a.created_at,
        })
    return {"analyses": result}
