"""F5 — Routes API : investigation (lecture seule, tenant-scoped)."""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt
from ...db import get_db, get_tenant_id
from ...domain.investigations import Investigation, InvestigationEvidence, InvestigationRecommendation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/investigations", tags=["Investigations"],
                   dependencies=[Depends(get_api_key_or_jwt)])


def _get_api_key_or_jwt(request: Request):
    """Lazy import of auth dependency."""
    from ...auth import get_api_key_or_jwt
    return get_api_key_or_jwt(request)


@router.get("")
def list_investigations(request: Request, db: Session = Depends(get_db),
                          status: Optional[str] = None,
                          limit: int = 100, offset: int = 0):
    tenant_id = get_tenant_id(request)
    query = db.query(Investigation).filter(Investigation.tenant_id == tenant_id)
    if status:
        query = query.filter(Investigation.status == status)
    total = query.count()
    items = query.order_by(Investigation.created_at.desc()).offset(offset).limit(min(limit, 500)).all()
    return {
        "items": [_investigation_to_dict(inv) for inv in items],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{id}")
def get_investigation(request: Request, id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    inv = db.query(Investigation).filter(Investigation.id == id, Investigation.tenant_id == tenant_id).first()
    if inv is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Investigation introuvable")
    return _investigation_to_dict(inv)


@router.get("/{id}/evidence")
def get_evidence(request: Request, id: int, db: Session = Depends(get_db),
                   limit: int = 100, offset: int = 0):
    tenant_id = get_tenant_id(request)
    inv = db.query(Investigation).filter(Investigation.id == id, Investigation.tenant_id == tenant_id).first()
    if inv is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Investigation introuvable")
    rows = db.query(InvestigationEvidence).filter(
        InvestigationEvidence.investigation_id == id,
        InvestigationEvidence.tenant_id == tenant_id,
    ).order_by(InvestigationEvidence.collected_at.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"items": [_evidence_to_dict(ev) for ev in rows], "total": len(rows)}


@router.get("/{id}/recommendations")
def get_recommendations(request: Request, id: int, db: Session = Depends(get_db),
                          limit: int = 100, offset: int = 0):
    tenant_id = get_tenant_id(request)
    inv = db.query(Investigation).filter(Investigation.id == id, Investigation.tenant_id == tenant_id).first()
    if inv is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Investigation introuvable")
    rows = db.query(InvestigationRecommendation).filter(
        InvestigationRecommendation.investigation_id == id,
        InvestigationRecommendation.tenant_id == tenant_id,
    ).order_by(InvestigationRecommendation.priority.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"items": [_recommendation_to_dict(rec) for rec in rows], "total": len(rows)}


def _investigation_to_dict(inv: Investigation) -> dict:
    return {
        "id": inv.id,
        "tenant_id": inv.tenant_id,
        "event_id": inv.event_id,
        "case_id": inv.case_id,
        "trigger_alert_type": inv.trigger_alert_type,
        "trigger_alert_id": inv.trigger_alert_id,
        "dedup_fingerprint": inv.dedup_fingerprint,
        "status": inv.status,
        "completion": inv.completion,
        "risk_score": inv.risk_score,
        "risk_level": inv.risk_level,
        "summary": inv.summary,
        "created_by": inv.created_by,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
        "score_breakdown": inv.score_breakdown,
        "missing_steps": inv.missing_steps,
    }


def _evidence_to_dict(ev: InvestigationEvidence) -> dict:
    return {
        "id": ev.id,
        "step_key": ev.step_key,
        "evidence_type": ev.evidence_type,
        "source": ev.source,
        "status": ev.status,
        "summary": ev.summary,
        "payload": ev.payload,
        "error": ev.error,
        "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
    }


def _recommendation_to_dict(rec: InvestigationRecommendation) -> dict:
    return {
        "id": rec.id,
        "action_type": rec.action_type,
        "target": rec.target,
        "priority": rec.priority,
        "confidence": rec.confidence,
        "rationale": rec.rationale,
        "source": rec.source,
        "status": rec.status,
        "response_ref": rec.response_ref,
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "resolved_at": rec.resolved_at.isoformat() if rec.resolved_at else None,
    }