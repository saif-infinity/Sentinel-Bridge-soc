"""F5 — Routes API : response runs (approval, rollback)."""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id
from ...domain.response import ResponseRun, ResponseActionResult, ResponseRollback
from ...application.response.executor import execute_response_run, execute_rollback
from ...application.system_config import get_config_value
from ...infrastructure.jobs.response_tasks import execute_run as execute_run_task

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/response", tags=["Response"],
                   dependencies=[Depends(get_api_key_or_jwt)])

WRITE_SCOPES = ["response:write"]


@router.get("/runs")
def list_runs(request: Request, db: Session = Depends(get_db),
                 status: Optional[str] = None,
                 investigation_id: Optional[int] = None,
                 limit: int = 100, offset: int = 0):
    tenant_id = get_tenant_id(request)
    query = db.query(ResponseRun).filter(ResponseRun.tenant_id == tenant_id)
    if status:
        query = query.filter(ResponseRun.status == status)
    if investigation_id:
        query = query.filter(ResponseRun.investigation_id == investigation_id)
    total = query.count()
    items = query.order_by(ResponseRun.created_at.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"items": [_run_to_dict(r) for r in items], "total": total}


@router.get("/runs/{id}")
def get_run(request: Request, id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    run = db.query(ResponseRun).filter(ResponseRun.id == id, ResponseRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    results = db.query(ResponseActionResult).filter(ResponseActionResult.run_id == id).all()
    return {"run": _run_to_dict(run), "action_results": [_result_to_dict(r) for r in results]}


@router.post("/runs/{id}/approve")
def approve_run(request: Request, id: int, db: Session = Depends(get_db),
                   principal: dict = Depends(has_scopes_or_api_key(WRITE_SCOPES))):
    tenant_id = get_tenant_id(request)
    run = db.query(ResponseRun).filter(ResponseRun.id == id, ResponseRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    if run.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Statut incompatible: {run.status}")
    run.status = "approved"
    run.approved_by = str(principal.get("sub", "api_key"))
    run.approved_at = datetime.now(timezone.utc)
    db.commit()
    execute_run_task.delay(id)
    return {"status": "approved", "run_id": id}


@router.post("/runs/{id}/reject")
def reject_run(request: Request, id: int, db: Session = Depends(get_db),
                  principal: dict = Depends(has_scopes_or_api_key(WRITE_SCOPES))):
    tenant_id = get_tenant_id(request)
    run = db.query(ResponseRun).filter(ResponseRun.id == id, ResponseRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    if run.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Statut incompatible: {run.status}")
    run.status = "rejected"
    db.commit()
    # Dismiss the recommendation
    try:
        from ...domain.investigations import InvestigationRecommendation
        rec = db.query(InvestigationRecommendation).filter(
            InvestigationRecommendation.id == run.recommendation_id
        ).first()
        if rec:
            rec.status = "dismissed"
            rec.resolved_at = datetime.now(timezone.utc)
            db.commit()
    except Exception:
        db.rollback()
    return {"status": "rejected", "run_id": id}


@router.post("/runs/{id}/rollback")
def rollback_run(request: Request, id: int, db: Session = Depends(get_db),
                    principal: dict = Depends(has_scopes_or_api_key(WRITE_SCOPES))):
    tenant_id = get_tenant_id(request)
    run = db.query(ResponseRun).filter(ResponseRun.id == id, ResponseRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    if not run.rollback_plan:
        raise HTTPException(status_code=409, detail="No rollback_plan defined for this run")
    reason = "manual rollback"
    from ...application.response.executor import execute_rollback
    result = execute_rollback(id, reason)
    return result


@router.get("/rollbacks")
def list_rollbacks(request: Request, db: Session = Depends(get_db),
                      limit: int = 100, offset: int = 0):
    tenant_id = get_tenant_id(request)
    rows = db.query(ResponseRollback).filter(ResponseRollback.tenant_id == tenant_id).order_by(ResponseRollback.created_at.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"items": [_rollback_to_dict(r) for r in rows], "total": len(rows)}


def _run_to_dict(run: ResponseRun) -> dict:
    return {
        "id": run.id,
        "tenant_id": run.tenant_id,
        "investigation_id": run.investigation_id,
        "recommendation_id": run.recommendation_id,
        "action_type": run.action_type,
        "target": run.target,
        "params": run.params,
        "requires_approval": run.requires_approval,
        "status": run.status,
        "rollback_plan": run.rollback_plan,
        "initiated_by": run.initiated_by,
        "approved_by": run.approved_by,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def _result_to_dict(result: ResponseActionResult) -> dict:
    return {
        "id": result.id,
        "run_id": result.run_id,
        "attempt": result.attempt,
        "status": result.status,
        "output": result.output,
        "error": result.error,
        "duration_ms": result.duration_ms,
        "started_at": result.started_at.isoformat() if result.started_at else None,
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
    }


def _rollback_to_dict(rb: ResponseRollback) -> dict:
    return {
        "id": rb.id,
        "run_id": rb.run_id,
        "action_type": rb.action_type,
        "target": rb.target,
        "status": rb.status,
        "initiated_by": rb.initiated_by,
        "reason": rb.reason,
        "output": rb.output,
        "error": rb.error,
        "created_at": rb.created_at.isoformat() if rb.created_at else None,
        "executed_at": rb.executed_at.isoformat() if rb.executed_at else None,
    }