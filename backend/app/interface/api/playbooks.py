"""F3 — Routes API Mini-SOAR (playbooks + runs + approbations)."""
import json
import logging
import threading
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_
from sqlalchemy.orm import Session

from ...application.action_logger import log_action
from ...application.soar.executor import execute_playbook
from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id
from ...domain.soar import Playbook, PlaybookRun, PlaybookStepResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


class PlaybookIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    trigger_rule_ids: list = Field(default_factory=list)
    trigger_min_severity: int | None = Field(None, ge=0, le=15)
    trigger_sources: list = Field(default_factory=list)
    requires_approval: bool = False
    enabled: bool = True
    steps: list = Field(default_factory=list)


class PlaybookOut(BaseModel):
    id: int
    tenant_id: str | None = None
    name: str
    description: str | None = None
    trigger_rule_ids: list = Field(default_factory=list)
    trigger_min_severity: int | None = None
    trigger_sources: list = Field(default_factory=list)
    requires_approval: bool
    enabled: bool
    steps: list = Field(default_factory=list)
    created_at: str | None = None

    @classmethod
    def from_model(cls, p: Playbook) -> "PlaybookOut":
        return cls(
            id=p.id, tenant_id=p.tenant_id, name=p.name, description=p.description,
            trigger_rule_ids=p.trigger_rule_ids or [], trigger_min_severity=p.trigger_min_severity,
            trigger_sources=p.trigger_sources or [], requires_approval=p.requires_approval,
            enabled=p.enabled, steps=p.steps or [],
            created_at=p.created_at.isoformat() if p.created_at else None,
        )


def _username(request: Request) -> str:
    return getattr(request.state, "username", "unknown")


# ── Runs (déclarés AVANT /{playbook_id}) ──────────────────────────────

@router.get("/runs", dependencies=[Depends(get_api_key_or_jwt)])
async def list_runs(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    runs = (
        db.query(PlaybookRun)
        .filter(PlaybookRun.tenant_id == tenant_id)
        .order_by(desc(PlaybookRun.created_at))
        .limit(min(limit, 200))
        .all()
    )
    return [{
        "id": r.id, "playbook_id": r.playbook_id, "event_id": r.event_id,
        "triggered_by": r.triggered_by, "status": r.status,
        "current_step_index": r.current_step_index,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    } for r in runs]


@router.get("/runs/{run_id}/steps", dependencies=[Depends(get_api_key_or_jwt)])
async def run_steps(request: Request, run_id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id, PlaybookRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    steps = (
        db.query(PlaybookStepResult)
        .filter(PlaybookStepResult.run_id == run.id)
        .order_by(PlaybookStepResult.step_index)
        .all()
    )
    return [{
        "step_index": s.step_index, "step_type": s.step_type, "status": s.status,
        "output": json.loads(s.output) if s.output else None, "error": s.error,
        "duration_ms": s.duration_ms,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    } for s in steps]


@router.post("/runs/{run_id}/approve", dependencies=[Depends(has_scopes_or_api_key(["soar:approve"]))])
async def approve_run(request: Request, run_id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id, PlaybookRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    if run.status != "pending_approval":
        raise HTTPException(status_code=409, detail=f"Statut incompatible: {run.status}")
    run.status = "approved"
    db.commit()
    log_action(db, _username(request), "playbook.approve", details=f"run {run.id}",
               resource=f"run:{run.id}", tenant_id=tenant_id)
    threading.Thread(target=execute_playbook, args=(run.id,), daemon=True).start()
    return {"status": "approved", "run_id": run.id}


@router.post("/runs/{run_id}/cancel", dependencies=[Depends(has_scopes_or_api_key(["soar:approve"]))])
async def cancel_run(request: Request, run_id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    run = db.query(PlaybookRun).filter(PlaybookRun.id == run_id, PlaybookRun.tenant_id == tenant_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run introuvable")
    if run.status not in ("pending_approval", "approved", "running"):
        raise HTTPException(status_code=409, detail=f"Statut incompatible: {run.status}")
    run.status = "cancelled"
    run.finished_at = datetime.now(UTC)
    db.commit()
    log_action(db, _username(request), "playbook.cancel", details=f"run {run.id}",
               resource=f"run:{run.id}", tenant_id=tenant_id)
    return {"status": "cancelled", "run_id": run.id}


# ── CRUD playbooks ────────────────────────────────────────────────────

@router.get("", response_model=list[PlaybookOut], dependencies=[Depends(get_api_key_or_jwt)])
async def list_playbooks(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    playbooks = (
        db.query(Playbook)
        .filter(or_(Playbook.tenant_id.is_(None), Playbook.tenant_id == tenant_id))
        .order_by(Playbook.name)
        .all()
    )
    return [PlaybookOut.from_model(p) for p in playbooks]


@router.post("", response_model=PlaybookOut, dependencies=[Depends(has_scopes_or_api_key(["soar:manage"]))])
async def create_playbook(request: Request, payload: PlaybookIn, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    existing = (
        db.query(Playbook)
        .filter(Playbook.name == payload.name,
                or_(Playbook.tenant_id == tenant_id, Playbook.tenant_id.is_(None)))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Un playbook avec ce nom existe déjà")
    playbook = Playbook(
        tenant_id=tenant_id, name=payload.name, description=payload.description,
        trigger_rule_ids=payload.trigger_rule_ids or [],
        trigger_min_severity=payload.trigger_min_severity,
        trigger_sources=payload.trigger_sources or [],
        requires_approval=payload.requires_approval, enabled=payload.enabled,
        steps=payload.steps or [],
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    log_action(db, _username(request), "playbook.create", details=playbook.name,
               resource=f"playbook:{playbook.id}", tenant_id=tenant_id)
    return PlaybookOut.from_model(playbook)


@router.patch("/{playbook_id}", response_model=PlaybookOut, dependencies=[Depends(has_scopes_or_api_key(["soar:manage"]))])
async def update_playbook(request: Request, playbook_id: int, payload: PlaybookIn, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id,
                or_(Playbook.tenant_id == tenant_id, Playbook.tenant_id.is_(None)))
        .first()
    )
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook introuvable")
    playbook.name = payload.name
    playbook.description = payload.description
    playbook.trigger_rule_ids = payload.trigger_rule_ids or []
    playbook.trigger_min_severity = payload.trigger_min_severity
    playbook.trigger_sources = payload.trigger_sources or []
    playbook.requires_approval = payload.requires_approval
    playbook.enabled = payload.enabled
    playbook.steps = payload.steps or []
    db.commit()
    db.refresh(playbook)
    log_action(db, _username(request), "playbook.update", details=playbook.name,
               resource=f"playbook:{playbook.id}", tenant_id=tenant_id)
    return PlaybookOut.from_model(playbook)


@router.post("/{playbook_id}/toggle", response_model=PlaybookOut, dependencies=[Depends(has_scopes_or_api_key(["soar:manage"]))])
async def toggle_playbook(request: Request, playbook_id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id,
                or_(Playbook.tenant_id == tenant_id, Playbook.tenant_id.is_(None)))
        .first()
    )
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook introuvable")
    playbook.enabled = not playbook.enabled
    db.commit()
    db.refresh(playbook)
    log_action(db, _username(request), "playbook.toggle", details=f"{playbook.name} -> {playbook.enabled}",
               resource=f"playbook:{playbook.id}", tenant_id=tenant_id)
    return PlaybookOut.from_model(playbook)


@router.delete("/{playbook_id}", dependencies=[Depends(has_scopes_or_api_key(["soar:manage"]))])
async def delete_playbook(request: Request, playbook_id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == playbook_id,
                or_(Playbook.tenant_id == tenant_id, Playbook.tenant_id.is_(None)))
        .first()
    )
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook introuvable")
    db.delete(playbook)
    db.commit()
    log_action(db, _username(request), "playbook.delete", details=playbook.name,
               resource=f"playbook:{playbook_id}", tenant_id=tenant_id)
    return {"deleted": playbook_id}
