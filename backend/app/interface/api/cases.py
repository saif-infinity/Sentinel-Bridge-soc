"""F2 — Routes API : gestion des affaires (cas d'investigation), triage, timeline.

Routers minces : toute la logique est dans application/cases.py.
Scoping tenant : STRICT (tenant_id de request.state, posé par TenantMiddleware).
Writes : scope "cases:write" (analyst + admin + API key) — voir auth.py.
"""
import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...application.cases import (
    add_timeline_note,
    case_stats,
    close_case,
    create_case,
    delete_case,
    get_case,
    link_alert,
    linkable_alerts,
    list_case_alerts,
    list_cases,
    list_timeline,
    reopen_case,
    triage_alert,
    unlink_alert,
    update_case,
)
from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cases", tags=["Cases"],
                   dependencies=[Depends(get_api_key_or_jwt)])

CASES_WRITE = ["cases:write"]


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    status: str = "open"
    severity: int = Field(5, ge=0, le=15)
    assignee: str | None = None


class CaseUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = None
    status: str | None = None
    severity: int | None = Field(None, ge=0, le=15)
    assignee: str | None = None


class CaseClose(BaseModel):
    resolution: str | None = Field(None, max_length=4000)


class LinkAlertRequest(BaseModel):
    alert_type: str = Field(..., description="alert | suricata")
    alert_id: int


class TriageRequest(BaseModel):
    status: str = Field(..., description="open | in_progress | resolved | dismissed")
    note: str | None = Field(None, max_length=2000)


class NoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)


def _principal_username(principal: dict) -> str:
    return str(principal.get("sub") or "api_key")


# ── Liste + création ────────────────────────────────────────────────

@router.get("")
def get_cases(request: Request, db: Session = Depends(get_db),
              status: str | None = None, assignee: str | None = None,
              severity_min: int | None = None, q: str | None = None,
              limit: int = 100, offset: int = 0):
    return list_cases(db, get_tenant_id(request), status=status, assignee=assignee,
                      severity_min=severity_min, q=q, limit=limit, offset=offset)


@router.post("", status_code=201)
def create_case_route(body: CaseCreate, request: Request, db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return create_case(db, get_tenant_id(request), _principal_username(principal),
                       body.model_dump())


# ── Stats + alertes liables (déclarées AVANT /{case_id}) ────────────

@router.get("/stats")
def get_case_stats(request: Request, db: Session = Depends(get_db)):
    return case_stats(db, get_tenant_id(request))


@router.get("/linkable-alerts")
def get_linkable_alerts(request: Request, db: Session = Depends(get_db),
                        source: str | None = None, limit: int = 50):
    return linkable_alerts(db, get_tenant_id(request), source=source, limit=limit)


# ── Détail / mise à jour / suppression ──────────────────────────────

@router.get("/{case_id}")
def get_case_route(case_id: int, request: Request, db: Session = Depends(get_db)):
    return get_case(db, get_tenant_id(request), case_id)


@router.put("/{case_id}")
def update_case_route(case_id: int, body: CaseUpdate, request: Request,
                      db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return update_case(db, get_tenant_id(request), _principal_username(principal),
                       case_id, body.model_dump(exclude_unset=True))


@router.delete("/{case_id}")
def delete_case_route(case_id: int, request: Request, db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return delete_case(db, get_tenant_id(request), _principal_username(principal), case_id)


@router.post("/{case_id}/close")
def close_case_route(case_id: int, body: CaseClose, request: Request,
                     db: Session = Depends(get_db),
                     principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return close_case(db, get_tenant_id(request), _principal_username(principal),
                      case_id, body.resolution)


@router.post("/{case_id}/reopen")
def reopen_case_route(case_id: int, request: Request, db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return reopen_case(db, get_tenant_id(request), _principal_username(principal), case_id)


# ── Alertes liées + triage ──────────────────────────────────────────

@router.get("/{case_id}/alerts")
def get_case_alerts(case_id: int, request: Request, db: Session = Depends(get_db)):
    return list_case_alerts(db, get_tenant_id(request), case_id)


@router.post("/{case_id}/alerts", status_code=201)
def link_alert_route(case_id: int, body: LinkAlertRequest, request: Request,
                     db: Session = Depends(get_db),
                     principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return link_alert(db, get_tenant_id(request), _principal_username(principal),
                      case_id, body.alert_type, body.alert_id)


@router.delete("/{case_id}/alerts/{link_id}")
def unlink_alert_route(case_id: int, link_id: int, request: Request,
                       db: Session = Depends(get_db),
                       principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return unlink_alert(db, get_tenant_id(request), _principal_username(principal),
                        case_id, link_id)


@router.post("/{case_id}/alerts/{link_id}/triage")
def triage_alert_route(case_id: int, link_id: int, body: TriageRequest,
                       request: Request, db: Session = Depends(get_db),
                       principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return triage_alert(db, get_tenant_id(request), _principal_username(principal),
                        case_id, link_id, body.status, body.note)


# ── Timeline ────────────────────────────────────────────────────────

@router.get("/{case_id}/timeline")
def get_timeline(case_id: int, request: Request, db: Session = Depends(get_db),
                 limit: int = 100):
    return list_timeline(db, get_tenant_id(request), case_id, limit=limit)


@router.post("/{case_id}/timeline", status_code=201)
def add_note(case_id: int, body: NoteRequest, request: Request,
             db: Session = Depends(get_db),
             principal: dict = Depends(has_scopes_or_api_key(CASES_WRITE))):
    return add_timeline_note(db, get_tenant_id(request), _principal_username(principal),
                             case_id, body.note)
