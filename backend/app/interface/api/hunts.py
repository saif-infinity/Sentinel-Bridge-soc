"""F2 — Routes API : hunting (chasses enregistrées) + preview non persistée.

Routers minces ; logique dans application/hunts.py.
Réutilise l'évaluateur F1 (OPS, evaluate_conditions) — aucun nouveau moteur.
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...application.hunts import (
    create_hunt, delete_hunt, generate_ai_hunt_proposals, get_hunt,
    list_hunts, run_hunt, update_hunt,
)
from ...application.rules.evaluator import OPS
from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hunts", tags=["Hunting"],
                   dependencies=[Depends(get_api_key_or_jwt)])

HUNTS_WRITE = ["cases:write"]


class HuntCondition(BaseModel):
    field: str = Field(..., max_length=100)
    op: str = Field("eq")
    value: object = None


class HuntCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    target: str = "both"   # alert | suricata | both
    conditions: List[HuntCondition] = Field(..., min_length=1)


class HuntUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    target: Optional[str] = None
    conditions: Optional[List[HuntCondition]] = None


class HuntRunRequest(BaseModel):
    target: str = "both"
    conditions: Optional[List[HuntCondition]] = Field(None, min_length=1)
    limit: int = Field(500, ge=1, le=1000)


def _principal_username(principal: dict) -> str:
    return str(principal.get("sub") or "api_key")


# ── Liste + création ────────────────────────────────────────────────

@router.get("")
def get_hunts(request: Request, db: Session = Depends(get_db)):
    return list_hunts(db, get_tenant_id(request))


@router.post("", status_code=201)
def create_hunt_route(body: HuntCreate, request: Request, db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    data = body.model_dump()
    data["conditions"] = [c.model_dump() for c in body.conditions]
    return create_hunt(db, get_tenant_id(request), _principal_username(principal), data)


# ── Preview / IA génération ─────────────────────────────

@router.post("/preview")
def preview_hunt(body: HuntRunRequest, request: Request, db: Session = Depends(get_db),
                 principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    return run_hunt(db, get_tenant_id(request), _principal_username(principal),
                    conditions=[c.model_dump() for c in (body.conditions or [])],
                    target=body.target, limit=body.limit, preview=True)


@router.post("/ai-generate")
def ai_generate_hunts(request: Request, db: Session = Depends(get_db),
                       principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    return generate_ai_hunt_proposals(db, get_tenant_id(request))


# ── CRUD d'une chasse enregistrée ───────────────────────────

@router.get("/{hunt_id}")
def get_hunt_route(hunt_id: int, request: Request, db: Session = Depends(get_db)):
    return get_hunt(db, get_tenant_id(request), hunt_id)


@router.put("/{hunt_id}")
def update_hunt_route(hunt_id: int, body: HuntUpdate, request: Request,
                      db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    data = body.model_dump(exclude_unset=True)
    if "conditions" in data and data["conditions"] is not None:
        # model_dump(exclude_unset=True) renvoie déjà les conditions en dicts ;
        # ne re-sérialise que si un élément n'est pas un dict (défense en profondeur).
        data["conditions"] = [c if isinstance(c, dict) else c.model_dump()
                              for c in data["conditions"]]
    return update_hunt(db, get_tenant_id(request), _principal_username(principal),
                       hunt_id, data)


@router.delete("/{hunt_id}")
def delete_hunt_route(hunt_id: int, request: Request, db: Session = Depends(get_db),
                      principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    return delete_hunt(db, get_tenant_id(request), _principal_username(principal), hunt_id)


@router.post("/{hunt_id}/run")
def run_hunt_route(hunt_id: int, request: Request, db: Session = Depends(get_db),
                   principal: dict = Depends(has_scopes_or_api_key(HUNTS_WRITE))):
    return run_hunt(db, get_tenant_id(request), _principal_username(principal),
                    hunt_id=hunt_id)
