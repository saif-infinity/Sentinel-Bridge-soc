"""F1 — CRUD des règles de corrélation + test dry-run + matchs récents.

Scoping : règles globales (tenant_id NULL) visibles partout, modifiables seulement
par API key ; règles de tenant visibles/modifiables par le tenant uniquement.
"""
import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...application.rules.engine import invalidate_rules_cache, visible_rules
from ...application.rules.evaluator import (
    build_normalized_alert,
    evaluate_conditions,
    mitre_parent,
    mitre_tactics_for,
    mitre_technique_info,
)
from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...core.rbac import require_role
from ...db import get_db, get_tenant_id
from ...domain.rule_models import Rule, RuleMatchOutbox, ensure_mitre_columns

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/rules", tags=["Rules"],
                   dependencies=[Depends(get_api_key_or_jwt)])


class ConditionModel(BaseModel):
    field: str = Field(..., description="Champ de l'alerte normalisée (ex: normalized_severity, src_ip, signature)")
    op: str = Field("eq", description="eq, ne, gt, ge, lt, le, in, contains, startswith, regex, exists")
    value: object = None


class CorrelationModel(BaseModel):
    window_seconds: int = 60
    sequence: List[int] = Field(default_factory=list, description="Indices des conditions, ordre attendu")
    require_same_src: bool = False
    require_same_dest: bool = False
    count: Optional[int] = Field(None, ge=1, description="R13 — seuil d'agrégat : déclenche après N matches dans la fenêtre")
    threshold_window_seconds: Optional[int] = Field(None, ge=1, description="R13 — fenêtre du seuil (défaut = window_seconds)")


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    enabled: bool = True
    severity: int = Field(5, ge=0, le=15)
    tags: List[str] = Field(default_factory=list)
    conditions: List[ConditionModel] = Field(default_factory=list)
    correlation: Optional[CorrelationModel] = None
    action_flags: dict = Field(default_factory=dict)
    mitre_attack_ids: List[str] = Field(default_factory=list, description="R2 — IDs MITRE ATT&CK (ex: T1059.001)")
    tactics: List[str] = Field(default_factory=list, description="R2 — tactiques dérivées des IDs")


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[int] = Field(None, ge=0, le=15)
    tags: Optional[List[str]] = None
    conditions: Optional[List[ConditionModel]] = None
    correlation: Optional[CorrelationModel] = None
    action_flags: Optional[dict] = None
    mitre_attack_ids: Optional[List[str]] = None
    tactics: Optional[List[str]] = None


class RuleTestRequest(BaseModel):
    rule: RuleCreate
    sample_alert: dict = Field(default_factory=dict)


def _loads(s: Optional[str], fallback: str):
    try:
        v = json.loads(s or fallback)
    except (TypeError, ValueError):
        v = json.loads(fallback)
    return v


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "tenant_id": rule.tenant_id,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "severity": rule.severity,
        "tags": _loads(rule.tags, "[]"),
        "conditions": _loads(rule.conditions, "[]"),
        "correlation": _loads(rule.correlation, "{}"),
        "action_flags": _loads(rule.action_flags, "{}"),
        "mitre_attack_ids": _loads(rule.mitre_attack_ids, "[]"),
        "tactics": _loads(rule.tactics, "[]"),
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _write_rule(db, rule: Rule, data: dict) -> Rule:
    if "name" in data and data["name"]:
        rule.name = data["name"]
    if "description" in data:
        rule.description = data.get("description") or ""
    if "enabled" in data:
        rule.enabled = bool(data["enabled"])
    if "severity" in data and data["severity"] is not None:
        rule.severity = int(data["severity"])
    if "tags" in data:
        rule.tags = json.dumps(list(data["tags"] or []), ensure_ascii=False)
    if "conditions" in data:
        rule.conditions = json.dumps(list(data["conditions"] or []), ensure_ascii=False)
    if "correlation" in data:
        corr = data["correlation"]
        rule.correlation = json.dumps(corr, ensure_ascii=False) if corr else "{}"
    if "action_flags" in data:
        rule.action_flags = json.dumps(dict(data["action_flags"] or {}), ensure_ascii=False)
    if "mitre_attack_ids" in data:
        rule.mitre_attack_ids = json.dumps(list(data["mitre_attack_ids"] or []), ensure_ascii=False)
    if "tactics" in data:
        rule.tactics = json.dumps(list(data["tactics"] or []), ensure_ascii=False)
    db.commit()
    db.refresh(rule)
    return rule


def _get_owned_rule(db, request: Request, rule_id: int) -> Rule:
    tenant_id = get_tenant_id(request)
    is_api_key = bool(request.headers.get("x-api-key"))
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    if rule.tenant_id is None:
        if not is_api_key:
            raise HTTPException(status_code=403,
                                detail="Règle globale : modification réservée à l'API key")
        return rule
    if rule.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return rule


# ── Routes (ordre : /test et /matches AVANT /{rule_id}) ──────────────

@router.get("")
def list_rules(request: Request, db: Session = Depends(get_db), enabled_only: bool = False):
    tenant_id = get_tenant_id(request)
    rules = visible_rules(db, tenant_id)
    if enabled_only:
        rules = [r for r in rules if r.enabled]
    rules.sort(key=lambda r: (r.tenant_id is not None, r.name.lower()))
    return [_rule_to_dict(r) for r in rules]


@router.post("", status_code=201)
def create_rule(body: RuleCreate, request: Request, db: Session = Depends(get_db),
                _=Depends(has_scopes_or_api_key(["admin:manage"]))):
    tenant_id = get_tenant_id(request)
    is_api_key = bool(request.headers.get("x-api-key"))
    rule = Rule(
        tenant_id=None if is_api_key else tenant_id,
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        severity=body.severity,
        tags=json.dumps(body.tags, ensure_ascii=False),
        conditions=json.dumps([c.model_dump() for c in body.conditions], ensure_ascii=False),
        correlation=json.dumps(body.correlation.model_dump(), ensure_ascii=False)
        if body.correlation else "{}",
        action_flags=json.dumps(body.action_flags, ensure_ascii=False),
        mitre_attack_ids=json.dumps(body.mitre_attack_ids, ensure_ascii=False),
        tactics=json.dumps(body.tactics, ensure_ascii=False),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    invalidate_rules_cache()
    return _rule_to_dict(rule)


@router.post("/test")
def test_rule(body: RuleTestRequest, request: Request,
              _=Depends(has_scopes_or_api_key(["admin:manage"]))):
    """Dry-run : évalue un échantillon d'alerte contre une définition de règle (non persistée)."""
    tenant_id = get_tenant_id(request)
    rule_def = body.rule
    normalized = build_normalized_alert({**body.sample_alert, "tenant_id": tenant_id})
    conditions = [c.model_dump() for c in rule_def.conditions]
    matched = evaluate_conditions(conditions, normalized)
    corr = rule_def.correlation
    corr_info = None
    if corr and (len(corr.sequence) >= 2 or corr.count):
        if corr.count:
            corr_info = {
                "configured": True,
                "note": (f"Agrégat de {corr.count} matches sur "
                         f"{corr.threshold_window_seconds or corr.window_seconds}s — "
                         f"le déclenchement nécessite le compteur persistant (corrélateur)."),
            }
        else:
            corr_info = {
                "configured": True,
                "note": (f"Séquence de {len(corr.sequence)} conditions sur {corr.window_seconds}s — "
                         f"la validation séquentielle nécessite l'historique du pipeline (corrélateur)."),
            }
    return {
        "matched": bool(conditions) and len(matched) == len(conditions),
        "matched_conditions": matched,
        "condition_count": len(conditions),
        "normalized_alert": normalized,
        "correlation": corr_info or ({"configured": False} if corr else None),
    }


@router.get("/matches")
def recent_matches(request: Request, db: Session = Depends(get_db), limit: int = 20):
    tenant_id = get_tenant_id(request)
    rows = (
        db.query(RuleMatchOutbox)
        .filter(RuleMatchOutbox.tenant_id == tenant_id)
        .order_by(RuleMatchOutbox.created_at.desc())
        .limit(min(limit, 100))
        .all()
    )
    out = []
    for row in rows:
        try:
            out.append(json.loads(row.payload))
        except (TypeError, ValueError):
            out.append({"event_id": row.event_id, "tenant_id": row.tenant_id,
                        "payload": row.payload})
    return out


@router.get("/coverage", dependencies=[Depends(require_role("analyst"))])
def mitre_coverage(request: Request, db: Session = Depends(get_db)):
    """R2 — Couverture MITRE ATT&CK des règles ENABLED (scoping tenant).

    Contrat VERROUILLÉ (consommé par le frontend MitrePage) :
    {"tactics": {"<tactic>": {"total_rules": int,
                              "techniques": {"<TID>": {"name": str, "rule_count": int}}}}}
    """
    ensure_mitre_columns(db)
    tenant_id = get_tenant_id(request)
    rules = (
        db.query(Rule)
        .filter(Rule.enabled == True)  # noqa: E712
        .filter((Rule.tenant_id == tenant_id) | (Rule.tenant_id.is_(None)))
        .all()
    )
    tactics: dict = {}
    for rule in rules:
        ids = _loads(rule.mitre_attack_ids, "[]")
        if not isinstance(ids, list) or not ids:
            continue
        rule_tactics = _loads(rule.tactics, "[]")
        if not isinstance(rule_tactics, list) or not rule_tactics:
            rule_tactics = mitre_tactics_for(ids)
        parents = {mitre_parent(t) for t in ids}
        for tactic in rule_tactics:
            entry = tactics.setdefault(tactic, {"total_rules": 0, "techniques": {}})
            entry["total_rules"] += 1
            for parent in parents:
                info = mitre_technique_info(parent)
                tech = entry["techniques"].setdefault(
                    parent, {"name": info["name"], "rule_count": 0})
                tech["rule_count"] += 1
    return {"tactics": tactics}


@router.get("/{rule_id}")
def get_rule(rule_id: int, request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    if rule.tenant_id is not None and rule.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return _rule_to_dict(rule)


@router.put("/{rule_id}")
def update_rule(rule_id: int, body: RuleUpdate, request: Request, db: Session = Depends(get_db),
                _=Depends(has_scopes_or_api_key(["admin:manage"]))):
    rule = _get_owned_rule(db, request, rule_id)
    data = body.model_dump(exclude_unset=True)
    if "conditions" in data and data["conditions"] is not None:
        data["conditions"] = [c.model_dump() for c in data["conditions"]]
    if "correlation" in data and data["correlation"] is not None:
        data["correlation"] = data["correlation"].model_dump()
    _write_rule(db, rule, data)
    invalidate_rules_cache()
    return _rule_to_dict(rule)


@router.delete("/{rule_id}")
def delete_rule(rule_id: int, request: Request, db: Session = Depends(get_db),
                _=Depends(has_scopes_or_api_key(["admin:manage"]))):
    rule = _get_owned_rule(db, request, rule_id)
    db.delete(rule)
    db.commit()
    invalidate_rules_cache()
    return {"status": "deleted", "id": rule_id}
