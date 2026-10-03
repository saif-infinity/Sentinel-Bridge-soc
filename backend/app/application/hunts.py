"""F2 — Logique métier : hunting.

Réutilise l'évaluateur F1 (evaluate_conditions + build_normalized_from_row) :
aucun nouveau moteur, aucun SQL dialecte-spécifique, SQLite-safe.
"""
import json
import logging
import time
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..infrastructure.ollama.client import _sanitize
from ..models import Alert, Hunt, SuricataAlert
from .action_logger import log_action
from .rules.evaluator import OPS, evaluate_conditions
from .rules.engine import build_normalized_from_row

logger = logging.getLogger(__name__)

HUNT_TARGETS = ("alert", "suricata", "both")

VALID_FIELDS = {"src_ip", "dest_ip", "proto", "severity", "normalized_severity",
                "signature", "event_type", "agent_id", "source"}
VALID_OPS = {"eq", "ne", "gt", "ge", "lt", "le", "in", "contains",
             "startswith", "regex", "exists"}
PRIMITIVE_TYPES = (str, int, float, bool, type(None))


def _jloads(s, fallback):
    try:
        return json.loads(s or fallback)
    except (TypeError, ValueError):
        return json.loads(fallback)


def _hunt_to_dict(h: Hunt) -> dict:
    return {
        "id": h.id,
        "tenant_id": h.tenant_id,
        "name": h.name,
        "description": h.description,
        "target": h.target,
        "conditions": _jloads(h.conditions, "[]"),
        "created_by": h.created_by,
        "created_at": h.created_at.isoformat() if h.created_at else None,
        "updated_at": h.updated_at.isoformat() if h.updated_at else None,
        "last_run_at": h.last_run_at.isoformat() if h.last_run_at else None,
        "last_run_by": h.last_run_by,
        "last_run_count": h.last_run_count,
        "last_run_duration_ms": h.last_run_duration_ms,
        "last_error": h.last_error,
    }


def _hunt_or_404(db, tenant_id: str, hunt_id: int) -> Hunt:
    h = db.query(Hunt).filter(Hunt.id == hunt_id,
                              Hunt.tenant_id == tenant_id).first()
    if h is None:
        raise HTTPException(status_code=404, detail="Chasse introuvable")
    return h


def _validate_conditions(conditions) -> list:
    if not isinstance(conditions, list) or not conditions:
        raise HTTPException(status_code=422,
                            detail="Au moins une condition est requise")
    out = []
    for cond in conditions:
        if not isinstance(cond, dict) or not cond.get("field"):
            raise HTTPException(status_code=422,
                                detail="Chaque condition doit avoir un champ 'field'")
        op = str(cond.get("op") or "eq")
        if op not in OPS:
            raise HTTPException(status_code=422, detail=f"Opérateur inconnu : {op}")
        out.append({"field": str(cond["field"])[:100],
                    "op": op, "value": cond.get("value")})
    return out


# ── CRUD ────────────────────────────────────────────────────────────

def list_hunts(db, tenant_id: str) -> list:
    rows = (db.query(Hunt).filter(Hunt.tenant_id == tenant_id)
            .order_by(Hunt.updated_at.desc()).limit(200).all())
    return [_hunt_to_dict(h) for h in rows]


def get_hunt(db, tenant_id: str, hunt_id: int) -> dict:
    return _hunt_to_dict(_hunt_or_404(db, tenant_id, hunt_id))


def create_hunt(db, tenant_id: str, username: str, data: dict) -> dict:
    name = str(data.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422,
                            detail="Le nom de la chasse est requis")
    target = str(data.get("target") or "both").lower()
    if target not in HUNT_TARGETS:
        raise HTTPException(status_code=422,
                            detail="Cible invalide (alert | suricata | both)")
    conditions = _validate_conditions(data.get("conditions"))
    h = Hunt(
        tenant_id=tenant_id,
        name=name[:200],
        description=str(data.get("description") or "")[:2000],
        target=target,
        conditions=json.dumps(conditions, ensure_ascii=False),
        created_by=username,
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    result = _hunt_to_dict(h)
    log_action(db, username, "hunts.save",
               details=f"Chasse enregistrée : {name}",
               resource=f"hunt:{h.id}", tenant_id=tenant_id)
    return result


def update_hunt(db, tenant_id: str, username: str, hunt_id: int,
                data: dict) -> dict:
    h = _hunt_or_404(db, tenant_id, hunt_id)
    changed: list = []
    if "name" in data and str(data.get("name") or "").strip():
        h.name = str(data["name"]).strip()[:200]
        changed.append("name")
    if "description" in data:
        h.description = str(data.get("description") or "")[:2000]
        changed.append("description")
    if "target" in data and data["target"]:
        target = str(data["target"]).lower()
        if target not in HUNT_TARGETS:
            raise HTTPException(status_code=422,
                                detail="Cible invalide (alert | suricata | both)")
        h.target = target
        changed.append("target")
    if "conditions" in data:
        h.conditions = json.dumps(_validate_conditions(data["conditions"]),
                                  ensure_ascii=False)
        changed.append("conditions")
    if not changed:
        raise HTTPException(status_code=422,
                            detail="Aucun champ modifiable fourni")
    db.commit()
    db.refresh(h)
    result = _hunt_to_dict(h)
    log_action(db, username, "hunts.save",
               details=f"Chasse #{h.id} mise à jour : {', '.join(changed)}",
               resource=f"hunt:{h.id}", tenant_id=tenant_id)
    return result


def delete_hunt(db, tenant_id: str, username: str, hunt_id: int) -> dict:
    h = _hunt_or_404(db, tenant_id, hunt_id)
    db.delete(h)
    db.commit()
    log_action(db, username, "hunts.delete",
               details=f"Chasse #{hunt_id} supprimée",
               resource=f"hunt:{hunt_id}", tenant_id=tenant_id)
    return {"status": "deleted", "id": hunt_id}


# ── Exécution ───────────────────────────────────────────────────────

def _iter_target_rows(db, tenant_id: str, target: str, limit: int):
    """Itère les lignes Alert/SuricataAlert du tenant (plus récentes d'abord)."""
    if target in ("alert", "both"):
        for row in (db.query(Alert).filter(Alert.tenant_id == tenant_id)
                    .order_by(Alert.timestamp.desc()).limit(limit).all()):
            yield row
    if target in ("suricata", "both"):
        for row in (db.query(SuricataAlert)
                    .filter(SuricataAlert.tenant_id == tenant_id)
                    .order_by(SuricataAlert.timestamp.desc()).limit(limit).all()):
            yield row


def run_hunt(db, tenant_id: str, username: str,
             hunt_id: int | None = None, conditions: list | None = None,
             target: str = "both", limit: int = 500,
             preview: bool = False) -> dict:
    """Exécute une chasse. hunt_id → chasse enregistrée ; preview=True → non persistée."""
    limit = min(max(limit, 1), 1000)
    if preview and hunt_id is not None:
        raise HTTPException(status_code=422,
                            detail="preview ne peut pas cibler une chasse enregistrée")
    if not preview:
        h = _hunt_or_404(db, tenant_id, hunt_id) if hunt_id else None
        conds = (_validate_conditions(_jloads(h.conditions, "[]")) if h
                 else _validate_conditions(conditions))
        tgt = h.target if h else target
    else:
        h = None
        conds = _validate_conditions(conditions)
        tgt = target
    if tgt not in HUNT_TARGETS:
        raise HTTPException(status_code=422,
                            detail="Cible invalide (alert | suricata | both)")

    started = time.monotonic()
    matched: list = []
    total_matched = 0
    last_error = None
    try:
        for row in _iter_target_rows(db, tenant_id, tgt, limit):
            try:
                normalized = build_normalized_from_row(row)
            except Exception:
                continue
            if len(evaluate_conditions(conds, normalized)) == len(conds):
                total_matched += 1
                if len(matched) < 100:
                    matched.append({
                        "alert_type": "suricata" if isinstance(row, SuricataAlert) else "alert",
                        "alert_id": row.id,
                        "timestamp": normalized.get("timestamp"),
                        "source": normalized.get("source"),
                        "normalized_severity": normalized.get("normalized_severity"),
                        "severity": normalized.get("severity"),
                        "signature": normalized.get("signature"),
                        "src_ip": normalized.get("src_ip"),
                        "dest_ip": normalized.get("dest_ip"),
                        "agent_id": normalized.get("agent_id"),
                        "proto": normalized.get("proto"),
                    })
    except Exception as e:
        last_error = str(e)[:2000]
        logger.warning("Hunt run: %s", e)

    duration_ms = int((time.monotonic() - started) * 1000)

    if not preview:
        if h is not None:
            h.last_run_at = datetime.now(timezone.utc)
            h.last_run_by = username
            h.last_run_count = total_matched
            h.last_run_duration_ms = duration_ms
            h.last_error = last_error
            db.commit()
            db.refresh(h)
        log_action(db, username, "hunts.run",
                   details=f"Chasse exécutée : {total_matched} résultat(s) en {duration_ms}ms",
                   resource=f"hunt:{h.id if h else 'draft'}", tenant_id=tenant_id)

    return {
        "hunt": _hunt_to_dict(h) if (not preview and h is not None) else None,
        "preview": preview,
        "conditions": conds,
        "target": tgt,
        "scanned": limit,
        "matched": total_matched,
        "duration_ms": duration_ms,
        "error": last_error,
        "results": matched,
    }


# ── AI-Generated Hunt Proposals (non-persisting) ────────────────

def _build_prompt(wazuh_alerts: list, suricata_alerts: list) -> str:
    wazuh_lines = []
    for a in wazuh_alerts:
        wazuh_lines.append(
            f"- Level {a.severity}: {_sanitize(a.description)} "
            f"(src: {a.src_ip}, agent: {a.agent_id})"
        )
    suricata_lines = []
    for a in suricata_alerts:
        suricata_lines.append(
            f"- S{a.severity}: {_sanitize(a.alert_msg)} "
            f"({a.src_ip}->{a.dest_ip} {a.proto})"
        )
    return f"""Tu es un analyste SOC senior. Génère des propositions de chasses aux menaces basées sur les alertes critiques récentes.

Alertes Wazuh critiques:
{chr(10).join(wazuh_lines) if wazuh_lines else "Aucune"}

Alertes Suricata critiques:
{chr(10).join(suricata_lines) if suricata_lines else "Aucune"}

Règles strictes :
- Réponds UNIQUEMENT un tableau JSON d'exemples de propositions de chasse. Aucun markdown, aucun texte autour.
- Chaque proposition : {{"name": str, "description": str, "target": "alert"|"suricata"|"both", "conditions": [{{"field": str, "op": str, "value": object}}]}}
- Champ autorisés : src_ip, dest_ip, proto, severity, normalized_severity, signature, event_type, agent_id, source
- Opérateurs autorisés : eq, ne, gt, ge, lt, le, in, contains, startswith, regex, exists
- 1 à 5 propositions max
- Conditions basées sur les patterns observés (même src_ip, même signature, proto suspect, etc.)

Exemple de sortie valide :
[{{"name": "Même IP source répétée", "description": "Détecte les alertes depuis une IP source apparaissant plusieurs fois dans les alertes critiques", "target": "alert", "conditions": [{{"field": "src_ip", "op": "in", "value": "10.0.0.5"}}]}}]"""


def _parse_ollama_response(text: str) -> list:
    """Extrait un JSON tableau de la réponse Ollama, très tolérant."""
    if not text:
        return []
    first_bracket = text.find("[")
    last_bracket = text.rfind("]")
    if first_bracket == -1 or last_bracket == -1 or last_bracket <= first_bracket:
        return []
    json_str = text[first_bracket:last_bracket + 1]
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return []


def _normalize_proposals(raw: list) -> list:
    """Norme les propositions du LLM : filtre, tronque, force les champs."""
    proposals = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        desc = p.get("description")
        if not isinstance(desc, str):
            desc = str(desc) if desc is not None else ""
        desc = desc[:500]
        target = p.get("target")
        if target not in HUNT_TARGETS:
            target = "both"
        raw_conds = p.get("conditions", [])
        if not isinstance(raw_conds, list):
            raw_conds = []
        conds = []
        for c in raw_conds[:10]:
            if not isinstance(c, dict):
                continue
            field = c.get("field")
            op = c.get("op")
            if field not in VALID_FIELDS or op not in VALID_OPS:
                continue
            value = c.get("value")
            if value is not None and not isinstance(value, PRIMITIVE_TYPES):
                value = str(value)
            conds.append({"field": str(field)[:100], "op": str(op), "value": value})
        proposals.append({
            "name": name.strip()[:200],
            "description": desc,
            "target": target,
            "conditions": conds[:10],
        })
    return proposals[:5]


def generate_ai_hunt_proposals(db: Session, tenant_id: str) -> dict:
    """Génère des propositions de chasse via Ollama sans persister.

    Retourne {"proposals": [...]} ou {"proposals": [], "notice": "..."}
    si aucune alerte critique. Lève HTTPException 503 si Ollama est down.
    """
    wazuh_alerts = (
        db.query(Alert)
        .filter(Alert.severity >= 7, Alert.tenant_id == tenant_id)
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )
    suricata_alerts = (
        db.query(SuricataAlert)
        .filter(SuricataAlert.severity >= 7, SuricataAlert.tenant_id == tenant_id)
        .order_by(SuricataAlert.timestamp.desc())
        .limit(5)
        .all()
    )
    if not wazuh_alerts and not suricata_alerts:
        return {"proposals": [], "notice": "Aucune alerte critique récente (Wazuh/Suricata ≥ 7) à analyser"}

    prompt = _build_prompt(wazuh_alerts, suricata_alerts)

    from ..infrastructure.ollama.client import _call_ollama
    try:
        raw_text = _call_ollama(prompt)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail="IA indisponible : lancez ollama serve")

    raw_proposals = _parse_ollama_response(raw_text)
    proposals = _normalize_proposals(raw_proposals)
    return {"proposals": proposals}
