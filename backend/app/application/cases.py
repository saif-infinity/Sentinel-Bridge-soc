"""F2 — Logique métier : gestion des affaires (cases), triage, timeline.

Toute la logique vit ici (routers minces). Scoping : tenant_id STRICT.
Identité : username STRING (JWT sub / api_key) — pas de FK vers User.
Chaque action significative écrit une ligne ActionLog via log_action().
Note : log_action() COMMIT en interne → construire la réponse AVANT l'appel.
"""
import json
import logging
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, or_

from ..models import Alert, Case, CaseAlertLink, SuricataAlert, TimelineEvent
from .action_logger import log_action

logger = logging.getLogger(__name__)

CASE_STATUSES = ("open", "in_progress", "resolved", "closed")
LINK_STATUSES = ("open", "in_progress", "resolved", "dismissed")


def _now():
    return datetime.now(timezone.utc)


def _jloads(s, fallback):
    try:
        v = json.loads(s or fallback)
    except (TypeError, ValueError):
        v = json.loads(fallback)
    return v


def _case_to_dict(case, links_count: int = 0, open_links_count: int = 0) -> dict:
    return {
        "id": case.id,
        "tenant_id": case.tenant_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "assignee": case.assignee,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
        "closed_by": case.closed_by,
        "links_count": links_count,
        "open_links_count": open_links_count,
    }


def _timeline_to_dict(ev) -> dict:
    return {
        "id": ev.id,
        "case_id": ev.case_id,
        "event_type": ev.event_type,
        "actor": ev.actor,
        "message": ev.message,
        "meta": _jloads(ev.meta, "null"),
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
    }


def _case_or_404(db, tenant_id: str, case_id: int) -> Case:
    case = db.query(Case).filter(Case.id == case_id,
                                 Case.tenant_id == tenant_id).first()
    if case is None:
        raise HTTPException(status_code=404, detail="Affaire introuvable")
    return case


def _link_or_404(db, tenant_id: str, case_id: int, link_id: int) -> CaseAlertLink:
    link = (db.query(CaseAlertLink)
            .filter(CaseAlertLink.id == link_id,
                    CaseAlertLink.case_id == case_id,
                    CaseAlertLink.tenant_id == tenant_id)
            .first())
    if link is None:
        raise HTTPException(status_code=404, detail="Lien alerte-affaire introuvable")
    return link


def _resolve_alert(db, tenant_id: str, alert_type: str, alert_id: int):
    model = SuricataAlert if alert_type == "suricata" else (Alert if alert_type == "alert" else None)
    if model is None:
        raise HTTPException(status_code=422,
                            detail="alert_type doit être 'alert' ou 'suricata'")
    row = db.query(model).filter(model.id == alert_id,
                                 model.tenant_id == tenant_id).first()
    if row is None:
        raise HTTPException(status_code=404,
                            detail="Alerte introuvable dans ce tenant")
    return row


def _alert_to_snapshot(row) -> dict | None:
    """Snapshot normalisé d'une alerte (Alert ou SuricataAlert) — forme uniforme."""
    if isinstance(row, SuricataAlert):
        return {
            "alert_type": "suricata", "alert_id": row.id,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "severity": row.severity, "normalized_severity": row.normalized_severity,
            "signature": row.alert_msg, "event_type": row.event_type,
            "src_ip": row.src_ip, "dest_ip": row.dest_ip, "proto": row.proto,
            "agent_id": None, "source": row.pipeline_source or "suricata",
        }
    if isinstance(row, Alert):
        return {
            "alert_type": "alert", "alert_id": row.id,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "severity": row.severity, "normalized_severity": row.normalized_severity,
            "signature": row.description, "event_type": None,
            "src_ip": row.src_ip, "dest_ip": None, "proto": None,
            "agent_id": row.agent_id, "source": row.pipeline_source or "wazuh",
        }
    return None


def _add_timeline(db, tenant_id: str, case_id: int, event_type: str,
                  actor: str, message: str, meta: dict | None = None) -> TimelineEvent:
    ev = TimelineEvent(
        tenant_id=tenant_id,
        case_id=case_id,
        event_type=event_type,
        actor=actor,
        message=message,
        meta=json.dumps(meta, ensure_ascii=False) if meta else None,
    )
    db.add(ev)
    return ev


def _link_to_dict(db, tenant_id: str, link: CaseAlertLink) -> dict:
    row = _resolve_alert(db, tenant_id, link.alert_type, link.alert_id)
    item = _alert_to_snapshot(row)
    item["link_id"] = link.id
    item["link_status"] = link.status
    item["link_note"] = link.note
    item["triaged_by"] = link.triaged_by
    item["triaged_at"] = link.triaged_at.isoformat() if link.triaged_at else None
    item["linked_at"] = link.created_at.isoformat() if link.created_at else None
    item["linked_by"] = link.created_by
    return item


# ── Cases CRUD ──────────────────────────────────────────────────────

def list_cases(db, tenant_id: str, status: str | None = None,
               assignee: str | None = None, severity_min: int | None = None,
               q: str | None = None, limit: int = 100, offset: int = 0) -> dict:
    query = db.query(Case).filter(Case.tenant_id == tenant_id)
    if status:
        query = query.filter(Case.status == status)
    if assignee:
        query = query.filter(Case.assignee == assignee)
    if severity_min is not None:
        query = query.filter(Case.severity >= int(severity_min))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Case.title.ilike(like),
                                 Case.description.ilike(like)))
    total = query.count()
    rows = query.order_by(Case.updated_at.desc()) \
                .offset(offset).limit(min(limit, 500)).all()

    link_counts = dict(db.query(CaseAlertLink.case_id, func.count(CaseAlertLink.id))
                       .filter(CaseAlertLink.tenant_id == tenant_id)
                       .group_by(CaseAlertLink.case_id).all())
    open_counts = dict(db.query(CaseAlertLink.case_id, func.count(CaseAlertLink.id))
                       .filter(CaseAlertLink.tenant_id == tenant_id,
                               CaseAlertLink.status.in_(("open", "in_progress")))
                       .group_by(CaseAlertLink.case_id).all())
    items = [_case_to_dict(c, link_counts.get(c.id, 0), open_counts.get(c.id, 0))
             for c in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def create_case(db, tenant_id: str, username: str, data: dict) -> dict:
    title = str(data.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=422, detail="Le titre de l'affaire est requis")
    status_val = data.get("status") or "open"
    if status_val not in CASE_STATUSES:
        raise HTTPException(status_code=422, detail="Statut d'affaire invalide")
    case = Case(
        tenant_id=tenant_id,
        title=title[:200],
        description=str(data.get("description") or "")[:4000],
        status=status_val,
        severity=max(0, min(15, int(data.get("severity") or 5))),
        assignee=str(data.get("assignee") or "").strip()[:100] or None,
        created_by=username,
    )
    db.add(case)
    db.flush()  # obtient case.id sans commit
    _add_timeline(db, tenant_id, case.id, "created", username,
                  f"Affaire créée : {title}")
    db.commit()
    db.refresh(case)
    result = _case_to_dict(case)
    log_action(db, username, "cases.create",
               details=f"Affaire créée : {title}",
               resource=f"case:{case.id}", tenant_id=tenant_id)
    return result


def get_case(db, tenant_id: str, case_id: int) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    link_counts = db.query(func.count(CaseAlertLink.id)).filter(
        CaseAlertLink.case_id == case_id,
        CaseAlertLink.tenant_id == tenant_id).scalar() or 0
    open_counts = db.query(func.count(CaseAlertLink.id)).filter(
        CaseAlertLink.case_id == case_id,
        CaseAlertLink.tenant_id == tenant_id,
        CaseAlertLink.status.in_(("open", "in_progress"))).scalar() or 0
    return _case_to_dict(case, link_counts, open_counts)


def update_case(db, tenant_id: str, username: str, case_id: int, data: dict) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    changed: list = []
    if "title" in data and str(data.get("title") or "").strip():
        case.title = str(data["title"]).strip()[:200]
        changed.append("title")
    if "description" in data:
        case.description = str(data.get("description") or "")[:4000]
        changed.append("description")
    if "status" in data and data["status"]:
        new_status = data["status"]
        if new_status not in CASE_STATUSES:
            raise HTTPException(status_code=422, detail="Statut d'affaire invalide")
        if new_status != case.status:
            old_status = case.status
            case.status = new_status
            _add_timeline(db, tenant_id, case.id, "status_changed", username,
                          f"Statut modifié : {old_status} → {new_status}",
                          {"from": old_status, "to": new_status})
            if new_status == "closed":
                case.closed_at = _now()
                case.closed_by = username
            elif new_status != "closed":
                case.closed_at = None
                case.closed_by = None
            changed.append("status")
    if "severity" in data and data["severity"] is not None:
        case.severity = max(0, min(15, int(data["severity"])))
        changed.append("severity")
    if "assignee" in data:
        case.assignee = str(data.get("assignee") or "").strip()[:100] or None
        changed.append("assignee")
    if not changed:
        raise HTTPException(status_code=422,
                            detail="Aucun champ modifiable fourni")
    db.commit()
    db.refresh(case)
    result = _case_to_dict(case)
    log_action(db, username, "cases.update",
               details=f"Affaire #{case.id} modifiée : {', '.join(changed)}",
               resource=f"case:{case.id}", tenant_id=tenant_id)
    return result


def close_case(db, tenant_id: str, username: str, case_id: int,
               resolution: str | None = None) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    if case.status == "closed":
        raise HTTPException(status_code=409,
                            detail="L'affaire est déjà clôturée")
    case.status = "closed"
    case.closed_at = _now()
    case.closed_by = username
    meta = {"resolution": resolution} if resolution else None
    _add_timeline(db, tenant_id, case.id, "closed", username,
                  resolution or "Affaire clôturée", meta)
    db.commit()
    db.refresh(case)
    result = _case_to_dict(case)
    log_action(db, username, "cases.close",
               details=f"Affaire #{case.id} clôturée",
               resource=f"case:{case.id}", tenant_id=tenant_id)
    return result


def reopen_case(db, tenant_id: str, username: str, case_id: int) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    if case.status != "closed":
        raise HTTPException(status_code=409,
                            detail="L'affaire n'est pas clôturée")
    case.status = "open"
    case.closed_at = None
    case.closed_by = None
    _add_timeline(db, tenant_id, case.id, "reopened", username,
                  "Affaire réouverte")
    db.commit()
    db.refresh(case)
    result = _case_to_dict(case)
    log_action(db, username, "cases.reopen",
               details=f"Affaire #{case.id} réouverte",
               resource=f"case:{case.id}", tenant_id=tenant_id)
    return result


def delete_case(db, tenant_id: str, username: str, case_id: int) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    # Cascade manuelle (FK en Postgres) : enfants d'abord, puis la case.
    db.query(TimelineEvent).filter(
        TimelineEvent.case_id == case_id,
        TimelineEvent.tenant_id == tenant_id).delete()
    db.query(CaseAlertLink).filter(
        CaseAlertLink.case_id == case_id,
        CaseAlertLink.tenant_id == tenant_id).delete()
    db.delete(case)
    db.commit()
    log_action(db, username, "cases.delete",
               details=f"Affaire #{case_id} supprimée (liens + timeline inclus)",
               resource=f"case:{case_id}", tenant_id=tenant_id)
    return {"status": "deleted", "id": case_id}


def case_stats(db, tenant_id: str) -> dict:
    rows = db.query(Case.status, func.count(Case.id)).filter(
        Case.tenant_id == tenant_id).group_by(Case.status).all()
    counts = {s: 0 for s in CASE_STATUSES}
    for status_val, n in rows:
        counts[status_val] = n
    high = db.query(func.count(Case.id)).filter(
        Case.tenant_id == tenant_id, Case.severity >= 8,
        Case.status.in_(("open", "in_progress", "resolved"))).scalar() or 0
    counts["total"] = sum(counts[s] for s in CASE_STATUSES)
    counts["high_severity_active"] = high
    return counts


# ── Alertes liées + triage ──────────────────────────────────────────

def linkable_alerts(db, tenant_id: str, source: str | None = None,
                    limit: int = 50) -> list:
    limit = min(max(limit, 1), 200)
    out: list = []
    if source in (None, "", "alert"):
        for row in (db.query(Alert).filter(Alert.tenant_id == tenant_id)
                    .order_by(Alert.timestamp.desc()).limit(limit).all()):
            snap = _alert_to_snapshot(row)
            if snap:
                out.append(snap)
    if source in (None, "", "suricata"):
        for row in (db.query(SuricataAlert)
                    .filter(SuricataAlert.tenant_id == tenant_id)
                    .order_by(SuricataAlert.timestamp.desc()).limit(limit).all()):
            snap = _alert_to_snapshot(row)
            if snap:
                out.append(snap)
    out.sort(key=lambda a: a["timestamp"] or "", reverse=True)
    return out


def list_case_alerts(db, tenant_id: str, case_id: int) -> list:
    _case_or_404(db, tenant_id, case_id)
    links = (db.query(CaseAlertLink)
             .filter(CaseAlertLink.case_id == case_id,
                     CaseAlertLink.tenant_id == tenant_id)
             .order_by(CaseAlertLink.created_at.desc())
             .all())
    return [_link_to_dict(db, tenant_id, link) for link in links]


def link_alert(db, tenant_id: str, username: str, case_id: int,
               alert_type: str, alert_id: int) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    _resolve_alert(db, tenant_id, alert_type, alert_id)
    dup = (db.query(CaseAlertLink)
           .filter(CaseAlertLink.case_id == case_id,
                   CaseAlertLink.alert_type == alert_type,
                   CaseAlertLink.alert_id == alert_id,
                   CaseAlertLink.tenant_id == tenant_id)
           .first())
    if dup is not None:
        raise HTTPException(status_code=409,
                            detail="Cette alerte est déjà liée à l'affaire")
    link = CaseAlertLink(
        tenant_id=tenant_id, case_id=case_id,
        alert_type=alert_type, alert_id=alert_id,
        status="open", created_by=username,
    )
    db.add(link)
    db.flush()
    _add_timeline(db, tenant_id, case_id, "alert_linked", username,
                  f"Alerte {alert_type}#{alert_id} liée à l'affaire « {case.title} »",
                  {"alert_type": alert_type, "alert_id": alert_id})
    db.commit()
    db.refresh(link)
    result = _link_to_dict(db, tenant_id, link)
    log_action(db, username, "cases.link_alert",
               details=f"Alerte {alert_type}#{alert_id} liée à l'affaire #{case_id}",
               resource=f"case:{case_id}", tenant_id=tenant_id)
    return result


def unlink_alert(db, tenant_id: str, username: str, case_id: int,
                 link_id: int) -> dict:
    link = _link_or_404(db, tenant_id, case_id, link_id)
    alert_ref = f"{link.alert_type}#{link.alert_id}"
    db.delete(link)
    _add_timeline(db, tenant_id, case_id, "alert_unlinked", username,
                  f"Alerte {alert_ref} retirée de l'affaire")
    db.commit()
    log_action(db, username, "cases.unlink_alert",
               details=f"Alerte {alert_ref} retirée de l'affaire #{case_id}",
               resource=f"case:{case_id}", tenant_id=tenant_id)
    return {"status": "unlinked", "case_id": case_id, "link_id": link_id}


def triage_alert(db, tenant_id: str, username: str, case_id: int, link_id: int,
                 new_status: str, note: str | None = None) -> dict:
    """Transition de triage : open/in_progress/resolved/dismissed sur la LIGNE de lien."""
    link = _link_or_404(db, tenant_id, case_id, link_id)
    if new_status not in LINK_STATUSES:
        raise HTTPException(status_code=422, detail="Statut de triage invalide")
    old_status = link.status
    link.status = new_status
    if note is not None:
        link.note = str(note).strip()[:2000] or None
    link.triaged_by = username
    link.triaged_at = _now()
    _add_timeline(db, tenant_id, case_id, "alert_triaged", username,
                  f"Alerte {link.alert_type}#{link.alert_id} : {old_status} → {new_status}",
                  {"from": old_status, "to": new_status, "note": link.note})
    db.commit()
    db.refresh(link)
    result = _link_to_dict(db, tenant_id, link)
    log_action(db, username, "cases.triage",
               details=f"Alerte {link.alert_type}#{link.alert_id} triée : {new_status}",
               resource=f"case:{case_id}", tenant_id=tenant_id)
    return result


# ── Timeline ────────────────────────────────────────────────────────

def list_timeline(db, tenant_id: str, case_id: int, limit: int = 100) -> list:
    _case_or_404(db, tenant_id, case_id)
    rows = (db.query(TimelineEvent)
            .filter(TimelineEvent.case_id == case_id,
                    TimelineEvent.tenant_id == tenant_id)
            .order_by(TimelineEvent.created_at.desc())
            .limit(min(limit, 500))
            .all())
    return [_timeline_to_dict(ev) for ev in rows]


def add_timeline_note(db, tenant_id: str, username: str, case_id: int,
                      note: str) -> dict:
    case = _case_or_404(db, tenant_id, case_id)
    note = str(note or "").strip()
    if not note:
        raise HTTPException(status_code=422, detail="La note est vide")
    ev = _add_timeline(db, tenant_id, case_id, "note_added", username, note[:4000])
    db.commit()
    db.refresh(ev)
    result = _timeline_to_dict(ev)
    log_action(db, username, "cases.note",
               details=f"Note ajoutée à l'affaire #{case_id}",
               resource=f"case:{case.id}", tenant_id=tenant_id)
    return result
