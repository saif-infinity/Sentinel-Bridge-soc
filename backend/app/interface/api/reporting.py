"""F5 — Routes API : reports and templates."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_db, get_tenant_id, query_with_tenant
from ...domain.reporting import Report, ReportTemplate, ReportSchedule, ReportRecipient
from ...models import Alert, SuricataAlert, Case, CaseAlertLink, PipelineEvent
from ...application.reporting import (
    generate_daily_report, generate_trends_report,
    generate_case_closure_report, generate_investigation_summary_report,
    send_report,
)
from ...application.system_config import get_config_value
from ...infrastructure.jobs.reporting_tasks import (
    generate_daily_report_task,
    generate_trends_report_task,
    deliver_pending_reports_task,
    process_scheduled_reports_task,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reporting", tags=["Reporting"],
                   dependencies=[Depends(get_api_key_or_jwt)])

REPORT_WRITE = ["reporting:write"]


@router.get("/reports")
def list_reports(request: Request, db: Session = Depends(get_db),
                    report_type: Optional[str] = None,
                    status: Optional[str] = None,
                    case_id: Optional[int] = None,
                    limit: int = Query(default=100, le=500),
                    offset: int = 0):
    tenant_id = get_tenant_id(request)
    query = db.query(Report).filter(Report.tenant_id == tenant_id)
    if report_type:
        query = query.filter(Report.report_type == report_type)
    if status:
        query = query.filter(Report.status == status)
    if case_id is not None:
        query = query.filter(Report.case_id == case_id)
    total = query.count()
    items = query.order_by(Report.created_at.desc()).offset(offset).limit(min(limit, 500)).all()
    return {"items": [_report_to_dict(r) for r in items], "total": total}


@router.get("/reports/{id}")
def get_report(request: Request, id: int, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    report = db.query(Report).filter(Report.id == id, Report.tenant_id == tenant_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report introuvable")
    recipients = db.query(ReportRecipient).filter(
        ReportRecipient.report_id == id, ReportRecipient.tenant_id == tenant_id
    ).all()
    return {"report": _report_to_dict(report), "recipients": [_recipient_to_dict(r) for r in recipients]}


@router.post("/reports/generate/daily")
def generate_daily_endpoint(request: Request, db: Session = Depends(get_db),
                               params: Optional[dict] = None,
                               principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    p = params or {}
    days_back = p.get("days_back", 1) if isinstance(p, dict) else 1
    report = generate_daily_report(db, tenant_id=tenant_id, params={"days_back": days_back}, generated_by=str(principal.get("sub", "api_key")))
    db.commit()
    return {"status": "generated", "report_id": report.id}


@router.post("/reports/generate/trends")
def generate_trends_endpoint(request: Request, db: Session = Depends(get_db),
                                params: Optional[dict] = None,
                                principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    p = params or {}
    days_back = p.get("days_back", 30) if isinstance(p, dict) else 30
    report = generate_trends_report(db, tenant_id=tenant_id, params={"days_back": days_back}, generated_by=str(principal.get("sub", "api_key")))
    db.commit()
    return {"status": "generated", "report_id": report.id}


@router.post("/reports/generate/case_closure/{case_id}")
def generate_case_closure_endpoint(request: Request, case_id: int, db: Session = Depends(get_db),
                                      principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    report = generate_case_closure_report(db, tenant_id=tenant_id, case_id=case_id, generated_by=str(principal.get("sub", "api_key")))
    db.commit()
    return {"status": "generated", "report_id": report.id}


@router.post("/reports/generate/investigation_summary")
def generate_investigation_summary_endpoint(request: Request, db: Session = Depends(get_db),
                                               params: Optional[dict] = None,
                                               principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    p = params or {}
    days_back = p.get("days_back", 7) if isinstance(p, dict) else 7
    report = generate_investigation_summary_report(db, tenant_id=tenant_id, params={"days_back": days_back}, generated_by=str(principal.get("sub", "api_key")))
    db.commit()
    return {"status": "generated", "report_id": report.id}


@router.get("/reports/{id}/download")
def download_report(request: Request, id: int, db: Session = Depends(get_db),
                       format: Optional[str] = None):
    tenant_id = get_tenant_id(request)
    report = db.query(Report).filter(Report.id == id, Report.tenant_id == tenant_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report introuvable")
    if report.format == "csv":
        from ...application.reporting.templates import build_csv
        rows = []
        if report.content:
            rows = [{"content": report.content}]
        csv_content = build_csv(rows, report.title)
        from fastapi.responses import Response
        return Response(content=csv_content, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{report.title}.csv"'})
    return {"report_id": report.id, "format": report.format, "title": report.title}


@router.post("/reports/{id}/deliver")
def deliver_report_endpoint(request: Request, id: int, db: Session = Depends(get_db),
                               principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    report = db.query(Report).filter(Report.id == id, Report.tenant_id == tenant_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report introuvable")
    from ...application.reporting.delivery import send_report
    result = send_report(id, tenant_id)
    return {"status": "delivered" if result else "failed", "report_id": id}


@router.get("/templates")
def list_templates(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    templates = db.query(ReportTemplate).filter(ReportTemplate.tenant_id == tenant_id).all()
    return {"items": [_template_to_dict(t) for t in templates]}


@router.get("/schedules")
def list_schedules(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    schedules = db.query(ReportSchedule).filter(ReportSchedule.tenant_id == tenant_id).all()
    return {"items": [_schedule_to_dict(s) for s in schedules]}


@router.post("/schedules")
def create_schedule(request: Request, db: Session = Depends(get_db),
                       name: str = Query(...), report_type: str = Query(...),
                       cron_expr: str = Query(...), recipients: str = Query("[]"),
                       params: str = Query("{}"), principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    tenant_id = get_tenant_id(request)
    schedule = ReportSchedule(
        tenant_id=tenant_id, name=name, report_type=report_type,
        cron_expr=cron_expr, recipients=recipients, params=params,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return {"status": "created", "schedule_id": schedule.id}


@router.post("/reports/{id}/trigger")
def trigger_report_task(request: Request, id: int, db: Session = Depends(get_db),
                           task: str = Query(...), principal: dict = Depends(has_scopes_or_api_key(REPORT_WRITE))):
    """Trigger a Celery task for a report."""
    tenant_id = get_tenant_id(request)
    report = db.query(Report).filter(Report.id == id, Report.tenant_id == tenant_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report introuvable")

    if task == "generate_daily":
        generate_daily_report_task.delay()
    elif task == "generate_trends":
        generate_trends_report_task.delay()
    elif task == "deliver_pending":
        deliver_pending_reports_task.delay()
    elif task == "process_scheduled":
        process_scheduled_reports_task.delay()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown task: {task}")

    return {"status": "triggered", "task": task, "report_id": id}


@router.get("/metrics")
def get_metrics(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)

    # ── MTTD : temps moyen entre création alerte et association case ──
    mttd_minutes = None
    try:
        mttd_rows = (
            db.query(func.avg(
                func.extract('epoch', CaseAlertLink.created_at - Alert.timestamp) / 60.0
            ))
            .join(Alert, CaseAlertLink.alert_id == Alert.id)
            .filter(CaseAlertLink.tenant_id == tenant_id)
            .filter(Alert.timestamp >= thirty_days_ago)
            .all()
        )
        val = mttd_rows[0][0] if mttd_rows and mttd_rows[0][0] is not None else None
        if val is not None:
            mttd_minutes = round(val, 2)
    except Exception:
        mttd_minutes = None

    # ── MTTR : temps moyen entre création et fermeture d'une case ──
    mttr_minutes = None
    try:
        closed_cases = (
            db.query(Case)
            .filter(Case.tenant_id == tenant_id)
            .filter(Case.status.in_(("closed", "resolved")))
            .filter(Case.created_at.isnot(None))
            .all()
        )
        deltas = []
        for c in closed_cases:
            end_dt = c.closed_at or c.updated_at
            if c.created_at and end_dt:
                delta = (end_dt - c.created_at).total_seconds() / 60.0
                if delta > 0:
                    deltas.append(delta)
        if deltas:
            mttr_minutes = round(sum(deltas) / len(deltas), 2)
    except Exception:
        mttr_minutes = None

    # ── Compteurs 30j ──
    total_alerts_30d = db.query(func.count(Alert.id)).filter(
        Alert.tenant_id == tenant_id, Alert.timestamp >= thirty_days_ago
    ).scalar() or 0
    total_suricata_30d = db.query(func.count(SuricataAlert.id)).filter(
        SuricataAlert.tenant_id == tenant_id, SuricataAlert.timestamp >= thirty_days_ago
    ).scalar() or 0
    total_cases = db.query(func.count(Case.id)).filter(
        Case.tenant_id == tenant_id
    ).scalar() or 0
    open_cases = db.query(func.count(Case.id)).filter(
        Case.tenant_id == tenant_id, Case.status != "closed"
    ).scalar() or 0
    resolved_cases = db.query(func.count(Case.id)).filter(
        Case.tenant_id == tenant_id, Case.status == "resolved"
    ).scalar() or 0

    # ── Breakdown sévérité (échelle 0-15) ──
    def _sev_bucket(n: int) -> str:
        if n <= 3: return "info"
        if n <= 6: return "low"
        if n <= 9: return "medium"
        if n <= 12: return "high"
        return "critical"

    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in db.query(Alert.normalized_severity, func.count(Alert.id)).filter(
        Alert.tenant_id == tenant_id, Alert.timestamp >= thirty_days_ago
    ).group_by(Alert.normalized_severity).all():
        bucket = _sev_bucket(int(row[0]))
        severity_breakdown[bucket] += int(row[1])
    for row in db.query(SuricataAlert.normalized_severity, func.count(SuricataAlert.id)).filter(
        SuricataAlert.tenant_id == tenant_id, SuricataAlert.timestamp >= thirty_days_ago
    ).group_by(SuricataAlert.normalized_severity).all():
        bucket = _sev_bucket(int(row[0]))
        severity_breakdown[bucket] += int(row[1])

    # ── Alerts par jour (7 derniers jours) ──
    alerts_per_day = []
    for i in range(7):
        day_start = seven_days_ago + timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        count = db.query(func.count(Alert.id)).filter(
            Alert.tenant_id == tenant_id,
            Alert.timestamp >= day_start, Alert.timestamp < day_end,
        ).scalar() or 0
        alerts_per_day.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "count": int(count),
        })

    return {
        "mttd_minutes": mttd_minutes,
        "mttr_minutes": mttr_minutes,
        "total_alerts_30d": total_alerts_30d,
        "total_suricata_30d": total_suricata_30d,
        "total_cases": total_cases,
        "open_cases": open_cases,
        "resolved_cases": resolved_cases,
        "severity_breakdown": severity_breakdown,
        "alerts_per_day": alerts_per_day,
    }


def _report_to_dict(r: Report) -> dict:
    return {
        "id": r.id, "tenant_id": r.tenant_id, "report_type": r.report_type,
        "title": r.title, "status": r.status, "format": r.format,
        "content": r.content, "file_path": r.file_path, "params": r.params,
        "schedule_id": r.schedule_id, "generated_by": r.generated_by,
        "case_id": r.case_id, "investigation_id": r.investigation_id,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "error": r.error, "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _template_to_dict(t: ReportTemplate) -> dict:
    return {
        "id": t.id, "tenant_id": t.tenant_id, "name": t.name,
        "description": t.description, "report_type": t.report_type,
        "params_schema": t.params_schema, "default_params": t.default_params,
        "is_active": t.is_active,
    }


def _schedule_to_dict(s: ReportSchedule) -> dict:
    return {
        "id": s.id, "tenant_id": s.tenant_id, "name": s.name,
        "report_type": s.report_type, "cron_expr": s.cron_expr,
        "format": s.format, "recipients": s.recipients,
        "is_active": s.is_active, "case_id": s.case_id,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
    }


def _recipient_to_dict(r: ReportRecipient) -> dict:
    return {
        "id": r.id, "tenant_id": r.tenant_id, "report_id": r.report_id,
        "channel": r.channel, "destination": r.destination,
        "status": r.status, "sent_at": r.sent_at.isoformat() if r.sent_at else None,
    }
