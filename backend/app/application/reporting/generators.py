"""F5 — Reporting Subsystem : report generators.

Generates daily, trends, case_closure, and investigation_summary reports.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func

from ...db import SessionLocal
from ...domain.models import Case, Alert, SuricataAlert, CaseAlertLink, TimelineEvent
from ...domain.investigations import Investigation, InvestigationRecommendation
from ...domain.reporting import Report, ReportLog
from .templates import (
    render_html_report, build_daily_html_body, build_trends_html_body,
    build_case_closure_html_body, build_csv, build_case_closure_csv,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _add_report_log(db, tenant_id: str, report_id: int, action: str,
                      detail: str = "", error: str | None = None,
                      initiated_by: str = "system") -> None:
    """Create a ReportLog entry."""
    db.add(ReportLog(
        tenant_id=tenant_id,
        report_id=report_id,
        action=action,
        detail=detail,
        error=error,
        initiated_by=initiated_by,
    ))
    db.commit()


def _store_report(db, tenant_id: str, report_type: str, title: str,
                   status: str, fmt: str, content: str | None,
                   file_path: str | None, params: str,
                   schedule_id: int | None, generated_by: str,
                   case_id: int | None, investigation_id: int | None,
                   started_at: datetime,
                   error: str | None = None) -> Report:
    """Persist a Report row and return it."""
    finished_at = _utcnow() if status in ("generated", "failed") else None
    report = Report(
        tenant_id=tenant_id,
        report_type=report_type,
        title=title,
        status=status,
        format=fmt,
        content=content,
        file_path=file_path,
        params=params,
        schedule_id=schedule_id,
        generated_by=generated_by,
        case_id=case_id,
        investigation_id=investigation_id,
        started_at=started_at,
        finished_at=finished_at,
        error=error,
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def _build_daily_rows(db, tenant_id: str, start: datetime,
                       now: datetime):
    """Query alert and case rows for daily report."""
    alert_rows: list[dict[str, Any]] = []
    alerts = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.timestamp >= start,
        Alert.timestamp <= now,
    ).order_by(Alert.timestamp.desc()).all()
    for a in alerts:
        alert_rows.append({
            "id": a.id, "timestamp": a.timestamp.isoformat(),
            "severity": a.severity, "description": (a.description or "")[:80],
            "src_ip": a.src_ip or "—", "agent_id": a.agent_id or "—",
        })

    case_rows: list[dict[str, Any]] = []
    cases = db.query(Case).filter(
        Case.tenant_id == tenant_id,
        Case.created_at >= start,
        Case.created_at <= now,
    ).order_by(Case.created_at.desc()).all()
    for c in cases:
        case_rows.append({
            "id": c.id, "title": c.title, "status": c.status,
            "severity": c.severity,
            "created_at": c.created_at.isoformat(),
            "assignee": c.assignee or "—",
        })

    return alert_rows, case_rows, alerts, cases


# ── Daily Report ──────────────────────────────────────

def generate_daily_report(db, tenant_id: str, params: dict | None = None,
                           schedule_id: int | None = None,
                           generated_by: str = "system") -> Report:
    """Generate a daily summary report for the tenant."""
    params = params or {}
    days_back = int(params.get("days_back", 1))
    include_alerts = params.get("include_alerts", True)
    include_cases = params.get("include_cases", True)
    now = _utcnow()
    start = now - timedelta(days=days_back)
    title = f"Rapport quotidien — {now.strftime('%Y-%m-%d')}"
    started_at = _utcnow()

    body_parts: list[str] = []
    summary: dict[str, Any] = {}
    alert_rows: list[dict[str, Any]] = []
    case_rows: list[dict[str, Any]] = []
    alert_count = 0
    case_count = 0

    if include_alerts:
        alert_rows, _, alerts, _ = _build_daily_rows(db, tenant_id, start, now)
        alert_count = len(alerts)
        summary["alerts_count"] = alert_count
        body_parts.append(build_daily_html_body(alert_rows, {"Alerts": alert_count}))

    if include_cases:
        _, case_rows, _, cases = _build_daily_rows(db, tenant_id, start, now)
        case_count = len(cases)
        summary["cases_count"] = case_count
        body_parts.append(build_daily_html_body(case_rows, {"Cases": case_count}))

    body = "".join(body_parts) if body_parts else "<p>Aucune donnée.</p>"
    summary_html = "<h2>Résumé</h2><ul>" + "".join(
        f"<li><strong>{k}:</strong> {v}</li>" for k, v in summary.items()
    ) + "</ul>"
    html_content = render_html_report(
        title, "daily", tenant_id, started_at.isoformat(),
        body + summary_html, 0, generated_by,
    )

    all_csv_rows = alert_rows + case_rows if (include_alerts and include_cases) else (alert_rows or case_rows or [])
    csv_content = build_csv(all_csv_rows, title)

    report = _store_report(
        db, tenant_id, "daily", title, "generated", "html",
        html_content, None, json.dumps(params), schedule_id,
        generated_by, None, None, started_at,
    )
    _add_report_log(db, tenant_id, report.id, "generated",
                     f"Daily report generated ({alert_count} alerts, {case_count} cases)")
    return report


# ── Trends Report ─────────────────────────────────────

def generate_trends_report(db, tenant_id: str, params: dict | None = None,
                            schedule_id: int | None = None,
                            generated_by: str = "system") -> Report:
    """Generate a trends report showing alert/case patterns over time."""
    params = params or {}
    days_back = int(params.get("days_back", 30))
    now = _utcnow()
    start = now - timedelta(days=days_back)
    title = f"Rapport de tendances — {days_back} jours"
    started_at = _utcnow()

    alert_trends: list[dict[str, Any]] = []
    rows = db.query(
        Alert.severity, func.count(Alert.id),
    ).filter(
        Alert.tenant_id == tenant_id,
        Alert.timestamp >= start,
        Alert.timestamp <= now,
    ).group_by(Alert.severity).all()
    for severity, count in rows:
        alert_trends.append({"severity": str(severity), "count": count})

    case_trends: list[dict[str, Any]] = []
    case_rows = db.query(
        Case.status, func.count(Case.id),
    ).filter(
        Case.tenant_id == tenant_id,
        Case.created_at >= start,
        Case.created_at <= now,
    ).group_by(Case.status).all()
    for status_val, count in case_rows:
        case_trends.append({"status": str(status_val), "count": count})

    body_parts: list[str] = []
    if alert_trends:
        body_parts.append(build_trends_html_body(alert_trends, {"Alert trends": len(alert_trends)}))
    if case_trends:
        body_parts.append(build_trends_html_body(case_trends, {"Case trends": len(case_trends)}))
    body = "".join(body_parts) if body_parts else "<p>Aucune donnée de tendance.</p>"

    summary = {
        "alert_severity_groups": len(alert_trends),
        "case_status_groups": len(case_trends),
        "days_back": days_back,
    }
    html_content = render_html_report(
        title, "trends", tenant_id, started_at.isoformat(),
        body, 0, generated_by,
    )
    csv_content = build_csv(alert_trends + case_trends, title)

    report = _store_report(
        db, tenant_id, "trends", title, "generated", "html",
        html_content, None, json.dumps(params), schedule_id,
        generated_by, None, None, started_at,
    )
    _add_report_log(db, tenant_id, report.id, "generated",
                     f"Trends report ({len(alert_trends)} severity groups, {len(case_trends)} status groups)")
    return report


# ── Case Closure Report ───────────────────────────────

def generate_case_closure_report(db, tenant_id: str, case_id: int,
                                  generated_by: str = "system",
                                  schedule_id: int | None = None) -> Report:
    """Generate a case closure report for a specific case."""
    case = db.query(Case).filter(
        Case.id == case_id, Case.tenant_id == tenant_id
    ).first()
    if case is None:
        raise ValueError(f"Case {case_id} not found for tenant {tenant_id}")

    title = f"Rapport de clôture — Affaire #{case_id}: {case.title}"
    started_at = _utcnow()

    case_data = {
        "ID": str(case.id), "Title": case.title, "Status": case.status,
        "Severity": str(case.severity), "Assignee": case.assignee or "—",
        "Created": case.created_at.isoformat() if case.created_at else "—",
        "Closed": case.closed_at.isoformat() if case.closed_at else "—",
        "Closed By": case.closed_by or "—",
        "Description": (case.description or "")[:200],
    }

    alerts: list[dict[str, Any]] = []
    links = db.query(CaseAlertLink).filter(
        CaseAlertLink.case_id == case_id,
        CaseAlertLink.tenant_id == tenant_id,
    ).all()
    for link in links:
        if link.alert_type == "alert":
            a = db.query(Alert).filter(Alert.id == link.alert_id).first()
            if a:
                alerts.append({"id": str(a.id), "type": "alert", "severity": str(a.severity),
                               "description": (a.description or "")[:80], "timestamp": a.timestamp.isoformat()})
        elif link.alert_type == "suricata":
            s = db.query(SuricataAlert).filter(SuricataAlert.id == link.alert_id).first()
            if s:
                alerts.append({"id": str(s.id), "type": "suricata", "severity": str(s.severity),
                               "description": s.alert_msg or "—", "timestamp": s.timestamp.isoformat()})

    timeline_events = db.query(TimelineEvent).filter(
        TimelineEvent.case_id == case_id,
        TimelineEvent.tenant_id == tenant_id,
    ).order_by(TimelineEvent.created_at.desc()).limit(10).all()
    timeline_summary = len(timeline_events)

    summary = {
        "Case ID": str(case.id),
        "Associated Alerts": str(len(alerts)),
        "Timeline Events": str(timeline_summary),
        "Case Status": case.status,
    }

    body = build_case_closure_html_body(case_data, alerts, summary)
    html_content = render_html_report(
        title, "case_closure", tenant_id, started_at.isoformat(),
        body, 0, generated_by,
    )
    csv_content = build_case_closure_csv(case_data, alerts)

    report = _store_report(
        db, tenant_id, "case_closure", title, "generated", "html",
        html_content, None, json.dumps({"case_id": case_id}), schedule_id,
        generated_by, case_id, None, started_at,
    )
    _add_report_log(db, tenant_id, report.id, "generated",
                     f"Case closure report for case {case_id} ({len(alerts)} alerts)")
    return report


# ── Investigation Summary Report ──────────────────────────

def generate_investigation_summary_report(db, tenant_id: str,
                                           params: dict | None = None,
                                           schedule_id: int | None = None,
                                           generated_by: str = "system") -> Report:
    """Generate an investigation summary report."""
    params = params or {}
    days_back = int(params.get("days_back", 7))
    now = _utcnow()
    start = now - timedelta(days=days_back)
    title = f"Rapport de synthèse d'investigation — {days_back} jours"
    started_at = _utcnow()

    investigations = db.query(Investigation).filter(
        Investigation.tenant_id == tenant_id,
        Investigation.created_at >= start,
    ).all()

    risk_levels: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for inv in investigations:
        rl = str(inv.risk_level)
        risk_levels[rl] = risk_levels.get(rl, 0) + 1
        st = str(inv.status)
        statuses[st] = statuses.get(st, 0) + 1

    recs = db.query(InvestigationRecommendation).filter(
        InvestigationRecommendation.tenant_id == tenant_id,
        InvestigationRecommendation.created_at >= start,
    ).all()
    rec_statuses: dict[str, int] = {}
    for r in recs:
        rs = str(r.status)
        rec_statuses[rs] = rec_statuses.get(rs, 0) + 1

    body = "<h2>Investigations</h2><table>"
    for risk, count in risk_levels.items():
        body += f"<tr><td>{risk}</td><td>{count}</td></tr>"
    body += "</table><h2>Statuts</h2><table>"
    for status_val, count in statuses.items():
        body += f"<tr><td>{status_val}</td><td>{count}</td></tr>"
    body += "</table><h2>Recommandations</h2><table>"
    for rstatus, count in rec_statuses.items():
        body += f"<tr><td>{rstatus}</td><td>{count}</td></tr>"
    body += "</table>"

    summary = {
        "Total investigations": len(investigations),
        "Risk levels": len(risk_levels),
        "Recommendation statuses": len(rec_statuses),
    }
    html_content = render_html_report(
        title, "investigation_summary", tenant_id, started_at.isoformat(),
        body, 0, generated_by,
    )
    csv_content = build_csv(
        [{"risk_level": k, "count": v} for k, v in risk_levels.items()] +
        [{"status": k, "count": v} for k, v in statuses.items()] +
        [{"rec_status": k, "count": v} for k, v in rec_statuses.items()],
        title,
    )

    report = _store_report(
        db, tenant_id, "investigation_summary", title, "generated", "html",
        html_content, None, json.dumps(params), schedule_id,
        generated_by, None, None, started_at,
    )
    _add_report_log(db, tenant_id, report.id, "generated",
                     f"Investigation summary ({len(investigations)} investigations)")
    return report
