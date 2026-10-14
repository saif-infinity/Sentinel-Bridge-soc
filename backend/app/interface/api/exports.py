"""R11 — Export endpoints: CSV, PDF, Markdown for alerts and cases."""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ...core.auth import get_api_key_or_jwt
from ...db import get_db, get_tenant_id
from ...domain.models import Alert, Case, CaseAlertLink, SuricataAlert
from ...infrastructure.export.csv_export import export_alerts_csv, export_suricata_csv
from ...infrastructure.export.pdf_export import export_alerts_pdf, export_case_markdown

router = APIRouter(prefix="/api", tags=["exports"])


@router.get("/alerts/export.csv")
def export_alerts_csv_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(get_api_key_or_jwt),
    limit: int = Query(default=10000, le=50000),
):
    tenant_id = get_tenant_id(request)
    alerts = db.query(Alert).filter(
        Alert.tenant_id == tenant_id
    ).order_by(Alert.timestamp.desc()).limit(limit).all()
    return export_alerts_csv(alerts)


@router.get("/suricata-alerts/export.csv")
def export_suricata_csv_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(get_api_key_or_jwt),
    limit: int = Query(default=10000, le=50000),
):
    tenant_id = get_tenant_id(request)
    alerts = db.query(SuricataAlert).filter(
        SuricataAlert.tenant_id == tenant_id
    ).order_by(SuricataAlert.timestamp.desc()).limit(limit).all()
    return export_suricata_csv(alerts)


@router.get("/alerts/export.pdf")
def export_alerts_pdf_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(get_api_key_or_jwt),
    limit: int = Query(default=1000, le=5000),
):
    tenant_id = get_tenant_id(request)
    alerts = db.query(Alert).filter(
        Alert.tenant_id == tenant_id
    ).order_by(Alert.timestamp.desc()).limit(limit).all()
    pdf_bytes = export_alerts_pdf(alerts)
    now = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="alerts_{now}.pdf"'},
    )


@router.get("/cases/{case_id}/export.md")
def export_case_md_endpoint(
    case_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(get_api_key_or_jwt),
):
    tenant_id = get_tenant_id(request)
    case = db.query(Case).filter(Case.id == case_id, Case.tenant_id == tenant_id).first()
    if not case:
        return Response(status_code=404, content='{"error": "case not found"}')

    links = db.query(CaseAlertLink).filter(CaseAlertLink.case_id == case_id).all()
    alerts = []
    for link in links:
        if link.alert_type == "alert":
            a = db.query(Alert).filter(Alert.id == link.alert_id).first()
        else:
            a = db.query(SuricataAlert).filter(SuricataAlert.id == link.alert_id).first()
        if a:
            alerts.append(a)

    md = export_case_markdown(case, alerts)
    return Response(
        content=md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}.md"'},
    )
