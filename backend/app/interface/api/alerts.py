import logging
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ...db import get_db
from ...models import Alert, Asset, Device
from ...auth import get_api_key_or_jwt

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["Alerts"], dependencies=[Depends(get_api_key_or_jwt)])

@router.get("/history")
async def get_alert_history(request: Request, limit: int = 500, db: Session = Depends(get_db)):
    """
    GET /api/alerts/history
    Fetch the full alert history from the DATABASE, enriched with asset data.
    Scoped to the requesting tenant.
    """
    tenant_id = getattr(request.state, "tenant_id", "default")
    db_alerts = (
        db.query(Alert)
        .filter(Alert.tenant_id == tenant_id)
        .order_by(desc(Alert.timestamp))
        .limit(min(limit, 5000))
        .all()
    )

    enriched_data = []
    for item in db_alerts:
        employee_name = "Unknown"
        department = "Unknown"
        mac_address = "Unknown"

        if item.src_ip:
            try:
                # Query assets
                asset = db.query(Asset).filter(Asset.ip == item.src_ip).first()
                if asset:
                    employee_name, department = asset.employee_name, asset.department
                # Query devices
                device = db.query(Device).filter(Device.ip == item.src_ip).first()
                if device:
                    mac_address = device.mac
            except Exception as e:
                logger.error(f"Error querying device for IP {item.src_ip}: {e}")

        enriched_data.append({
            "Timestamp": item.timestamp.isoformat(),
            "Description": item.description,
            "Severity": item.severity,
            "Source IP": item.src_ip,
            "Agent ID": item.agent_id,
            "MAC Address": mac_address,
            "Employee Name": employee_name,
            "Department": department,
            # ── F3 Threat Intel (additif — null quand non enrichi) ──
            "Intel Verdict": item.intel_verdict,
            "Intel Score": item.intel_score,
            "Intel Source": item.intel_source,
            "Intel Checked At": item.intel_checked_at.isoformat() if item.intel_checked_at else None,
        })

    return enriched_data
