import logging
from datetime import datetime, timezone

import dateutil.parser
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .suricata import receive_suricata_alert
from ...auth import get_api_key_or_jwt
from ...core.broadcaster import broadcaster
from ...db import get_db
from ...models import Alert

logger = logging.getLogger(__name__)

router = APIRouter()

# Same handler object as /api/suricata/webhook — re-registered at the
# un-prefixed /webhook path, exactly as the original app/main.py did.
router.add_api_route("/webhook", receive_suricata_alert, methods=["POST"])


@router.post("/api/wazuh/webhook", dependencies=[Depends(get_api_key_or_jwt)])
async def wazuh_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        rule = data.get("rule", {})
        
        ts_str = data.get("timestamp", datetime.now(timezone.utc).isoformat())
        ts = dateutil.parser.isoparse(ts_str) if ts_str else datetime.now(timezone.utc)
        desc_text = rule.get("description", "Wazuh Alert")

        exists = db.query(Alert).filter(
            Alert.description == desc_text,
            Alert.timestamp == ts
        ).first()
        if exists:
            return {"status": "duplicate", "id": exists.id}

        new_alert = Alert(
            timestamp=ts,
            description=desc_text[:500],
            severity=min(int(rule.get("level", 0)), 15),
            src_ip=str(data.get("agent", {}).get("ip", "0.0.0.0"))[:45],
            agent_id=str(data.get("agent", {}).get("id", "Unknown"))[:10]
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        alert_pkg = {
            "Timestamp": ts.isoformat(),
            "Description": new_alert.description,
            "Severity": new_alert.severity,
            "Source IP": new_alert.src_ip,
            "Agent ID": new_alert.agent_id,
            "MAC Address": "Auto-Detect",
            "Employee Name": "System Incident",
            "Department": "SOC Managed"
        }
        await broadcaster.broadcast({"type": "alerts_update", "data": [alert_pkg]})
        return {"status": "saved", "id": new_alert.id}
    except Exception as e:
        logger.error("Wazuh webhook error: %s", e)
        return {"status": "error", "message": "Internal processing error"}
