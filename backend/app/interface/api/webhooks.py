import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ...application.normalization import map_wazuh, to_pipeline_payload
from ...application.pipeline import ingest_alert
from ...application.source_control import is_source_enabled
from ...auth import webhook_token_auth
from ...core.broadcaster import broadcaster
from ...db import get_db, get_tenant_id
from .suricata import receive_suricata_alert

logger = logging.getLogger(__name__)

router = APIRouter()

# Same handler object as /api/suricata/webhook — re-registered at the
# un-prefixed /webhook path, exactly as the original app/main.py did.
router.add_api_route("/webhook", receive_suricata_alert, methods=["POST"])


@router.post("/api/wazuh/webhook", dependencies=[Depends(webhook_token_auth("wazuh"))])
async def wazuh_webhook(request: Request, db: Session = Depends(get_db)):
    if not is_source_enabled(db, "wazuh", tenant_id=get_tenant_id(request)):
        return {"status": "ignored", "source": "wazuh"}
    try:
        data = await request.json()

        # R1 — Normalisation canonique (ECS-like) puis pipeline unique :
        # le pipeline crée la ligne Alert, déduplique, normalise la sévérité
        # et évalue les règles. Pas de double-écriture ici.
        canonical = map_wazuh(data)
        canonical["tenant_id"] = get_tenant_id(request)
        payload = to_pipeline_payload(canonical, source="wazuh")
        result = ingest_alert(payload, db=db)

        if result.get("status") == "accepted":
            alert_pkg = {
                "Timestamp": canonical.get("@timestamp") or datetime.now(UTC).isoformat(),
                "Description": canonical.get("description") or "Wazuh Alert",
                "Severity": canonical.get("severity") or 0,
                "Source IP": canonical.get("src_ip") or "0.0.0.0",
                "Agent ID": canonical.get("agent_id") or "Unknown",
                "MAC Address": "Auto-Detect",
                "Employee Name": "System Incident",
                "Department": "SOC Managed"
            }
            await broadcaster.broadcast({"type": "alerts_update", "data": [alert_pkg]})
        return {"status": result.get("status", "accepted"), "id": result.get("alert_id")}
    except Exception as e:
        logger.error("Wazuh webhook error: %s", e)
        return {"status": "error", "message": "Internal processing error"}
