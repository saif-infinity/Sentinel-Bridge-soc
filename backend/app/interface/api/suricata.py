import logging
import json
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ...db import get_db, get_tenant_id, query_with_tenant
from ...models import SuricataAlert
from ...schemas import SuricataAlertRead
from ...auth import get_api_key_or_jwt, webhook_token_auth, webhook_slug_auth
from ...application.normalization import map_suricata, to_pipeline_payload
from ...application.pipeline import ingest_alert
from ...application.source_control import is_source_enabled
from typing import List, Optional

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/suricata", tags=["Suricata IPS"])

@router.get("/alerts", dependencies=[Depends(get_api_key_or_jwt)])
def get_suricata_alerts(request: Request, db: Session = Depends(get_db)):
    # Prioritize fetching actual alerts so they don't get buried by flow/stats
    alerts = query_with_tenant(SuricataAlert, request, db).filter(SuricataAlert.event_type == "alert").order_by(desc(SuricataAlert.timestamp)).limit(100).all()
    others = query_with_tenant(SuricataAlert, request, db).filter(SuricataAlert.event_type != "alert").order_by(desc(SuricataAlert.timestamp)).limit(200).all()
    
    combined = alerts + others
    combined.sort(key=lambda x: x.timestamp, reverse=True)

    result = []
    for a in combined:
        verdict = "pass"
        if a.payload:
            try:
                payload_data = json.loads(a.payload)
                v = payload_data.get("verdict") or (payload_data.get("alert") or {}).get("action")
                if v and isinstance(v, str):
                    verdict = v.lower()
                elif payload_data.get("drop") is True:
                    verdict = "drop"
            except (json.JSONDecodeError, TypeError):
                pass
        result.append({
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "event_type": a.event_type,
            "src_ip": a.src_ip,
            "dest_ip": a.dest_ip,
            "proto": a.proto,
            "alert_msg": a.alert_msg,
            "severity": a.severity,
            "verdict": verdict,
            "payload": a.payload,
        })
    return result


@router.post("/webhook", dependencies=[Depends(webhook_token_auth("suricata"))])
async def receive_suricata_alert(request: Request, db: Session = Depends(get_db)):
    """
    Receives alerts from Suricata (e.g., via a custom script or log forwarder sending eve.json items)
    """
    if not is_source_enabled(db, "suricata", tenant_id=get_tenant_id(request)):
        return {"status": "ignored", "source": "suricata"}
    try:
        body = await request.body()
        try:
            payload_data = json.loads(body)
        except json.JSONDecodeError:
            # Suricata often sends NDJSON (JSON Lines)
            payload_data = []
            for line in body.decode('utf-8').splitlines():
                if line.strip():
                    payload_data.append(json.loads(line))
    except Exception as e:
        logger.error("JSON Decode Error in webhook: %s", e)
        return {"status": "error", "message": "Invalid JSON"}

    if not isinstance(payload_data, list):
        payload_data = [payload_data]
        
    tenant_id = get_tenant_id(request)
    alerts_added = 0
    for original_data in payload_data:
        if not isinstance(original_data, dict):
            continue
            
        data = original_data
        # Unwrap if the actual Suricata JSON is inside a 'message' string
        if "message" in data and isinstance(data["message"], str):
            try:
                data = json.loads(data["message"])
            except json.JSONDecodeError:
                pass
                
        event_type = data.get("event_type", "unknown")
        
        # Simplify huge payloads to avoid truncation (which breaks JSON.parse in frontend)
        if event_type == "stats" and "stats" in data:
            s = data["stats"]
            data = {
                "event_type": "stats",
                "stats": {
                    "uptime": s.get("uptime", 0),
                    "decoder": {"pkts": s.get("decoder", {}).get("pkts", 0)},
                    "ips": {
                        "accepted": s.get("ips", {}).get("accepted", 0),
                        "blocked": s.get("ips", {}).get("blocked", 0),
                        "rejected": s.get("ips", {}).get("rejected", 0),
                    },
                    "detect": {"alert": s.get("detect", {}).get("alert", 0)},
                    "flow": {"total": s.get("flow", {}).get("total", 0), "active": s.get("flow", {}).get("active", 0)},
                }
            }

        # R1 — Normalisation canonique (ECS-like) puis pipeline unique :
        # le pipeline crée la ligne SuricataAlert, déduplique, normalise la
        # sévérité et évalue les règles. Pas de double-écriture ici.
        canonical = map_suricata(data)
        canonical["tenant_id"] = tenant_id
        payload = to_pipeline_payload(canonical, source="suricata")
        try:
            ingest_alert(payload, db=db)
            alerts_added += 1
        except Exception as e:
            logger.error("Suricata webhook: pipeline ingest échoué: %s", e)
            
    if alerts_added > 0:
        return {"status": "success", "alerts_processed": alerts_added}
            
    # For debugging, let's see what we are ignoring
    for original_data in payload_data:
        if isinstance(original_data, dict):
            data = original_data
            if "message" in data and isinstance(data["message"], str):
                try:
                    data = json.loads(data["message"])
                except Exception:
                    pass
            logger.debug("Suricata Ignored Event Type: %s", data.get('event_type', 'still_unknown'))
            
    return {"status": "ignored"}


# ── Slugged per-tenant webhook URL (F4 hardening) ─────────────────────
# POST /api/suricata/webhook/{slug} — tenant résolu par slug (404 si
# inconnu), X-SOC-Token optionnel validé contre le tenant résolu.
router.add_api_route(
    "/webhook/{slug}",
    receive_suricata_alert,
    methods=["POST"],
    dependencies=[Depends(webhook_slug_auth("suricata"))],
)
