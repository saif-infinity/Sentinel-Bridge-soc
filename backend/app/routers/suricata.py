from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..db import get_db
from ..models import SuricataAlert
from ..schemas import SuricataAlertRead
from ..auth import api_key_auth
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/suricata", tags=["Suricata IDS"], dependencies=[Depends(api_key_auth)])

@router.get("/alerts", response_model=List[SuricataAlertRead])
def get_suricata_alerts(db: Session = Depends(get_db)):
    # Prioritize fetching actual alerts so they don't get buried by flow/stats
    alerts = db.query(SuricataAlert).filter(SuricataAlert.event_type == "alert").order_by(desc(SuricataAlert.timestamp)).limit(100).all()
    others = db.query(SuricataAlert).filter(SuricataAlert.event_type != "alert").order_by(desc(SuricataAlert.timestamp)).limit(200).all()
    
    combined = alerts + others
    combined.sort(key=lambda x: x.timestamp, reverse=True)
    return combined

import json

@router.post("/webhook")
async def receive_suricata_alert(request: Request, db: Session = Depends(get_db)):
    """
    Receives alerts from Suricata (e.g., via a custom script or log forwarder sending eve.json items)
    """
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
        print(f"JSON Decode Error in webhook: {e}")
        return {"status": "error", "message": "Invalid JSON"}

    if not isinstance(payload_data, list):
        payload_data = [payload_data]
        
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
        alert_data = data.get("alert", {})
        
        # Safely parse timestamp
        ts_str = data.get("timestamp", "")
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str.replace("Z", "+00:00")
            elif len(ts_str) > 5 and ts_str[-5] in ("+", "-") and ":" not in ts_str[-5:]:
                ts_str = ts_str[:-2] + ":" + ts_str[-2:]
            ts = datetime.fromisoformat(ts_str)
        except Exception:
            ts = datetime.utcnow()
            
        # Prevent huge payloads from being truncated mid-JSON (which breaks JSON.parse in frontend)
        if event_type == "stats" and "stats" in data:
            data = {
                "event_type": "stats",
                "stats": {
                    "uptime": data["stats"].get("uptime", 0),
                    "capture": data["stats"].get("capture", {})
                }
            }
            
         # Safely get payload
         try:
             payload_str = json.dumps(data)
         except Exception as e:
             logger.error(f"Error serializing payload: {e}")
             payload_str = str(data)
            
        if len(payload_str) > 1000:
            payload_str = payload_str[:997] + "..."

        # Safely get alert_msg
        alert_msg = alert_data.get("signature", "")
        if not alert_msg:
            alert_msg = f"Suricata {event_type.upper()} Log"
        alert_msg = str(alert_msg)[:255]
        
        # Safely get ips
        src_ip = data.get("src_ip", "")[:45] if data.get("src_ip") else None
        dest_ip = data.get("dest_ip", "")[:45] if data.get("dest_ip") else None
        proto = data.get("proto", "")[:20] if data.get("proto") else None
        
        severity = alert_data.get("severity", 0)
        try:
            severity = int(severity)
        except (ValueError, TypeError):
            severity = 0

        new_alert = SuricataAlert(
            timestamp=ts,
            event_type=event_type,
            src_ip=src_ip,
            dest_ip=dest_ip,
            proto=proto,
            alert_msg=alert_msg,
            severity=severity,
            payload=payload_str
        )
        db.add(new_alert)
        alerts_added += 1
            
    if alerts_added > 0:
        try:
            db.commit()
            return {"status": "success", "alerts_processed": alerts_added}
        except Exception as e:
            db.rollback()
            print(f"Database Error in webhook: {e}")
            return {"status": "error", "message": "Database insertion error"}
            
    # For debugging, let's see what we are ignoring
    for original_data in payload_data:
        if isinstance(original_data, dict):
            data = original_data
            if "message" in data and isinstance(data["message"], str):
                try:
                    data = json.loads(data["message"])
                except Exception:
                    pass
            print(f"DEBUG Suricata Ignored Event Type: {data.get('event_type', 'still_unknown')}")
            
    return {"status": "ignored"}
