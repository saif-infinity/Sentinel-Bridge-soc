import asyncio
import logging
import time
from datetime import datetime, timezone

import psutil
from fastapi import APIRouter, Depends, Request, WebSocket
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ...application.wazuh.service import wazuh_service
from ...auth import get_api_key_or_jwt
from ...config import settings
from ...core.broadcaster import broadcaster
from ...core.jwt_utils import verify_token
from ...db import get_db, query_with_tenant
from ...models import Alert, Asset, Device

logger = logging.getLogger(__name__)

router = APIRouter()

bandwidth_lock = asyncio.Lock()
prev_io = psutil.net_io_counters()
prev_time = time.time()


@router.get("/api/real-alerts", dependencies=[Depends(get_api_key_or_jwt)])
async def get_real_alerts(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    """ 
    Fetch latest security alerts from DATABASE, enriched with asset data.
    """
    db_alerts = query_with_tenant(Alert, request, db).order_by(desc(Alert.timestamp)).limit(min(limit, 500)).all()
    
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
            "ID": item.id,
            "Timestamp": item.timestamp.isoformat(),
            "Description": item.description,
            "Severity": item.severity,
            "Source IP": item.src_ip,
            "Agent ID": item.agent_id,
            "MAC Address": mac_address,
            "Employee Name": employee_name,
            "Department": department
        })
        
    return enriched_data


@router.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket, api_key: str | None = None, token: str | None = None):
    await websocket.accept()

    authenticated = False

    # Accept either the API key OR a valid JWT (passed as `token` query param).
    if api_key:
        if api_key == settings.API_KEY.get_secret_value():
            authenticated = True

    if not authenticated and token:
        if verify_token(token):
            authenticated = True

    if not authenticated:
        try:
            await websocket.send_json({"type": "error", "message": "Unauthorized"})
        except Exception:
            pass
        try:
            await websocket.close(code=4001)
        except Exception:
            pass
        return

    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        await broadcaster.disconnect(websocket)


@router.get("/")
async def root():
    return {"status": "Sentinel Bridge API is Online"}


@router.get("/api/stats/bandwidth", dependencies=[Depends(get_api_key_or_jwt)])
async def get_bandwidth():
    global prev_io, prev_time
    async with bandwidth_lock:
        curr_io = psutil.net_io_counters()
        curr_time = time.time()
        
        interval = curr_time - prev_time
        if interval <= 0: 
            return {"mbps": 0}
        
        bytes_sent = curr_io.bytes_sent - prev_io.bytes_sent
        bytes_recv = curr_io.bytes_recv - prev_io.bytes_recv
        
        mbps = ((bytes_sent + bytes_recv) / (1024 * 1024)) / interval
        
        prev_io = curr_io
        prev_time = curr_time
        
        return {"mbps": round(mbps, 2)}


@router.get("/api/wazuh/investigate/{agent_id}", dependencies=[Depends(get_api_key_or_jwt)])
async def investigate_agent(agent_id: str):
    try:
        hardware = await wazuh_service.get_agent_hardware(agent_id)
        packages = await wazuh_service.get_agent_packages(agent_id, limit=8)
        return {"hardware": hardware, "packages": packages, "scan_time": datetime.now(timezone.utc).isoformat()}
    except Exception as e:
        logger.error("Investigate agent error: %s", e)
        return {"error": "Failed to investigate agent"}
