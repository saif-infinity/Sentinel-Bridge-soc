import asyncio
import logging
import urllib3
import dateutil.parser
from sqlalchemy import desc
from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends, Request, WebSocket, HTTPException, status
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from .db import engine, Base, SessionLocal, get_db
from .models import Alert, Device, Asset
from .routers import devices, analyse, scan, wazuh, suricata, tasks, terminal
from .scanner import background_scanner
from .services import broadcaster
from .config import settings
import psutil
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

prev_io = psutil.net_io_counters()
prev_time = time.time()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Sentinel Bridge - SOC Dashboard API")
logger.info("FastAPI server starting/reloading...")


# Proper CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    
    async def init_wazuh():
        try:
            from .services.wazuh_service import wazuh_service
            await wazuh_service.refresh_agent_cache()
        except Exception as e:
            logger.error("Wazuh cache init error: %s", e)
    asyncio.create_task(init_wazuh())
    
    async def safe_scanner():
        try:
            await background_scanner(SessionLocal, broadcaster.broadcast, settings.SCAN_INTERVAL_SECONDS)
        except Exception as e:
            logger.error("Background scanner crashed: %s", e)
    asyncio.create_task(safe_scanner())

    async def wazuh_sync_task():
        refresh_counter = 0
        while True:
            try:
                await wazuh_service.sync_alerts(SessionLocal)
            except Exception as e:
                logger.error("Alert sync error: %s", e)

            refresh_counter += 1
            if refresh_counter >= 10:
                refresh_counter = 0
                try:
                    await wazuh_service.refresh_agent_cache()
                    logger.info("Agent IP cache refreshed.")
                except Exception as e:
                    logger.error("Cache refresh error: %s", e)

            await asyncio.sleep(30)
    asyncio.create_task(wazuh_sync_task())

# Include routes
app.include_router(devices.router)
app.include_router(analyse.router)
app.include_router(scan.router)
app.include_router(tasks.router)
app.include_router(wazuh.router)
app.include_router(suricata.router)
app.include_router(terminal.router)

from .routers.suricata import receive_suricata_alert
app.add_api_route("/webhook", receive_suricata_alert, methods=["POST"])

from .services.wazuh_service import wazuh_service

@app.get("/api/real-alerts")
async def get_real_alerts(db: Session = Depends(get_db)):
    """ 
    Fetch latest security alerts from DATABASE, enriched with asset data.
    """
    db_alerts = db.query(Alert).order_by(desc(Alert.timestamp)).limit(50).all()
    
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
            "Department": department
        })
        
    return enriched_data

@app.post("/api/wazuh/webhook")
async def wazuh_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        rule = data.get("rule", {})
        
        ts_str = data.get("timestamp", datetime.utcnow().isoformat())
        ts = dateutil.parser.isoparse(ts_str) if ts_str else datetime.utcnow()
        desc_text = rule.get("description", "Wazuh Alert")

        exists = db.query(Alert).filter(
            Alert.description == desc_text,
            Alert.timestamp == ts
        ).first()
        if exists:
            return {"status": "duplicate", "id": exists.id}

        new_alert = Alert(
            timestamp=ts,
            description=desc_text,
            severity=rule.get("level", 0),
            src_ip=data.get("agent", {}).get("ip", "0.0.0.0"),
            agent_id=data.get("agent", {}).get("id", "Unknown")
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
        return {"status": "error", "message": str(e)}

@app.websocket("/ws/status")
async def websocket_endpoint(websocket: WebSocket, api_key: str = None):
    await websocket.accept()

    if api_key != settings.API_KEY:
        await websocket.send_json({"type": "error", "message": "Unauthorized"})
        await websocket.close(code=4001)
        return

    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        await broadcaster.disconnect(websocket)

@app.get("/")
async def root():
    return {"status": "Sentinel Bridge API is Online"}

@app.get("/api/stats/bandwidth")
async def get_bandwidth():
    global prev_io, prev_time
    curr_io = psutil.net_io_counters()
    curr_time = time.time()
    
    interval = curr_time - prev_time
    if interval <= 0: return {"mbps": 0}
    
    # Bytes to Megabytes per second
    bytes_sent = curr_io.bytes_sent - prev_io.bytes_sent
    bytes_recv = curr_io.bytes_recv - prev_io.bytes_recv
    
    mbps = ((bytes_sent + bytes_recv) / (1024 * 1024)) / interval
    
    prev_io = curr_io
    prev_time = curr_time
    
    return {"mbps": round(mbps, 2)}

@app.get("/api/wazuh/investigate/{agent_id}")
async def investigate_agent(agent_id: str):
    try:
        hardware = await wazuh_service.get_agent_hardware(agent_id)
        packages = await wazuh_service.get_agent_packages(agent_id, limit=8)
        return {"hardware": hardware, "packages": packages, "scan_time": datetime.utcnow().isoformat()}
    except Exception as e: return {"error": str(e)}