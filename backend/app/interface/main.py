import logging
import ssl

import urllib3
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import (
    admin,
    alerts,
    analyse,
    auth,
    billing,
    database,
    devices,
    faces,
    network_config,
    scan,
    sensors,
    settings as settings_router,
    super_admin,
    surveillance,
    suricata,
    tasks,
    tenants,
    terminal,
    wazuh,
)
from .api.realtime import (
    get_bandwidth,
    get_real_alerts,
    investigate_agent,
    root,
    websocket_endpoint,
)
from .api.suricata import receive_suricata_alert
from .api.webhooks import wazuh_webhook
from .api.rules import router as rules_router
from .api.pipeline import router as pipeline_router
from .api.cases import router as cases_router
from .api.hunts import router as hunts_router
from .api.playbooks import router as playbooks_router
from .api.intel import router as intel_router
from .api.auth import me_router
from .middleware.action_log import ActionLogMiddleware
from .middleware.tenant import TenantMiddleware
from ..application.bootstrap import run_startup
from ..auth import get_api_key_or_jwt
from ..config import settings
from ..core import logging_setup  # noqa: F401
from ..core.rbac import DEFAULT_POLICY, apply_role_guard, require_role  # noqa: F401

logger = logging.getLogger(__name__)

# SSL context: verify in production, skip in dev
ENVIRONMENT = settings.ENVIRONMENT
SSL_VERIFY = ENVIRONMENT == "production"
if SSL_VERIFY:
    ssl_ctx = ssl.create_default_context()
else:
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

if not SSL_VERIFY:
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

app.add_middleware(TenantMiddleware)
app.add_middleware(ActionLogMiddleware)


@app.on_event("startup")
async def startup():
    await run_startup()


# Include routers (order preserved from the original app/main.py)
app.include_router(devices.router)
app.include_router(analyse.router)
app.include_router(scan.router)
app.include_router(tasks.router)
app.include_router(wazuh.router)
app.include_router(suricata.router)
app.include_router(terminal.router)
app.include_router(auth.router)
app.include_router(me_router)
app.include_router(faces.router)
app.include_router(surveillance.router)
app.include_router(admin.router)
app.include_router(settings_router.router)
app.include_router(sensors.router)
app.include_router(database.router)
app.include_router(network_config.router)
app.include_router(tenants.router)
app.include_router(super_admin.router)
app.include_router(billing.router)
app.include_router(alerts.router)
app.include_router(rules_router)
app.include_router(pipeline_router)
app.include_router(cases_router)
app.include_router(hunts_router)
app.include_router(playbooks_router)
app.include_router(intel_router)

# ────────────────────────────────────────────────────────────────────
# F4 — RBAC: apply role guards to every router (runs at import time,
# right after the include block, before any request is served).
# ────────────────────────────────────────────────────────────────────
ROUTER_POLICIES = {
    "devices": {}, "analyse": {"read": "analyst", "write": "analyst"}, "scan": {"read": "analyst", "write": "analyst"},
    "tasks": {}, "wazuh": {}, "suricata": {}, "terminal": {},
    "auth": {"exempt": True}, "faces": {"exempt": True}, "surveillance": {},
    "admin": {"exempt": True}, "settings": {"read": "admin", "write": "admin"}, "sensors": {},
    "database": {"exempt": True}, "network_config": {},
    "tenants": {"read": "viewer", "write": "admin", "exempt_paths": ["/api/tenants/register"]},
    "super_admin": {"exempt": True},
    "billing": {"read": "admin", "write": "admin", "exempt_paths": ["/api/billing/webhook"]},
    "alerts": {}, "rules": {"read": "admin", "write": "admin"}, "pipeline": {}, "cases": {}, "hunts": {},
    "playbooks": {"read": "analyst", "write": "admin"}, "intel": {},
}
for name, router in [( "devices", devices.router), ("analyse", analyse.router), ("scan", scan.router), ("tasks", tasks.router), ("wazuh", wazuh.router), ("suricata", suricata.router), ("terminal", terminal.router), ("auth", auth.router), ("faces", faces.router), ("surveillance", surveillance.router), ("admin", admin.router), ("settings", settings_router.router), ("sensors", sensors.router), ("database", database.router), ("network_config", network_config.router), ("tenants", tenants.router), ("super_admin", super_admin.router), ("billing", billing.router), ("alerts", alerts.router), ("rules", rules_router), ("pipeline", pipeline_router), ("cases", cases_router), ("hunts", hunts_router), ("playbooks", playbooks_router), ("intel", intel_router) ]:
    policy = ROUTER_POLICIES.get(name, DEFAULT_POLICY)
    if not policy.get("exempt"):
        apply_role_guard(router, policy)

# ────────────────────────────────────────────────────────────────────
# /webhook (Suricata) + /api/wazuh/webhook — registered directly on the
# app, exactly as the original app/main.py did (this FastAPI version
# counts each `include_router` as a single lazy `_IncludedRouter` entry,
# so the formerly-direct routes must stay direct to keep the route count
# identical). The endpoint modules still own the handlers.
# ────────────────────────────────────────────────────────────────────
app.add_api_route("/webhook", receive_suricata_alert, methods=["POST"])
app.add_api_route(
    "/api/wazuh/webhook",
    wazuh_webhook,
    methods=["POST"],
    dependencies=[Depends(get_api_key_or_jwt)],
)

# /api/real-alerts, /ws/status, /, /api/stats/bandwidth, /api/wazuh/investigate/{agent_id}
app.add_api_route(
    "/api/real-alerts",
    get_real_alerts,
    methods=["GET"],
    dependencies=[Depends(get_api_key_or_jwt)],
)
app.add_api_websocket_route("/ws/status", websocket_endpoint)
app.add_api_route("/", root, methods=["GET"])
app.add_api_route(
    "/api/stats/bandwidth",
    get_bandwidth,
    methods=["GET"],
    dependencies=[Depends(get_api_key_or_jwt)],
)
app.add_api_route(
    "/api/wazuh/investigate/{agent_id}",
    investigate_agent,
    methods=["GET"],
    dependencies=[Depends(get_api_key_or_jwt)],
)
