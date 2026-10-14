"""
Audit fixes regression tests.

Covers the 8 findings fixed in the backend audit pass:
  1. WS /ws/status accepts JWT (token query param) — API key still works.
  2. /api/real-alerts is tenant-scoped (no cross-tenant leak).
  3. Write endpoints require scopes: terminal exec, network-device
     create/push/test, rules write methods.
  4. Sensor endpoints protected: health → get_api_key_or_jwt,
     analyst/analysts → has_scopes_or_api_key(["devices:read"]).
  5. /api/tasks/nmap-scan accepts a JSON body ({target, scan_type}).
  6. GET /api/faces/image/{username} returns stored face (404 if none).
  7. /auth/register forces tenant "default" for anonymous callers.
  8. /api/tenants/subscribe response includes plan + status.

Run: DATABASE_URL="sqlite:////tmp/opencode/audit_fixes.db" \
     python -m pytest tests/test_audit_fixes.py -q
"""
import os
import tempfile
import uuid

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_audit_fixes_test.db')}"
os.environ["SUPER_ADMIN_PASSWORD"] = "test-sa-pass"
os.environ["SUPER_ADMIN_API_KEY"] = "test-sa-key"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401  # enregistre toutes les tables avant create_all
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.core.jwt_utils import create_access_token  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Alert, Tenant, TenantUser  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()

# Scopes legacy (auth.py) — mêmes listes que test_rbac.py
SCOPES = {
    "viewer": ["devices:read", "alerts:read", "ws:alerts"],
    "analyst": [
        "devices:read", "alerts:read", "ws:alerts", "terminal:exec",
        "scan:execute", "ai:generate", "surveillance:read", "surveillance:write", "cases:write",
        "soar:approve",
    ],
    "admin": [
        "devices:read", "devices:write", "alerts:read", "ws:alerts",
        "terminal:exec", "scan:execute", "ai:generate", "admin:manage",
        "surveillance:read", "surveillance:write", "cases:write",
        "soar:manage", "soar:approve",
    ],
}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    if "sqlite" not in str(engine.url):
        pytest.skip("Audit tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


# ── Helpers ────────────────────────────────────────────────────────────

def _seed_user(username, role, tenant_id="default", is_active=True,
               password_hash="x", email=None):
    db = SessionLocal()
    try:
        u = TenantUser(
            tenant_id=tenant_id,
            username=username,
            password_hash=password_hash,
            role=role,
            is_active=is_active,
            email=email,
        )
        db.add(u)
        db.commit()
        db.refresh(u)
        return u
    finally:
        db.close()


def _seed_tenant(tenant_id, company_name="Default", email=None):
    db = SessionLocal()
    try:
        t = Tenant(id=tenant_id, company_name=company_name,
                   email=email or f"{tenant_id}@example.com")
        db.add(t)
        db.commit()
        return t
    finally:
        db.close()


def _token(username, tenant_id="default", role="analyst"):
    return create_access_token({
        "sub": username,
        "scopes": SCOPES.get(role, SCOPES["analyst"]),
        "tenant_id": tenant_id,
    })


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ── 1. WebSocket auth ─────────────────────────────────────────────────

def test_ws_accepts_jwt_token(client):
    """Un JWT valide passé en query param `token` est accepté."""
    tok = _token("alice", tenant_id="default", role="analyst")
    with client.websocket_connect(f"/ws/status?token={tok}") as ws:
        ws.send_text("ping")
        # Si la connexion reste ouverte sans close 4001, l'auth a réussi.
        ws.send_text("ping")


def test_ws_accepts_api_key(client):
    with client.websocket_connect(f"/ws/status?api_key={API_KEY}") as ws:
        ws.send_text("ping")


def test_ws_rejects_invalid_credentials(client):
    from starlette.websockets import WebSocketDisconnect
    # Le serveur envoie d'abord un message d'erreur, puis ferme avec 4001.
    with client.websocket_connect("/ws/status?token=garbage.token.here") as ws:
        msg = ws.receive_text()
        assert "Unauthorized" in msg
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
        assert exc.value.code == 4001


# ── 2. /api/real-alerts tenant scoping ────────────────────────────────

def test_real_alerts_tenant_scoped(client):
    _seed_tenant("tenant-a")
    _seed_tenant("tenant-b")
    db = SessionLocal()
    try:
        db.add_all([
            Alert(tenant_id="tenant-a", description="A-alert",
                  severity=5, timestamp=None),
            Alert(tenant_id="tenant-b", description="B-alert",
                  severity=5, timestamp=None),
        ])
        db.commit()
    finally:
        db.close()

    # tenant-a ne voit que ses alertes
    r = client.get("/api/real-alerts",
                   headers={"X-API-Key": API_KEY, "X-Tenant-ID": "tenant-a"})
    assert r.status_code == 200
    assert all("A-alert" == a["Description"] for a in r.json())

    # tenant-b ne voit que ses alertes
    r = client.get("/api/real-alerts",
                   headers={"X-API-Key": API_KEY, "X-Tenant-ID": "tenant-b"})
    assert r.status_code == 200
    assert all("B-alert" == a["Description"] for a in r.json())


# ── 3. Write endpoint scope enforcement ───────────────────────────────

def test_terminal_exec_requires_scope(client):
    _seed_user("viewer", role="viewer")
    # viewer n'a pas terminal:exec → 403
    r = client.post("/api/terminal/exec",
                    json={"target": "wazuh", "command": "ls"},
                    headers=_auth(_token("viewer", tenant_id="default", role="viewer")))
    assert r.status_code == 403
    # admin a terminal:exec → atteint le handler (réponse métier attendue)
    _seed_user("admin", role="admin")
    r = client.post("/api/terminal/exec",
                    json={"target": "wazuh", "command": "ls"},
                    headers=_auth(_token("admin", tenant_id="default", role="admin")))
    assert r.status_code == 200


def test_network_device_write_requires_admin_scope(client):
    _seed_user("analyst", role="analyst")
    _seed_tenant("default")
    # analyst sans admin:manage → refusé sur create / push / test
    # (RBAC write=analyst passe, mais has_scopes_or_api_key renvoie 401)
    h = _auth(_token("analyst", tenant_id="default", role="analyst"))
    r = client.post("/api/network-devices",
                    json={"name": "sw1", "ip": "10.0.0.1", "device_type": "switch"},
                    headers=h)
    assert r.status_code in (401, 403)

    # admin avec admin:manage → création OK (endpoint tenant-scoped)
    _seed_user("admin", role="admin")
    h_admin = _auth(_token("admin", tenant_id="default", role="admin"))
    r = client.post("/api/network-devices",
                    json={"name": "sw1", "ip": "10.0.0.1", "device_type": "switch"},
                    headers=h_admin)
    assert r.status_code == 200
    dev_id = r.json()["id"]

    r = client.post(f"/api/network-devices/{dev_id}/test-connection",
                    json={}, headers=h)
    assert r.status_code in (401, 403)

    r = client.post(f"/api/network-devices/{dev_id}/push-config",
                    json={"config": {"device_type": "switch"}}, headers=h)
    assert r.status_code in (401, 403)


def test_rules_write_requires_admin_scope(client):
    _seed_user("analyst", role="analyst")
    h = _auth(_token("analyst", tenant_id="default", role="analyst"))
    # RBAC rules: write=admin → analyst 403
    r = client.post("/api/rules",
                    json={"name": "rule", "conditions": []}, headers=h)
    assert r.status_code == 403
    r = client.post("/api/rules/test",
                    json={"rule": {"name": "r", "conditions": []}, "sample_alert": {}},
                    headers=h)
    assert r.status_code == 403

    # GET /api/rules : RBAC read=admin → viewer 403, admin 200
    _seed_user("viewer", role="viewer")
    r = client.get("/api/rules", headers=_auth(_token("viewer", tenant_id="default", role="viewer")))
    assert r.status_code == 403
    _seed_user("admin", role="admin")
    r = client.get("/api/rules", headers=_auth(_token("admin", tenant_id="default", role="admin")))
    assert r.status_code == 200


# ── 4. Sensor endpoints auth ──────────────────────────────────────────

def test_sensors_health_requires_auth(client):
    r = client.get("/api/sensors/health")
    assert r.status_code in (401, 403)
    r = client.get("/api/sensors/health", headers={"X-API-Key": API_KEY})
    assert r.status_code == 200


def test_sensors_analysts_requires_devices_read(client):
    _seed_user("viewer", role="viewer")
    # viewer a devices:read → OK
    r = client.get("/api/sensors/analysts?hours=24",
                   headers=_auth(_token("viewer", tenant_id="default", role="viewer")))
    assert r.status_code == 200
    # anonyme → refusé
    r = client.get("/api/sensors/analysts?hours=24")
    assert r.status_code in (401, 403)


def test_sensors_analyst_username_requires_devices_read(client):
    _seed_user("viewer", role="viewer")
    r = client.get("/api/sensors/analyst/bob?hours=24",
                   headers=_auth(_token("viewer", tenant_id="default", role="viewer")))
    assert r.status_code == 200
    r = client.get("/api/sensors/analyst/bob?hours=24")
    assert r.status_code in (401, 403)


# ── 5. nmap-scan JSON body ────────────────────────────────────────────

def test_nmap_scan_accepts_json_body(client):
    # Frontend envoie {target, scan_type} en JSON → réponse 200 (tâche Celery)
    r = client.post("/api/tasks/nmap-scan",
                    json={"target": "192.168.1.0/24", "scan_type": "ports"},
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "PENDING"
    assert "task_id" in body


def test_nmap_scan_invalid_target(client):
    r = client.post("/api/tasks/nmap-scan",
                    json={"target": "not-an-ip", "scan_type": "ports"},
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 400


# ── 6. Face image route ───────────────────────────────────────────────

def test_face_image_returns_404_when_missing(client):
    _seed_user("viewer", role="viewer")
    r = client.get("/api/faces/image/nobody",
                   headers=_auth(_token("viewer", tenant_id="default", role="viewer")))
    assert r.status_code == 404


def test_face_image_requires_auth(client):
    r = client.get("/api/faces/image/nobody")
    assert r.status_code in (401, 403)


# ── 7. Anonymous register forces default tenant ───────────────────────

def test_register_anonymous_uses_default_tenant(client, monkeypatch):
    # Désactive le rate-limit Redis (persiste entre runs dans la fenêtre 300s)
    from app.interface.api import auth as auth_api
    async def _no_rate_limit(request, max_attempts=5, window_seconds=60, **_kwargs):
        # **_kwargs : check_rate_limit() accepte désormais `username=` (limite par
        # compte en plus de l'IP). Sans ça, le stub levait TypeError.
        return None
    monkeypatch.setattr(auth_api, "check_rate_limit", _no_rate_limit)
    username = f"anonreg_{uuid.uuid4().hex[:8]}"
    # Header X-Tenant-ID fourni par le client → ignoré car non authentifié.
    # Mode approbation admin par défaut : la demande pending est créée.
    r = client.post("/auth/register",
                    json={"username": username, "password": "Str0ngPass!"},
                    headers={"X-Tenant-ID": "evil-tenant"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending"
    assert "access_token" not in body
    # La demande d'inscription est rattachée au tenant par défaut (pas "evil-tenant")
    from app.models import RegistrationRequest
    db = SessionLocal()
    try:
        row = db.query(RegistrationRequest).filter_by(id=body["request_id"]).first()
    finally:
        db.close()
    assert row is not None
    assert row.tenant_id == "default"


# ── 8. Subscribe response includes plan + status ──────────────────────

def test_subscribe_response_includes_plan_and_status(client):
    _seed_tenant("default")
    _seed_user("admin", role="admin")
    r = client.post("/api/tenants/subscribe",
                    json={"plan": "pro"},
                    headers=_auth(_token("admin", tenant_id="default", role="admin")))
    assert r.status_code == 200
    body = r.json()
    assert body["plan"] == "pro"
    assert body["status"] == "active"
    assert "subscription_end" in body


# ── 9. Console-admin token access (ADMIN_JWT_SECRET) ───────────────────

def test_admin_token_accesses_sensor_endpoints(client):
    """Le token console (ADMIN_JWT_SECRET) passe require_role ET les deps de
    scope : l'app admin-frontend (polling sensors toutes les 15s) ne doit plus
    recevoir de 401 → plus de boucle de déconnexion."""
    from app.admin_auth import create_admin_token
    headers = _auth(create_admin_token())
    # require_role (sensors read=viewer) + has_scopes_or_api_key(devices:read)
    r = client.get("/api/sensors/analysts?hours=24", headers=headers)
    assert r.status_code == 200
    # require_role + get_api_key_or_jwt
    r = client.get("/api/sensors/health", headers=headers)
    assert r.status_code == 200


def test_admin_token_on_write_endpoint(client):
    """Le token console est opérateur : il passe aussi les scopes écriture."""
    from app.admin_auth import create_admin_token
    headers = _auth(create_admin_token())
    r = client.post("/api/terminal/exec",
                    json={"target": "wazuh", "command": "ls"}, headers=headers)
    assert r.status_code == 200


def test_bogus_token_still_rejected(client):
    r = client.get("/api/sensors/analysts?hours=24",
                   headers=_auth("garbage.token.value"))
    assert r.status_code in (401, 403)
