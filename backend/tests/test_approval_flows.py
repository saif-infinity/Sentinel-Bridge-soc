"""
Flux d'approbation admin — tests.

Couvre les nouveaux flux implémentés :
  A. Inscription → demande pending → approbation/refus admin → login
  B. Connexion faciale → demande pending → approbation/refus admin
  C. Scoping tenant des demandes (pas de fuite cross-tenant)

Pattern (miroir de test_audit_fixes.py) : DATABASE_URL surchargé AVANT tout
import app.* ; `import app.models` avant create_all ; TestClient avec
with TestClient(app) as c: pour déclencher startup.

Run: python -m pytest tests/test_approval_flows.py -q
"""
import os
import tempfile
import uuid

os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32chars-minimum!!"
os.environ["API_KEY"] = "test-api-key"
os.environ["WAZUH_PASS"] = "test-wazuh-pass"
os.environ["WAZUH_INDEXER_PASS"] = "test-indexer-pass"
os.environ["SURICATA_PASS"] = "test-suricata-pass"
os.environ["WAZUH_SSH_PASS"] = "test-ssh-pass"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["ADMIN_JWT_SECRET"] = "test-admin-jwt-secret"
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_approval_test.db')}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401  # enregistre toutes les tables avant create_all
from app.admin_auth import create_admin_token  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.core.jwt_utils import create_access_token  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import FaceLoginRequest, RegistrationRequest  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY}
ADMIN_HEADERS = {"Authorization": f"Bearer {create_admin_token()}"}

SCOPES = {
    "analyst": [
        "devices:read", "alerts:read", "ws:alerts", "terminal:exec",
        "scan:execute", "ai:generate", "surveillance:read", "cases:write",
        "soar:approve",
    ],
}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    if "sqlite" not in str(engine.url):
        pytest.skip("Approval-flow tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture(autouse=True)
def _no_rate_limit(monkeypatch):
    """Désactive le rate-limit Redis (register + token) pour chaque test."""
    from app.interface.api import auth as auth_api

    async def _no_rate_limit(request, max_attempts=5, window_seconds=60):
        return None

    monkeypatch.setattr(auth_api, "check_rate_limit", _no_rate_limit)


@pytest.fixture(autouse=True)
def _force_pending_mode(monkeypatch):
    """Force REGISTRATION_REQUIRES_APPROVAL = True pour les tests."""
    import app.interface.api.auth as auth_api
    monkeypatch.setattr(auth_api, "REGISTRATION_REQUIRES_APPROVAL", True)


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


def _user_token(username: str, tenant_id: str = "default") -> str:
    return create_access_token(
        data={"sub": username, "role": "analyst", "scopes": SCOPES["analyst"], "tenant_id": tenant_id}
    )


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _register(client, username: str, password: str = "Str0ngPass!") -> dict:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _approve_registration(client, request_id: int) -> dict:
    r = client.post(f"/api/admin/registration-requests/{request_id}/approve", headers=ADMIN_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def _login(client, username: str, password: str = "Str0ngPass!"):
    return client.post("/auth/token", data={"username": username, "password": password})


# ── A. Inscription → approbation/refus admin ─────────────────────

def test_register_creates_pending_request(client):
    username = f"reg_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    assert body["status"] == "pending"
    assert isinstance(body["request_id"], int)
    # Pas de token direct dans le mode pending
    assert "access_token" not in body


def test_register_duplicate_pending_conflict(client):
    username = f"dup_{uuid.uuid4().hex[:8]}"
    _register(client, username)
    r = client.post("/auth/register", json={"username": username, "password": "Str0ngPass!"})
    assert r.status_code == 409
    assert "attente" in r.json()["detail"]


def test_register_request_status_endpoint(client):
    username = f"st_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    r = client.get(f"/auth/register-request/{body['request_id']}")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_admin_lists_registration_requests(client):
    username = f"lst_{uuid.uuid4().hex[:8]}"
    _register(client, username)
    r = client.get("/api/admin/registration-requests?status=pending", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(i["username"] == username and i["status"] == "pending" for i in items)


def test_approve_registration_then_login(client):
    username = f"appr_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    # Avant approbation : login impossible
    assert _login(client, username).status_code == 401
    # Approbation admin
    result = _approve_registration(client, body["request_id"])
    assert result["status"] == "approved"
    # Statut visible côté analyste
    r = client.get(f"/auth/register-request/{body['request_id']}")
    assert r.json()["status"] == "approved"
    # Login fonctionne maintenant
    r = _login(client, username)
    assert r.status_code == 200, r.text
    assert "access_token" in r.json()


def test_refuse_registration_blocks_login(client):
    username = f"ref_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    r = client.post(f"/api/admin/registration-requests/{body['request_id']}/refuse", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "refused"
    # Login toujours impossible après refus
    assert _login(client, username).status_code == 401
    # Double résolution refusée
    r = client.post(f"/api/admin/registration-requests/{body['request_id']}/refuse", headers=ADMIN_HEADERS)
    assert r.status_code == 400


def test_approve_unknown_request_404(client):
    r = client.post("/api/admin/registration-requests/999999/approve", headers=ADMIN_HEADERS)
    assert r.status_code == 404


# ── B. Connexion faciale → approbation/refus admin ────────────────

@pytest.fixture()
def _mock_face_verify(monkeypatch):
    from app.interface.api import faces as faces_api
    monkeypatch.setattr(
        faces_api.face_service,
        "verify_face",
        lambda username, image, tenant_id="default": (True, "ok"),
    )


def test_face_login_request_flow(client, _mock_face_verify):
    username = f"face_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    _approve_registration(client, body["request_id"])
    token = _user_token(username)

    # Demande de connexion faciale
    r = client.post(
        "/api/faces/request-login",
        json={"username": username, "image": "base64fake"},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "pending"
    assert isinstance(data["request_id"], int)

    # Statut côté analyste
    r = client.get(f"/api/faces/login-request/{data['request_id']}", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["status"] == "pending"

    # Liste admin
    r = client.get("/api/admin/face-login-requests?status=pending", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert any(i["id"] == data["request_id"] and i["username"] == username for i in r.json()["items"])

    # Approbation admin
    r = client.post(f"/api/admin/face-login-requests/{data['request_id']}/approve", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "approved"

    # Statut final côté analyste
    r = client.get(f"/api/faces/login-request/{data['request_id']}", headers=_auth(token))
    assert r.json()["status"] == "approved"


def test_face_login_request_refused(client, _mock_face_verify):
    username = f"faceref_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    _approve_registration(client, body["request_id"])
    token = _user_token(username)

    r = client.post(
        "/api/faces/request-login",
        json={"username": username, "image": "base64fake"},
        headers=_auth(token),
    )
    assert r.status_code == 200
    request_id = r.json()["request_id"]

    r = client.post(f"/api/admin/face-login-requests/{request_id}/refuse", headers=ADMIN_HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "refused"

    r = client.get(f"/api/faces/login-request/{request_id}", headers=_auth(token))
    assert r.json()["status"] == "refused"


def test_face_login_request_forbidden_for_other_user(client, _mock_face_verify):
    username = f"faceforb_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    _approve_registration(client, body["request_id"])
    token = _user_token(username)

    # Demande pour un AUTRE compte que celui du JWT → 403
    r = client.post(
        "/api/faces/request-login",
        json={"username": "someone_else", "image": "base64fake"},
        headers=_auth(token),
    )
    assert r.status_code == 403


def test_face_login_request_requires_auth(client):
    r = client.post(
        "/api/faces/request-login",
        json={"username": "nobody", "image": "base64fake"},
    )
    assert r.status_code in (401, 403)


# ── C. Scoping tenant ─────────────────────────────────────────────

def test_registration_request_forced_to_default_tenant(client):
    username = f"tenant_{uuid.uuid4().hex[:8]}"
    # Header X-Tenant-ID fourni par un client anonyme → ignoré
    r = client.post(
        "/auth/register",
        json={"username": username, "password": "Str0ngPass!"},
        headers={"X-Tenant-ID": "evil-tenant"},
    )
    assert r.status_code == 200
    request_id = r.json()["request_id"]
    db = SessionLocal()
    try:
        row = db.query(RegistrationRequest).filter_by(id=request_id).first()
    finally:
        db.close()
    assert row is not None
    assert row.tenant_id == "default"


def test_face_login_request_tenant_scoped(client, _mock_face_verify):
    username = f"faceten_{uuid.uuid4().hex[:8]}"
    body = _register(client, username)
    _approve_registration(client, body["request_id"])
    token = _user_token(username, tenant_id="default")

    r = client.post(
        "/api/faces/request-login",
        json={"username": username, "image": "base64fake"},
        headers=_auth(token),
    )
    assert r.status_code == 200
    request_id = r.json()["request_id"]

    db = SessionLocal()
    try:
        row = db.query(FaceLoginRequest).filter_by(id=request_id).first()
    finally:
        db.close()
    assert row is not None
    assert row.tenant_id == "default"
