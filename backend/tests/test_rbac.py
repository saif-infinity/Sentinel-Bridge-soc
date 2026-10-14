"""
F4 — Tests RBAC (rôles viewer/analyst/admin/super_admin, require_role,
endpoints admin/super-admin, bootstrap super admin).

Pattern (miroir de test_hunts.py) : DATABASE_URL + SUPER_ADMIN_PASSWORD +
SUPER_ADMIN_API_KEY surchargés AVANT tout import app.* ; `import app.models`
avant create_all ; fixture `client` avec `with TestClient(app) as c:` pour
déclencher startup → run_startup → seeding du super admin.

Run: python -m pytest tests/test_rbac.py -q
"""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_f4_rbac_test.db')}"
os.environ["SUPER_ADMIN_PASSWORD"] = "test-sa-pass"
os.environ["SUPER_ADMIN_API_KEY"] = "test-sa-key"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import SecretStr  # noqa: E402

import app.models  # noqa: E402,F401  # enregistre toutes les tables avant create_all
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.core.jwt_utils import create_access_token  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Tenant, TenantUser  # noqa: E402

# Si un autre module de test a déjà importé app (settings singleton figé) sans
# ces variables, on les injecte ici pour que le bootstrap seed le super admin.
if not settings.SUPER_ADMIN_PASSWORD.get_secret_value():
    settings.SUPER_ADMIN_PASSWORD = SecretStr("test-sa-pass")
if not settings.SUPER_ADMIN_API_KEY.get_secret_value():
    settings.SUPER_ADMIN_API_KEY = SecretStr("test-sa-key")

API_KEY = settings.API_KEY.get_secret_value()
SUPER_ADMIN_API_KEY = settings.SUPER_ADMIN_API_KEY.get_secret_value()

# Scopes legacy (auth.py) — requis par les deps `has_scopes_or_api_key` qui
# tournent APRÈS require_role. Le rôle réel est résolu depuis la DB.
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
    "super_admin": [
        "devices:read", "devices:write", "alerts:read", "ws:alerts",
        "terminal:exec", "scan:execute", "ai:generate", "admin:manage",
        "surveillance:read", "surveillance:write", "cases:write",
        "soar:manage", "soar:approve",
    ],
}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    """Si un autre module de test a déjà importé app avec Postgres, on skippe
    (l'override DATABASE_URL n'aurait plus d'effet)."""
    if "sqlite" not in str(engine.url):
        pytest.skip("F4 RBAC tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Le contexte TestClient déclenche startup → run_startup → seeding super admin.
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


def _db_role(username, tenant_id="default"):
    db = SessionLocal()
    try:
        row = db.query(TenantUser).filter_by(username=username, tenant_id=tenant_id).first()
        return row.role if row else None
    finally:
        db.close()


# ── 1. /api/auth/me — happy path ────────────────────────────────────────

def test_me_happy(client):
    _seed_user("admin", role="admin", email="admin@example.com")
    r = client.get("/api/auth/me", headers=_auth(_token("admin", role="admin")))
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "admin"
    assert body["role"] == "admin"
    assert body["tenant_id"] == "default"
    assert body["email"] == "admin@example.com"
    assert body["is_active"] is True


# ── 2. /api/auth/me — utilisateur inconnu / token invalide ─────────────

def test_me_missing_user_fallback(client):
    """Utilisateur non seedé → fallback JSON store → rôle par défaut **le plus bas**.

    Ce test affirmait auparavant `role == "analyst"`, c'est-à-dire qu'il verrouillait
    un RBAC *fail-open* : tout porteur d'un JWT signé dont le compte était absent de
    TenantUser obtenait un rôle qui écrit. `resolve_user_role()` retombe maintenant
    sur "viewer" (fail-closed) — voir core/rbac.py. Le test vérifie donc le comportement
    sûr, et échouera si quelqu'un réintroduit le défaut permissif.
    """
    r = client.get("/api/auth/me", headers=_auth(_token("ghost", role="analyst")))
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "ghost"
    assert body["role"] == "viewer"          # fail-closed, pas "analyst"
    assert body["email"] is None
    assert body["is_active"] is True


def test_missing_user_cannot_write(client):
    """Corollaire: le fallback viewer doit réellement interdire les écritures."""
    token = _token("ghost-writer", role="admin")   # le JWT revendique admin
    r = client.post("/api/rules", headers=_auth(token), json={"name": "x"})
    assert r.status_code in (401, 403), (
        "un utilisateur absent de TenantUser ne doit pas pouvoir écrire, "
        f"même si son JWT revendique un rôle élevé (obtenu {r.status_code})"
    )


def test_me_garbage_token(client):
    r = client.get("/api/auth/me", headers=_auth("garbage.token.here"))
    assert r.status_code == 401
    assert r.json()["detail"] == "Not authenticated"


# ── 3. /api/auth/me — compte désactivé ─────────────────────────────────

def test_me_disabled(client):
    _seed_user("disabled", role="analyst", is_active=False)
    r = client.get("/api/auth/me", headers=_auth(_token("disabled", role="analyst")))
    assert r.status_code == 401
    assert r.json()["detail"] == "Account disabled"


# ── 4. require_role — enforcement viewer/analyst ───────────────────────

def test_require_role_enforcement(client):
    _seed_user("viewer", role="viewer")
    # POST /api/cases = write → min analyst → viewer 403
    r = client.post("/api/cases", json={"title": "x", "severity": 5},
                    headers=_auth(_token("viewer", role="viewer")))
    assert r.status_code == 403
    assert r.json()["detail"] == "Not enough permissions"
    # GET /api/cases = read → min viewer → viewer 200
    r2 = client.get("/api/cases", headers=_auth(_token("viewer", role="viewer")))
    assert r2.status_code == 200


def test_no_token_guarded_route_401(client):
    r = client.get("/api/cases")
    assert r.status_code == 401
    assert r.json()["detail"] == "Not authenticated"


# ── 5. API-key bypass (jusqu'au seuil admin) ───────────────────────────

def test_api_key_bypass(client):
    r = client.post("/api/cases", json={"title": "API key case", "severity": 5},
                    headers={"X-API-Key": API_KEY})
    assert r.status_code == 201
    assert r.json()["created_by"] == "api_key"


# ── 6. API key vs seuil super_admin ────────────────────────────────────

def test_api_key_not_super_admin(client):
    r = client.get("/api/super-admin/users", headers={"X-API-Key": API_KEY})
    assert r.status_code in (401, 403)


def test_super_admin_api_key(client):
    r = client.get("/api/super-admin/users", headers={"X-API-Key": SUPER_ADMIN_API_KEY})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ── 7. Liste admin des users (tenant-scoped, exclut super_admin) ───────

def test_admin_users_list(client):
    _seed_user("admin", role="admin")
    _seed_user("viewer", role="viewer")
    _seed_user("sa", role="super_admin")            # même tenant → exclu
    _seed_tenant("tenant-b")
    _seed_user("b_user", role="analyst", tenant_id="tenant-b")  # autre tenant → exclu

    r = client.get("/api/admin/users", headers=_auth(_token("admin", role="admin")))
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert {u["username"] for u in body} == {"admin", "viewer"}
    assert all(u["tenant_id"] == "default" for u in body)
    assert all(u["role"] != "super_admin" for u in body)


# ── 8. Règles de rôle admin ────────────────────────────────────────────

def test_admin_role_rules(client):
    _seed_user("admin", role="admin")
    _seed_user("viewer", role="viewer")
    admin_headers = _auth(_token("admin", role="admin"))

    # viewer token PATCH → 403
    r = client.patch("/api/admin/users/viewer/role", json={"role": "analyst"},
                     headers=_auth(_token("viewer", role="viewer")))
    assert r.status_code == 403

    # admin assigne analyst → 200 + DB mise à jour
    r = client.patch("/api/admin/users/viewer/role", json={"role": "analyst"},
                     headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "analyst"
    assert _db_role("viewer") == "analyst"

    # admin assigne super_admin → 400
    r = client.patch("/api/admin/users/viewer/role", json={"role": "super_admin"},
                     headers=admin_headers)
    assert r.status_code == 400
    assert "super admin" in r.json()["detail"].lower()

    # admin PATCH une cible super_admin → 403
    r = client.patch("/api/admin/users/super_admin/role", json={"role": "viewer"},
                     headers=admin_headers)
    assert r.status_code == 403


def test_admin_role_whitelist_and_missing(client):
    _seed_user("admin", role="admin")
    admin_headers = _auth(_token("admin", role="admin"))

    # rôle hors whitelist → 400
    r = client.patch("/api/admin/users/viewer/role", json={"role": "bogus"},
                     headers=admin_headers)
    assert r.status_code == 400

    # utilisateur absent → 404
    r2 = client.patch("/api/admin/users/nobody/role", json={"role": "viewer"},
                      headers=admin_headers)
    assert r2.status_code == 404


def test_admin_last_admin_demotion(client):
    _seed_user("admin", role="admin")
    admin_headers = _auth(_token("admin", role="admin"))
    r = client.patch("/api/admin/users/admin/role", json={"role": "viewer"},
                     headers=admin_headers)
    assert r.status_code == 400
    assert "last admin" in r.json()["detail"].lower()


def test_admin_self_demotion_two_admins(client):
    _seed_user("admin", role="admin")
    _seed_user("admin2", role="admin")
    admin_headers = _auth(_token("admin", role="admin"))
    r = client.patch("/api/admin/users/admin/role", json={"role": "viewer"},
                     headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"


# ── 9. Lane super_admin ────────────────────────────────────────────────

def test_super_admin_bootstrap_seeded(client):
    """Le bootstrap (SUPER_ADMIN_PASSWORD défini) seed super_admin/default."""
    db = SessionLocal()
    try:
        row = db.query(TenantUser).filter_by(username="super_admin", role="super_admin").first()
        assert row is not None
        assert row.tenant_id == "default"
        assert row.is_active is True
    finally:
        db.close()


def test_super_admin_users_list(client):
    _seed_user("admin", role="admin")
    _seed_user("viewer", role="viewer")
    _seed_tenant("tenant-b")
    _seed_user("b_user", role="analyst", tenant_id="tenant-b")
    sa_headers = _auth(_token("super_admin", tenant_id="default", role="super_admin"))

    r = client.get("/api/super-admin/users", headers=sa_headers)
    assert r.status_code == 200
    body = r.json()
    usernames = {u["username"] for u in body}
    assert "super_admin" in usernames
    assert "admin" in usernames
    assert "b_user" in usernames
    assert any(u["tenant_id"] == "tenant-b" for u in body)


def test_super_admin_assign_role(client):
    _seed_user("alice", role="analyst")
    sa_headers = _auth(_token("super_admin", tenant_id="default", role="super_admin"))
    r = client.patch("/api/super-admin/users/alice/role", json={"role": "super_admin"},
                     headers=sa_headers)
    assert r.status_code == 200
    assert r.json()["role"] == "super_admin"
    assert _db_role("alice") == "super_admin"


def test_super_admin_duplicate_username_409(client):
    _seed_tenant("tenant-b")
    _seed_user("dup", role="analyst")
    _seed_user("dup", role="viewer", tenant_id="tenant-b")
    sa_headers = _auth(_token("super_admin", tenant_id="default", role="super_admin"))
    r = client.patch("/api/super-admin/users/dup/role", json={"role": "admin"},
                     headers=sa_headers)
    assert r.status_code == 409


def test_super_admin_last_super_admin_demotion(client):
    # Un seul super_admin (celui du bootstrap) → démotion interdite.
    sa_headers = _auth(_token("super_admin", tenant_id="default", role="super_admin"))
    r = client.patch("/api/super-admin/users/super_admin/role", json={"role": "admin"},
                     headers=sa_headers)
    assert r.status_code == 400
    assert "last super admin" in r.json()["detail"].lower()


# ── 10. Guard map — spot checks ────────────────────────────────────────

def test_guard_map_alerts_history_viewer(client):
    _seed_user("viewer", role="viewer")
    r = client.get("/api/alerts/history", headers=_auth(_token("viewer", role="viewer")))
    assert r.status_code == 200


def test_guard_map_tenants_current_viewer(client):
    _seed_user("viewer", role="viewer")
    r = client.get("/api/tenants/current", headers=_auth(_token("viewer", role="viewer")))
    assert r.status_code == 200


GUARD_MATRIX = [
    # (method, path, body) — analyst refusé, admin autorisé
    ("PUT", "/api/settings", {"section": "soar", "data": {"enabled": "true"}}),
    ("GET", "/api/rules", None),
    ("POST", "/api/playbooks", {"name": "pb", "steps": []}),
    ("POST", "/api/tenants/subscribe", {"plan": "basic"}),
]


@pytest.mark.parametrize("method,path,body", GUARD_MATRIX)
def test_guard_map_analyst_denied(client, method, path, body):
    _seed_user("analyst", role="analyst")
    r = client.request(method, path, json=body,
                       headers=_auth(_token("analyst", role="analyst")))
    assert r.status_code == 403
    assert r.json()["detail"] == "Not enough permissions"


@pytest.mark.parametrize("method,path,body", GUARD_MATRIX)
def test_guard_map_admin_allowed(client, method, path, body):
    _seed_user("admin", role="admin")
    _seed_tenant("default")  # requis par /api/tenants/subscribe
    r = client.request(method, path, json=body,
                       headers=_auth(_token("admin", role="admin")))
    assert r.status_code == 200


def test_tenants_register_exempt(client):
    """/api/tenants/register est exempté de require_role (exempt_paths)."""
    r = client.post("/api/tenants/register", json={
        "company_name": "Acme Corp",
        "email": "acme@example.com",
        "admin_username": "acmeadmin",
        "admin_password": "StrongPass1",
    })
    assert r.status_code == 200
    assert r.json()["tenant_id"]


# ── 11. Lane admin legacy intacte ──────────────────────────────────────

def test_legacy_admin_lane(client):
    r = client.post("/api/admin/token",
                    data={"username": "admin",
                          "password": settings.ADMIN_API_KEY.get_secret_value()})
    assert r.status_code == 200
    token = r.json()["access_token"]
    r2 = client.get("/api/admin/stats", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200


# ── 12. Routers exemptés ───────────────────────────────────────────────

def test_faces_register_exempt(client):
    """faces est exempté de require_role ; son propre dep `_require_jwt_user`
    renvoie 401 'Token Bearer requis' pour un appel anonyme."""
    r = client.post("/api/faces/register", json={"image": "abc", "username": "x"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Token Bearer requis"


def test_root_public(client):
    r = client.get("/")
    assert r.status_code == 200
