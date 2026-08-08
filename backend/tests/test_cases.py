"""
F2 — Tests de l'API Cases (gestion des affaires, triage, timeline).

Pattern: SQLite temporaire via surcharge de DATABASE_URL AVANT l'import d'app
(settings singleton) ; `import app.models` avant `create_all` ; TestClient
avec en-tête X-API-Key (clef lue depuis settings, comme dans .env).
Run: python -m pytest tests/test_cases.py -q
"""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_f2_test.db')}"

import pytest  # noqa: E402

import app.models  # noqa: E402,F401  # enregistre toutes les tables avant create_all
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Alert  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    c = TestClient(app)
    yield c


def _seed_alert(description="Suspicious login", severity=9, src_ip="10.0.0.1",
                tenant_id="default") -> int:
    db = SessionLocal()
    try:
        a = Alert(tenant_id=tenant_id, description=description, severity=severity,
                  src_ip=src_ip, normalized_severity=severity)
        db.add(a)
        db.commit()
        db.refresh(a)
        return a.id
    finally:
        db.close()


def _create_case(client, title="Affaire test", **overrides):
    payload = {"title": title, "description": "description de test", "severity": 8}
    payload.update(overrides)
    r = client.post("/api/cases", json=payload, headers=HEADERS)
    assert r.status_code == 201, r.text
    return r.json()


def test_create_case(client):
    r = client.post("/api/cases", json={"title": "Affaire de test", "severity": 8},
                    headers=HEADERS)
    assert r.status_code == 201
    body = r.json()
    assert body["title"] == "Affaire de test"
    assert body["status"] == "open"
    assert body["created_by"] == "api_key"
    assert body["severity"] == 8
    assert body["links_count"] == 0


def test_create_case_requires_auth(client):
    r = client.post("/api/cases", json={"title": "No auth"})
    # F4 RBAC: require_role short-circuits first and returns 401 for
    # unauthenticated requests (previously 403 from get_api_key_or_jwt).
    assert r.status_code in (401, 403)


def test_create_case_missing_title(client):
    r = client.post("/api/cases", json={"title": " "}, headers=HEADERS)
    assert r.status_code == 422


def test_list_cases_and_filter_by_status(client):
    _create_case(client, "Affaire A")
    _create_case(client, "Affaire B", status="resolved")
    _create_case(client, "Affaire C", status="closed")

    r = client.get("/api/cases", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 3

    r = client.get("/api/cases?status=resolved", headers=HEADERS)
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["title"] == "Affaire B"

    r = client.get("/api/cases?q=Affaire+A", headers=HEADERS)
    assert r.json()["total"] == 1


def test_case_stats(client):
    _create_case(client, "Affaire A")
    _create_case(client, "Affaire B", severity=12, status="in_progress")
    _create_case(client, "Affaire C", severity=3)
    r = client.get("/api/cases/stats", headers=HEADERS)
    body = r.json()
    assert body["open"] == 2
    assert body["in_progress"] == 1
    assert body["total"] == 3
    assert body["high_severity_active"] == 2  # sev >= 8 et non clôturée


def test_get_case_not_found(client):
    r = client.get("/api/cases/999", headers=HEADERS)
    assert r.status_code == 404


def test_update_case(client):
    c = _create_case(client)
    r = client.put(f"/api/cases/{c['id']}", json={"description": "mise à jour"},
                   headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["description"] == "mise à jour"


def test_link_alert_and_duplicate_409(client):
    aid = _seed_alert()
    c = _create_case(client)
    r = client.post(f"/api/cases/{c['id']}/alerts",
                    json={"alert_type": "alert", "alert_id": aid}, headers=HEADERS)
    assert r.status_code == 201
    body = r.json()
    assert body["alert_type"] == "alert"
    assert body["alert_id"] == aid
    assert body["link_status"] == "open"

    # doublon → 409
    r2 = client.post(f"/api/cases/{c['id']}/alerts",
                     json={"alert_type": "alert", "alert_id": aid}, headers=HEADERS)
    assert r2.status_code == 409

    # alerte inexistante dans ce tenant → 404
    r3 = client.post(f"/api/cases/{c['id']}/alerts",
                     json={"alert_type": "alert", "alert_id": 9999}, headers=HEADERS)
    assert r3.status_code == 404


def test_linkable_alerts(client):
    _seed_alert("First alert")
    _seed_alert("Second alert")
    r = client.get("/api/cases/linkable-alerts?source=alert&limit=50", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, list)
    assert len(body) == 2
    assert all(a["alert_type"] == "alert" for a in body)


def test_triage_status_and_note(client):
    aid = _seed_alert()
    c = _create_case(client)
    link = client.post(f"/api/cases/{c['id']}/alerts",
                       json={"alert_type": "alert", "alert_id": aid},
                       headers=HEADERS).json()

    r = client.post(f"/api/cases/{c['id']}/alerts/{link['link_id']}/triage",
                    json={"status": "resolved", "note": "Faux positif — trafic légitime"},
                    headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["link_status"] == "resolved"
    assert body["link_note"] == "Faux positif — trafic légitime"
    assert body["triaged_by"] == "api_key"
    assert body["triaged_at"] is not None

    # statut invalide → 422
    r2 = client.post(f"/api/cases/{c['id']}/alerts/{link['link_id']}/triage",
                     json={"status": "bogus"}, headers=HEADERS)
    assert r2.status_code == 422


def test_unlink_alert(client):
    aid = _seed_alert()
    c = _create_case(client)
    link = client.post(f"/api/cases/{c['id']}/alerts",
                       json={"alert_type": "alert", "alert_id": aid},
                       headers=HEADERS).json()
    r = client.delete(f"/api/cases/{c['id']}/alerts/{link['link_id']}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "unlinked"

    alerts = client.get(f"/api/cases/{c['id']}/alerts", headers=HEADERS).json()
    assert alerts == []


def test_add_timeline_note(client):
    c = _create_case(client)
    r = client.post(f"/api/cases/{c['id']}/timeline",
                    json={"note": "Investigation en cours…"}, headers=HEADERS)
    assert r.status_code == 201
    body = r.json()
    assert body["event_type"] == "note_added"
    assert body["message"] == "Investigation en cours…"

    tl = client.get(f"/api/cases/{c['id']}/timeline", headers=HEADERS).json()
    assert any(ev["event_type"] == "note_added" for ev in tl)
    assert any(ev["event_type"] == "created" for ev in tl)


def test_close_and_reopen_case(client):
    c = _create_case(client)
    r = client.post(f"/api/cases/{c['id']}/close",
                    json={"resolution": "Incident contenu"}, headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "closed"
    assert body["closed_by"] == "api_key"
    assert body["closed_at"] is not None

    # double clôture → 409
    r2 = client.post(f"/api/cases/{c['id']}/close", json={}, headers=HEADERS)
    assert r2.status_code == 409

    r3 = client.post(f"/api/cases/{c['id']}/reopen", headers=HEADERS)
    assert r3.status_code == 200
    assert r3.json()["status"] == "open"

    # réouverture d'une affaire déjà ouverte → 409
    r4 = client.post(f"/api/cases/{c['id']}/reopen", headers=HEADERS)
    assert r4.status_code == 409


def test_delete_case(client):
    c = _create_case(client)
    r = client.delete(f"/api/cases/{c['id']}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "deleted"

    r2 = client.get(f"/api/cases/{c['id']}", headers=HEADERS)
    assert r2.status_code == 404
