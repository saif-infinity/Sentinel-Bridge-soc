"""
F2 — Tests de l'API Hunting (chasses enregistrées + preview non persistée).

Pattern: SQLite temporaire via surcharge de DATABASE_URL AVANT l'import d'app ;
`import app.models` avant `create_all` ; TestClient avec X-API-Key.
Run: python -m pytest tests/test_hunts.py -q
"""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_f2_test.db')}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Alert, SuricataAlert  # noqa: E402

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


def _seed_suricata(alert_msg="ET MALWARE", severity=1, src_ip="192.168.1.5",
                   tenant_id="default") -> int:
    db = SessionLocal()
    try:
        s = SuricataAlert(tenant_id=tenant_id, event_type="alert", alert_msg=alert_msg,
                          severity=severity, src_ip=src_ip, dest_ip="8.8.8.8",
                          proto="TCP", normalized_severity=15)
        db.add(s)
        db.commit()
        db.refresh(s)
        return s.id
    finally:
        db.close()


def _create_hunt(client, name="Chasse test", conditions=None, target="both"):
    payload = {
        "name": name,
        "description": "description",
        "target": target,
        "conditions": conditions or [{"field": "normalized_severity", "op": "ge", "value": 8}],
    }
    r = client.post("/api/hunts", json=payload, headers=HEADERS)
    assert r.status_code == 201, r.text
    return r.json()


def test_create_and_list_hunt(client):
    h = _create_hunt(client)
    assert h["name"] == "Chasse test"
    assert h["target"] == "both"
    assert h["conditions"][0]["field"] == "normalized_severity"
    assert h["last_run_at"] is None

    r = client.get("/api/hunts", headers=HEADERS)
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_create_hunt_requires_conditions(client):
    r = client.post("/api/hunts", json={"name": "Sans conditions", "target": "both",
                                        "conditions": []}, headers=HEADERS)
    assert r.status_code == 422


def test_create_hunt_invalid_op(client):
    r = client.post("/api/hunts", json={"name": "Bad op", "target": "both",
                                        "conditions": [{"field": "src_ip", "op": "bogus", "value": "x"}]},
                    headers=HEADERS)
    assert r.status_code == 422


def test_get_and_update_hunt(client):
    h = _create_hunt(client)
    r = client.get(f"/api/hunts/{h['id']}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["id"] == h["id"]

    r = client.put(f"/api/hunts/{h['id']}",
                   json={"name": "Chasse renommée",
                         "conditions": [{"field": "src_ip", "op": "eq", "value": "10.0.0.1"}]},
                   headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Chasse renommée"
    assert body["conditions"][0]["field"] == "src_ip"


def test_delete_hunt(client):
    h = _create_hunt(client)
    r = client.delete(f"/api/hunts/{h['id']}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "deleted"

    r2 = client.get(f"/api/hunts/{h['id']}", headers=HEADERS)
    assert r2.status_code == 404


def test_preview_no_persistence(client):
    _seed_alert(severity=9)
    _seed_alert(severity=3)
    _seed_suricata(severity=1)

    r = client.post("/api/hunts/preview",
                    json={"target": "both",
                          "conditions": [{"field": "normalized_severity", "op": "ge", "value": 8}],
                          "limit": 100},
                    headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["preview"] is True
    assert body["hunt"] is None
    assert body["matched"] == 2  # alert sev 9 + suricata sev 15
    assert len(body["results"]) == 2

    # preview ne crée AUCUNE chasse enregistrée
    r2 = client.get("/api/hunts", headers=HEADERS)
    assert r2.json() == []


def test_run_persists_last_run(client):
    _seed_alert(severity=9)
    h = _create_hunt(client, conditions=[{"field": "normalized_severity", "op": "ge", "value": 8}])
    assert h["last_run_at"] is None

    r = client.post(f"/api/hunts/{h['id']}/run", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["preview"] is False
    assert body["matched"] == 1
    assert body["hunt"]["last_run_at"] is not None
    assert body["hunt"]["last_run_count"] == 1
    assert body["hunt"]["last_run_by"] == "api_key"

    # la chasse enregistrée porte bien les infos de dernière exécution
    r2 = client.get(f"/api/hunts/{h['id']}", headers=HEADERS)
    assert r2.json()["last_run_count"] == 1
    assert r2.json()["last_run_at"] is not None


def test_run_hunt_not_found(client):
    r = client.post("/api/hunts/999/run", headers=HEADERS)
    assert r.status_code == 404


def test_limit_clamp(client):
    """run_hunt clamps limit dans [1, 1000] (défense en profondeur)."""
    from app.application.hunts import run_hunt  # noqa: PLC0415
    db = SessionLocal()
    try:
        _seed_alert(severity=9)
        res = run_hunt(db, "default", "api_key",
                       conditions=[{"field": "normalized_severity", "op": "ge", "value": 8}],
                       target="alert", limit=5000, preview=True)
        assert res["scanned"] == 1000  # clampé à 1000
        res2 = run_hunt(db, "default", "api_key",
                        conditions=[{"field": "normalized_severity", "op": "ge", "value": 8}],
                        target="alert", limit=0, preview=True)
        assert res2["scanned"] == 1  # clampé à 1
    finally:
        db.close()


def test_preview_with_hunt_id_422(client):
    """preview=True ET hunt_id défini → 422 (interdit par le contrat)."""
    from app.application.hunts import run_hunt  # noqa: PLC0415
    db = SessionLocal()
    try:
        h = _create_hunt(client)
        with pytest.raises(Exception) as exc:
            run_hunt(db, "default", "api_key", hunt_id=h["id"],
                     conditions=[{"field": "src_ip", "op": "eq", "value": "1.1.1.1"}],
                     preview=True)
        assert exc.value.status_code == 422
    finally:
        db.close()
