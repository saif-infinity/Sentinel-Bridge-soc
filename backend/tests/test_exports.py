"""
R11 — Tests des exports (CSV / PDF / Markdown) pour alertes et cases.

Pattern (miroir de test_cases.py) : DATABASE_URL surchargé AVANT tout import
app.* ; `import app.models` avant create_all ; TestClient avec X-API-Key.
Run: python -m pytest tests/test_exports.py -q
"""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_r11_export_test.db')}"

import pytest  # noqa: E402

import app.models  # noqa: E402,F401  # enregistre toutes les tables avant create_all
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Alert, CaseAlertLink, SuricataAlert  # noqa: E402
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


def _seed_suricata(alert_msg="ET MALWARE", severity=3, src_ip="10.0.0.2",
                   dest_ip="8.8.8.8", tenant_id="default") -> int:
    db = SessionLocal()
    try:
        a = SuricataAlert(tenant_id=tenant_id, event_type="alert", alert_msg=alert_msg,
                          severity=severity, src_ip=src_ip, dest_ip=dest_ip,
                          proto="TCP", normalized_severity=severity)
        db.add(a)
        db.commit()
        db.refresh(a)
        return a.id
    finally:
        db.close()


def _create_case(client, title="Affaire export", **overrides):
    payload = {"title": title, "description": "description de test", "severity": 8}
    payload.update(overrides)
    r = client.post("/api/cases", json=payload, headers=HEADERS)
    assert r.status_code == 201, r.text
    return r.json()


def test_export_alerts_csv(client):
    _seed_alert("First alert", severity=12)
    _seed_alert("Second alert", severity=5)
    r = client.get("/api/alerts/export.csv", headers=HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "\ufeff" in r.text  # BOM Excel
    assert "First alert" in r.text
    assert "Second alert" in r.text


def test_export_suricata_csv(client):
    _seed_suricata()
    r = client.get("/api/suricata-alerts/export.csv", headers=HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "ET MALWARE" in r.text


def test_export_alerts_pdf(client):
    _seed_alert("PDF alert", severity=12)
    r = client.get("/api/alerts/export.pdf", headers=HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/pdf")
    assert r.content.startswith(b"%PDF")


def test_export_case_markdown(client):
    aid = _seed_alert("Linked alert", severity=12)
    c = _create_case(client, title="Affaire export MD")
    r = client.post(f"/api/cases/{c['id']}/alerts",
                    json={"alert_type": "alert", "alert_id": aid}, headers=HEADERS)
    assert r.status_code == 201, r.text
    r = client.get(f"/api/cases/{c['id']}/export.md", headers=HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "Affaire export MD" in r.text
    assert "Linked alert" in r.text


def test_export_case_markdown_not_found(client):
    r = client.get("/api/cases/9999/export.md", headers=HEADERS)
    assert r.status_code == 404


def test_export_requires_auth(client):
    r = client.get("/api/alerts/export.csv")
    assert r.status_code in (401, 403)