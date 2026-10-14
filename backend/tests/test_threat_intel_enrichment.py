"""
Tests d'enrichissement Threat Intelligence dans le pipeline d'ingestion.

Run: python -m pytest tests/test_threat_intel_enrichment.py -q
"""
import os
import tempfile

os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-32chars-minimum!!"
os.environ["API_KEY"] = "test-api-key"
os.environ["WAZUH_PASS"] = "test-wazuh-pass"
os.environ["WAZUH_INDEXER_PASS"] = "test-indexer-pass"
os.environ["SURICATA_PASS"] = "test-suricata-pass"
os.environ["WAZUH_SSH_PASS"] = "test-ssh-pass"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["ADMIN_JWT_SECRET"] = "test-admin-jwt-secret"
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_ti_enrichment_test.db')}"
os.environ["THREAT_INTEL_ENABLED"] = "true"

from unittest.mock import patch

import pytest  # noqa: E402

import app.models  # noqa: E402,F401
from app.application.pipeline import ingest_alert, reset_pipeline  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal  # noqa: E402


@pytest.fixture(autouse=True)
def _setup_db():
    Base.metadata.drop_all(bind=SessionLocal().get_bind())
    Base.metadata.create_all(bind=SessionLocal().get_bind())
    reset_pipeline()
    yield
    Base.metadata.drop_all(bind=SessionLocal().get_bind())


def _make_payload(src_ip: str = "1.2.3.4", description: str = "Test alert") -> dict:
    return {
        "source": "manual",
        "severity": 5,
        "description": description,
        "src_ip": src_ip,
        "tenant_id": "default",
        "agent_id": "agent-1",
    }


def test_ingest_alert_enriches_description_with_malicious_ioc():
    """Quand lookup_ip retourne verdict malicious, la description est enrichie."""
    mock_intel = {"verdict": "malicious", "score": 90, "risk_score": 90,
                  "source_name": "AbuseIPDB", "raw_json": "{}",
                  "checked_at": None, "from_cache": False}

    with patch("app.infrastructure.threat_intel.client.lookup_ip", return_value=mock_intel):
        payload = _make_payload()
        result = ingest_alert(payload)

    assert result["status"] == "accepted"

    db = SessionLocal()
    try:
        row = db.query(app.models.Alert).first()
        assert row is not None
        assert "[IoC MALICIOUS" in row.description
        assert "(score:90)" in row.description
    finally:
        db.close()


def test_ingest_alert_enriches_description_with_suspicious_ioc():
    """Quand lookup_ip retourne verdict suspicious, la description est enrichie."""
    mock_intel = {"verdict": "suspicious", "score": 55, "risk_score": 55,
                  "source_name": "AbuseIPDB", "raw_json": "{}",
                  "checked_at": None, "from_cache": False}

    with patch("app.infrastructure.threat_intel.client.lookup_ip", return_value=mock_intel):
        payload = _make_payload()
        result = ingest_alert(payload)

    assert result["status"] == "accepted"

    db = SessionLocal()
    try:
        row = db.query(app.models.Alert).first()
        assert row is not None
        assert "[IoC SUSPICIOUS" in row.description
        assert "(score:55)" in row.description
    finally:
        db.close()


def test_ingest_alert_no_enrichment_when_clean():
    """Quand lookup_ip retourne verdict clean, la description n'est pas enrichie."""
    mock_intel = {"verdict": "clean", "score": 10, "risk_score": 10,
                  "source_name": "AbuseIPDB", "raw_json": "{}",
                  "checked_at": None, "from_cache": False}

    with patch("app.infrastructure.threat_intel.client.lookup_ip", return_value=mock_intel):
        payload = _make_payload()
        result = ingest_alert(payload)

    assert result["status"] == "accepted"

    db = SessionLocal()
    try:
        row = db.query(app.models.Alert).first()
        assert row is not None
        assert "[IoC" not in row.description
        assert row.description == "Test alert"
    finally:
        db.close()


def test_ingest_alert_fail_open_on_exception():
    """Si lookup_ip lève une exception, le pipeline continue (fail open)."""
    with patch("app.infrastructure.threat_intel.client.lookup_ip", side_effect=Exception("TI down")):
        payload = _make_payload()
        result = ingest_alert(payload)

    assert result["status"] == "accepted"

    db = SessionLocal()
    try:
        row = db.query(app.models.Alert).first()
        assert row is not None
        assert row.description == "Test alert"
    finally:
        db.close()


def test_ingest_alert_no_enrichment_without_src_ip():
    """Si pas de src_ip dans le payload, pas d'enrichissement TI."""
    mock_intel = {"verdict": "malicious", "score": 90, "risk_score": 90,
                  "source_name": "AbuseIPDB", "raw_json": "{}",
                  "checked_at": None, "from_cache": False}

    with patch("app.infrastructure.threat_intel.client.lookup_ip", return_value=mock_intel):
        payload = _make_payload(src_ip="")
        result = ingest_alert(payload)

    assert result["status"] == "accepted"

    db = SessionLocal()
    try:
        row = db.query(app.models.Alert).first()
        assert row is not None
        assert row.description == "Test alert"
    finally:
        db.close()


def test_ingest_alert_no_enrichment_when_ti_disabled():
    """Quand THREAT_INTEL_ENABLED=False, pas d'enrichissement."""
    original = settings.THREAT_INTEL_ENABLED
    settings.THREAT_INTEL_ENABLED = False
    try:
        with patch("app.infrastructure.threat_intel.client.lookup_ip", return_value={
            "verdict": "malicious", "score": 90, "risk_score": 90,
            "source_name": "AbuseIPDB", "raw_json": "{}",
            "checked_at": None, "from_cache": False
        }):
            payload = _make_payload()
            result = ingest_alert(payload)

        assert result["status"] == "accepted"

        db = SessionLocal()
        try:
            row = db.query(app.models.Alert).first()
            assert row is not None
            assert row.description == "Test alert"
        finally:
            db.close()
    finally:
        settings.THREAT_INTEL_ENABLED = original
