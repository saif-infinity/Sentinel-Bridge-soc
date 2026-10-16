"""
R1 — Normalisation d'événements (schéma canonique ECS-like) — tests.

Vérifie que les 3 sources qui contournaient le pipeline (webhook Suricata,
webhook Wazuh, sync Wazuh indexer) passent désormais par ingest_alert() :
  (a) webhook Suricata → ligne SuricataAlert + pipeline_processed_at rempli
  (b) webhook Wazuh    → ligne Alert + pipeline_processed_at rempli
  (c) alert_sync       → ligne Alert + pipeline_processed_at + Device créé
  (d) ingestion générique POST /api/pipeline/ingest inchangée

Pattern (SQLite temp DB) :
  - DATABASE_URL surchargée AVANT tout import app.* (settings lit les env
    vars en priorité sur .env).
  - `import app.models` AVANT `Base.metadata.create_all(bind=engine)` pour
    enregistrer les modèles existants + domain.rule_models/pipeline_models.
  - TestClient SANS contexte (pas de startup => pas de background_scanner)
    + auth par X-API-Key.
"""
import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, Mock

import pytest

TEST_DB = os.path.join(tempfile.gettempdir(), "r1_normalization_test.db")
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402

import app.domain.pipeline_models  # noqa: E402, F401 — PipelineEvent
import app.domain.rule_models  # noqa: E402, F401 — Rule / RuleMatchOutbox / CorrelationState
import app.models  # noqa: E402, F401 — modèles existants AVANT create_all
from app.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.models import Alert, Device, SuricataAlert  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    """Si un autre module de test a déjà importé app avec Postgres, on skippe
    (l'override DATABASE_URL n'aurait plus d'effet)."""
    if "sqlite" not in str(engine.url):
        pytest.skip("R1 normalization tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture(scope="module", autouse=True)
def _ensure_tables():
    """create_all idempotent (une fois par module)."""
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(scope="module")
def client(_ensure_tables):
    c = TestClient(app)
    yield c
    c.close()


@pytest.fixture
def db(_ensure_tables):
    s = SessionLocal()
    yield s
    s.close()


# ── Mappers canoniques (unit) ─────────────────────────────────────────

def test_mappers_produce_canonical_keys():
    from app.application.normalization import (
        map_generic,
        map_suricata,
        map_wazuh,
        normalize_event,
        to_pipeline_payload,
    )

    sur = map_suricata({
        "timestamp": "2026-08-09T10:00:00Z",
        "event_type": "alert",
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "alert": {"signature": "sig", "severity": 1},
    })
    assert sur["@timestamp"] == "2026-08-09T10:00:00Z"
    assert sur["event.kind"] == "alert"
    assert sur["event.category"] == "alert"
    assert sur["event.type"] == "sig"
    assert sur["src_ip"] == "1.1.1.1"
    assert sur["dest_ip"] == "2.2.2.2"
    assert sur["severity"] == 1
    assert sur["payload"] == sur["payload"]

    waz = map_wazuh({
        "timestamp": "2026-08-09T10:00:00Z",
        "rule": {"id": "1001", "level": 9, "description": "wazuh sig"},
        "agent": {"id": "a1", "name": "pc", "ip": "10.0.0.1"},
    })
    assert waz["event.kind"] == "alert"
    assert waz["event.category"] == "1001"
    assert waz["event.type"] == "wazuh sig"
    assert waz["src_ip"] == "10.0.0.1"
    assert waz["agent_id"] == "a1"
    assert waz["severity"] == 9

    # Tolérance : payload inconnu / absent → jamais d'exception, clés None
    empty = map_generic({})
    assert empty["src_ip"] is None
    assert empty["description"] is None
    assert normalize_event("not-a-dict", "suricata") == {}
    assert normalize_event({}, "inconnu")["event.kind"] == "alert"

    # to_pipeline_payload : conversion canonique → payload ingest_alert
    payload = to_pipeline_payload(sur, source="suricata")
    assert payload["source"] == "suricata"
    assert payload["signature"] == "sig"
    assert payload["category"] == "alert"
    assert payload["raw"] is sur["payload"]


# ── (a) Webhook Suricata → pipeline ──────────────────────────────────

def test_suricata_webhook_goes_through_pipeline(client, db):
    r = client.post("/api/suricata/webhook", headers=HEADERS, json={
        "timestamp": "2026-08-09T10:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "203.0.113.5",
        "dest_ip": "198.51.100.7",
        "proto": "TCP",
        "alert": {"signature": "ET SURV Suspicious Download", "severity": 1},
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "success"
    assert r.json()["alerts_processed"] == 1

    row = db.query(SuricataAlert).filter(SuricataAlert.src_ip == "203.0.113.5").first()
    assert row is not None
    assert row.event_type == "alert"
    assert row.alert_msg == "ET SURV Suspicious Download"
    assert row.pipeline_source == "suricata"
    assert row.pipeline_processed_at is not None
    assert row.normalized_severity == 15  # suricata severity 1 → 15


# ── (b) Webhook Wazuh → pipeline ─────────────────────────────────────

def test_wazuh_webhook_goes_through_pipeline(client, db):
    r = client.post("/api/wazuh/webhook", headers=HEADERS, json={
        "timestamp": "2026-08-09T11:00:00.000Z",
        "rule": {"id": "1002", "level": 12, "description": "Wazuh webhook test alert"},
        "agent": {"id": "agent-1", "ip": "10.0.0.41"},
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "accepted"

    row = db.query(Alert).filter(Alert.description == "Wazuh webhook test alert").first()
    assert row is not None
    assert row.pipeline_source == "wazuh"
    assert row.pipeline_processed_at is not None
    assert row.src_ip == "10.0.0.41"
    assert row.agent_id == "agent-1"


# ── (c) Wazuh alert_sync → pipeline + Device ─────────────────────────

def test_alert_sync_goes_through_pipeline_and_creates_device(db):
    from app.application.wazuh.alert_sync import WazuhAlertSync

    sync = WazuhAlertSync()
    sync._cache_lock = asyncio.Lock()
    sync._agent_ip_cache = {}
    sync._indexer_auth_failure_count = 0
    sync._indexer_available = True
    sync.indexer_url = "https://fake-indexer:9200"

    resp = Mock()
    resp.status_code = 200
    resp.json.return_value = {
        "hits": {"hits": [{"_source": {
            "timestamp": "2026-08-09T12:00:00.000Z",
            "rule": {"id": "1003", "level": 7, "description": "Wazuh sync test alert"},
            "agent": {"id": "042", "name": "pc-alice"},
            "full_log": "test log",
        }}]}
    }
    sync._get_indexer_auth = AsyncMock(return_value="fake-b64")
    sync._rate_limited_request = AsyncMock(return_value=resp)
    sync.get_agent_real_identity = AsyncMock(return_value={
        "ip": "10.0.0.42", "mac": "aa:bb:cc:dd:ee:ff", "user": "alice",
    })

    asyncio.run(sync.sync_alerts(SessionLocal, tenant_id="default"))

    alert = db.query(Alert).filter(Alert.description == "Wazuh sync test alert").first()
    assert alert is not None
    assert alert.pipeline_source == "wazuh"
    assert alert.pipeline_processed_at is not None
    assert alert.src_ip == "10.0.0.42"
    assert alert.agent_id == "042"

    device = db.query(Device).filter(Device.ip == "10.0.0.42").first()
    assert device is not None
    assert device.is_wazuh_agent is True


# ── (d) Ingestion générique /api/pipeline/ingest inchangée ───────────

def test_generic_pipeline_ingest_unchanged(client, db):
    r = client.post("/api/pipeline/ingest", headers=HEADERS, json={
        "source": "manual",
        "severity": 7,
        "signature": "manual test signature",
        "description": "manual test description",
        "src_ip": "10.9.9.9",
    })
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "accepted"
    assert data["normalized_severity"] == 7

    row = db.query(Alert).filter(Alert.description == "manual test description").first()
    assert row is not None
    assert row.pipeline_source == "manual"
    assert row.pipeline_processed_at is not None
