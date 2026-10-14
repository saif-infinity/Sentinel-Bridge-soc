"""
F3 — Mini-SOAR (playbooks) + Threat Intelligence — tests PASS 2a.

Run with: python -m pytest tests/test_soar_intel.py -q

Fixture pattern (SQLite temp DB) :
  - DATABASE_URL est surchargée AVANT tout import app.* (settings lit les env
    vars en priorité sur .env).
  - `import app.models` AVANT `Base.metadata.create_all(bind=engine)` pour
    enregistrer les modèles existants + domain.soar/intel/rule_models.
  - TestClient SANS contexte (pas de startup => pas de background_scanner qui
    fait de vrais scans réseau) + X-API-Key.
  - Le handler on_rule_match est abonné manuellement au bus (même câblage que
    bootstrap.py, mais sans les tâches asyncio de fond).
"""
import json
import os
import tempfile
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

TEST_DB = os.path.join(tempfile.gettempdir(), "f3_soar_intel_test.db")
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import inspect as sa_inspect  # noqa: E402

import app.domain.intel  # noqa: E402, F401 — ThreatIntelCache
import app.domain.rule_models  # noqa: E402, F401 — RuleMatchOutbox (F1)
import app.domain.soar  # noqa: E402, F401 — Playbook / PlaybookRun
import app.models  # noqa: E402, F401 — modèles existants AVANT create_all
from app.application.events import (  # noqa: E402
    CHANNEL_RULE_MATCH,
    event_bus,
    make_rule_match_event,
)
from app.application.soar.executor import on_rule_match  # noqa: E402
from app.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.domain.rule_models import RuleMatchOutbox  # noqa: E402
from app.domain.soar import Playbook, PlaybookRun  # noqa: E402
from app.infrastructure.jobs.intel_tasks import enrich_alerts_intel  # noqa: E402
from app.infrastructure.threat_intel.client import ensure_intel_columns  # noqa: E402
from app.interface.main import app  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    """Si un autre module de test a déjà importé app avec Postgres, on skippe
    (l'override DATABASE_URL n'aurait plus d'effet)."""
    if "sqlite" not in str(engine.url):
        pytest.skip("F3 tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture(scope="module", autouse=True)
def _wire_bus(_require_sqlite):
    """Même câblage que bootstrap.py, sans le startup complet (pas de scan
    réseau en arrière-plan)."""
    event_bus.subscribe(CHANNEL_RULE_MATCH, on_rule_match)
    yield


@pytest.fixture(scope="module", autouse=True)
def _ensure_tables():
    """create_all idempotent (une fois par module) — indépendant du client :
    les tests de dispatch/intel n'utilisant pas le client en ont besoin."""
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


# ── Routage (wire-in main.py) ─────────────────────────────────────────

def test_f3_routers_registered():
    from fastapi.routing import _IncludedRouter

    prefixes = [
        getattr(getattr(r, "original_router", None), "prefix", None)
        for r in app.routes
        if isinstance(r, _IncludedRouter)
    ]
    assert "/api/playbooks" in prefixes
    assert "/api/intel" in prefixes
    # Delta attendu : +2 _IncludedRouter vs la baseline (F1+F2).
    assert len(prefixes) >= 25


# ── CRUD playbooks (API) ──────────────────────────────────────────────

def test_playbook_crud_via_api(client):
    r = client.post("/api/playbooks", headers=HEADERS, json={
        "name": "Block scanner",
        "description": "log + block",
        "trigger_rule_ids": ["R100"],
        "trigger_min_severity": 8,
        "trigger_sources": ["pipeline"],
        "requires_approval": False,
        "enabled": True,
        "steps": [{"type": "log", "params": {"message": "block {{src_ip}}"}, "timeout_seconds": 5}],
    })
    assert r.status_code == 200, r.text
    pb = r.json()
    assert pb["name"] == "Block scanner"
    assert pb["steps"][0]["type"] == "log"
    pid = pb["id"]

    # Nom dupliqué -> 409
    r2 = client.post("/api/playbooks", headers=HEADERS, json={"name": "Block scanner", "steps": []})
    assert r2.status_code == 409

    # Liste
    r3 = client.get("/api/playbooks", headers=HEADERS)
    assert r3.status_code == 200
    assert "Block scanner" in [p["name"] for p in r3.json()]

    # Update
    r4 = client.patch(f"/api/playbooks/{pid}", headers=HEADERS, json={
        "name": "Block scanner v2", "requires_approval": True, "enabled": False, "steps": [],
    })
    assert r4.status_code == 200, r4.text
    assert r4.json()["name"] == "Block scanner v2"
    assert r4.json()["enabled"] is False

    # Toggle
    r5 = client.post(f"/api/playbooks/{pid}/toggle", headers=HEADERS)
    assert r5.status_code == 200
    assert r5.json()["enabled"] is True

    # Runs / steps endpoints (vides) -> 200
    assert client.get("/api/playbooks/runs", headers=HEADERS).status_code == 200

    # Delete
    r7 = client.delete(f"/api/playbooks/{pid}", headers=HEADERS)
    assert r7.status_code == 200
    assert r7.json()["deleted"] == pid

    # Après delete -> 404
    r8 = client.patch(f"/api/playbooks/{pid}", headers=HEADERS, json={"name": "x", "steps": []})
    assert r8.status_code == 404


def test_playbook_requires_auth(client):
    # Sans X-API-Key ni JWT -> 401 (F4 RBAC require_role) ou 403 (legacy)
    r = client.get("/api/playbooks")
    assert r.status_code in (401, 403)
    r2 = client.post("/api/playbooks/runs/1/approve")
    assert r2.status_code in (401, 403)


# ── Workflow d'approbation ────────────────────────────────────────────

def test_approve_workflow(client, db):
    r = client.post("/api/playbooks", headers=HEADERS, json={
        "name": "Approve me",
        "requires_approval": True,
        "enabled": True,
        "steps": [],
    })
    assert r.status_code == 200, r.text
    pb = r.json()

    run = PlaybookRun(
        playbook_id=pb["id"], event_id="evt-approve", tenant_id="default",
        status="pending_approval", event_payload={"src_ip": "9.9.9.9"},
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    r2 = client.post(f"/api/playbooks/runs/{run.id}/approve", headers=HEADERS)
    assert r2.status_code == 200, r2.text
    assert r2.json()["status"] == "approved"

    db.refresh(run)
    assert run.status != "pending_approval"

    # Approbation d'un run non-en-attente -> 409
    r3 = client.post(f"/api/playbooks/runs/{run.id}/approve", headers=HEADERS)
    assert r3.status_code == 409

    # Cancel
    run2 = PlaybookRun(
        playbook_id=pb["id"], event_id="evt-cancel", tenant_id="default",
        status="pending_approval", event_payload={},
    )
    db.add(run2)
    db.commit()
    db.refresh(run2)
    r4 = client.post(f"/api/playbooks/runs/{run2.id}/cancel", headers=HEADERS)
    assert r4.status_code == 200
    assert r4.json()["status"] == "cancelled"

    # Run introuvable -> 404
    r5 = client.post("/api/playbooks/runs/999999/approve", headers=HEADERS)
    assert r5.status_code == 404


# ── Dispatch : outbox F1 -> bus -> PlaybookRun (idempotent) ────────────

def test_dispatch_creates_run_and_replay_noop(db):
    pb = Playbook(
        tenant_id="default", name="dispatch-pb", description=None,
        trigger_rule_ids=[], trigger_min_severity=None, trigger_sources=[],
        requires_approval=True, enabled=True, steps=[],
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)

    event = make_rule_match_event(
        tenant_id="default",
        normalized_alert={"src_ip": "8.8.8.8", "message": "port scan"},
        matched_rules=[{"rule_id": "R900", "rule_name": "Scan", "rule_severity": 9}],
    )

    # Insertion durable de l'outbox (F1) — moitié persistante du contrat
    db.add(RuleMatchOutbox(
        event_id=event.event_id, tenant_id="default", channel=CHANNEL_RULE_MATCH,
        payload=json.dumps({}), status="pending",
    ))
    db.commit()

    # Publication sur le bus (channel F1) -> on_rule_match -> PlaybookRun.
    # NB : d'autres playbooks (sans filtres) peuvent matcher aussi — on vérifie
    # notre playbook précis.
    event_bus.publish_sync(CHANNEL_RULE_MATCH, event)

    runs = db.query(PlaybookRun).filter(PlaybookRun.event_id == event.event_id).all()
    assert len(runs) >= 1
    mine = [r for r in runs if r.playbook_id == pb.id]
    assert len(mine) == 1
    run = mine[0]
    assert run.tenant_id == "default"
    assert run.status == "pending_approval"   # requires_approval=True
    assert run.triggered_by == "R900"

    # Re-publication du même événement = no-op (garde AVANT insert +
    # UNIQUE(event_id, playbook_id)) — même nombre de runs, aucun nouveau.
    before = {r.playbook_id for r in runs}
    event_bus.publish_sync(CHANNEL_RULE_MATCH, event)
    runs2 = db.query(PlaybookRun).filter(PlaybookRun.event_id == event.event_id).all()
    assert {r.playbook_id for r in runs2} == before
    assert len(runs2) == len(runs)

    # Un événement inconnu (channel différent) est ignoré
    event_bus.publish_sync("autre.channel", event)
    runs3 = db.query(PlaybookRun).filter(PlaybookRun.event_id == event.event_id).all()
    assert len(runs3) == len(runs)


def test_dispatch_honors_trigger_filters(db):
    pb = Playbook(
        tenant_id="default", name="filtered-pb", description=None,
        trigger_rule_ids=["R-ONLY"], trigger_min_severity=12, trigger_sources=["pipeline"],
        requires_approval=True, enabled=True, steps=[],
    )
    db.add(pb)
    db.commit()
    db.refresh(pb)

    # Événement hors filtres (mauvaise règle + mauvaise sévérité) -> pas de run
    # pour NOTRE playbook filtré.
    ev_no = make_rule_match_event(
        tenant_id="default",
        normalized_alert={"src_ip": "1.1.1.1"},
        matched_rules=[{"rule_id": "OTHER", "rule_severity": 3}],
    )
    event_bus.publish_sync(CHANNEL_RULE_MATCH, ev_no)
    no_runs = db.query(PlaybookRun).filter(
        PlaybookRun.event_id == ev_no.event_id, PlaybookRun.playbook_id == pb.id
    ).count()
    assert no_runs == 0

    # Événement conforme (bonne règle + bonne sévérité) -> exactement 1 run
    # pour notre playbook.
    ev_yes = make_rule_match_event(
        tenant_id="default",
        normalized_alert={"src_ip": "2.2.2.2"},
        matched_rules=[{"rule_id": "R-ONLY", "rule_severity": 14}],
    )
    event_bus.publish_sync(CHANNEL_RULE_MATCH, ev_yes)
    yes_runs = db.query(PlaybookRun).filter(
        PlaybookRun.event_id == ev_yes.event_id, PlaybookRun.playbook_id == pb.id
    ).count()
    assert yes_runs == 1


# ── Threat intel ──────────────────────────────────────────────────────

def test_intel_enrich_skipped_when_disabled(monkeypatch):
    """THREAT_INTEL_ENABLED=False -> skipped, ZERO appel réseau."""
    monkeypatch.setattr(settings, "THREAT_INTEL_ENABLED", False)
    with patch("app.infrastructure.threat_intel.client.fetch_abuseipdb") as mock_fetch:
        result = enrich_alerts_intel()
    assert result["status"] == "skipped"
    assert result["reason"] == "THREAT_INTEL_ENABLED=false"
    mock_fetch.assert_not_called()


def test_lookup_ip_returns_unknown_without_network(db):
    """Clé API vide / intel désactivé -> 'unknown' sans aucun appel HTTP."""
    assert not settings.THREAT_INTEL_API_KEY.get_secret_value()
    with patch("app.infrastructure.threat_intel.client.fetch_abuseipdb") as mock_fetch:
        info = lookup(db, "default", "8.8.8.8")
    assert info["verdict"] == "unknown"
    mock_fetch.assert_not_called()


def lookup(db, tenant_id, ip):
    from app.infrastructure.threat_intel.client import lookup_ip
    return lookup_ip(db, tenant_id, ip)


def test_ensure_intel_columns_idempotent(db):
    first = ensure_intel_columns(db)
    second = ensure_intel_columns(db)
    assert second == 0  # déjà présentes (create_all + idempotence)
    insp = sa_inspect(engine)
    for table in ("alerts", "suricata_alerts"):
        cols = {c["name"] for c in insp.get_columns(table)}
        assert {"intel_score", "intel_verdict", "intel_source", "intel_checked_at"} <= cols


def test_intel_models_registered():
    """Les colonnes intel_* sont définies dans les modèles (create_all)."""
    from app.models import Alert, SuricataAlert

    for model in (Alert, SuricataAlert):
        cols = set(model.__table__.columns.keys())
        assert {"intel_score", "intel_verdict", "intel_source", "intel_checked_at"} <= cols


def test_intel_columns_nullable_for_old_rows(db):
    """Les lignes non-enrichies restent NULL — le badge front rend l'état neutre."""
    from app.models import Alert

    a = Alert(
        tenant_id="default", description="old alert", severity=5,
        src_ip="3.3.3.3", timestamp=datetime.now(UTC),
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    assert a.intel_verdict is None
    assert a.intel_score is None
    assert a.intel_checked_at is None
