"""
R2 (MITRE ATT&CK) + R13 (corrélation avancée) — tests du moteur de règles.

Pattern (SQLite temp DB) :
  - DATABASE_URL surchargée AVANT tout import app.* (settings lit les env vars
    en priorité sur .env).
  - `import app.models` AVANT `Base.metadata.create_all(bind=engine)` pour
    enregistrer les modèles existants + domain.rule_models (Rule, RuleMatchOutbox,
    CorrelationState).
  - TestClient SANS contexte (pas de startup => pas de background_scanner) +
    X-API-Key.
  - event_bus.subscribe manuel pour capturer les RuleMatchEvent.
"""
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

TEST_DB = os.path.join(tempfile.gettempdir(), "r2_r13_mitre_correlation_test.db")
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402

from app.core.db import Base, engine, SessionLocal  # noqa: E402
import app.models  # noqa: E402, F401 — modèles existants AVANT create_all
import app.domain.rule_models  # noqa: E402, F401 — Rule / RuleMatchOutbox / CorrelationState
from app.config import settings  # noqa: E402
from app.interface.main import app  # noqa: E402
from app.application.events import CHANNEL_RULE_MATCH, event_bus  # noqa: E402
from app.application.rules.evaluator import (  # noqa: E402
    NORMALIZED_KEYS,
    build_normalized_alert,
    mitre_tactics_for,
)
from app.application.rules.engine import evaluate_normalized_alert, invalidate_rules_cache  # noqa: E402
from app.application.rules.correlator import WindowedCorrelator  # noqa: E402
from app.domain.rule_models import Rule, RuleMatchOutbox, CorrelationState  # noqa: E402
from app.models import Tenant  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    """Si un autre module de test a déjà importé app avec Postgres, on skippe."""
    if "sqlite" not in str(engine.url):
        pytest.skip("R2/R13 tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture(scope="module", autouse=True)
def _ensure_tables():
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


@pytest.fixture(autouse=True)
def _fresh_rules_cache():
    invalidate_rules_cache()
    yield


@pytest.fixture(autouse=True)
def _clean_state(_ensure_tables):
    """Chaque test part d'une table rules/correlation_state/outbox vide."""
    s = SessionLocal()
    try:
        s.query(CorrelationState).delete()
        s.query(RuleMatchOutbox).delete()
        s.query(Rule).delete()
        s.commit()
    finally:
        s.close()
    invalidate_rules_cache()
    yield


def _mk_rule(db, name, conditions, correlation="{}", mitre_ids=None, tactics=None,
             enabled=True, tenant_id=None):
    rule = Rule(
        tenant_id=tenant_id,
        name=name,
        description="",
        enabled=enabled,
        severity=5,
        tags="[]",
        conditions=json.dumps(conditions),
        correlation=correlation,
        action_flags="{}",
        mitre_attack_ids=json.dumps(mitre_ids or []),
        tactics=json.dumps(tactics or []),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


# ── R2 — propagation MITRE dans l'alerte normalisée ───────────────────

def test_normalized_alert_mitre_keys():
    """build_normalized_alert propage mitre_attack_ids/tactics (None si absents),
    sans casser les 14 clés canoniques existantes."""
    normalized = build_normalized_alert({
        "tenant_id": "default", "category": "malware",
        "mitre_attack_ids": ["T1059.001"], "tactics": ["execution"],
    })
    assert normalized["mitre_attack_ids"] == ["T1059.001"]
    assert normalized["tactics"] == ["execution"]

    plain = build_normalized_alert({"tenant_id": "default"})
    assert plain["mitre_attack_ids"] is None
    assert plain["tactics"] is None
    for k in ("alert_id", "tenant_id", "timestamp", "source", "severity",
              "normalized_severity", "signature", "category", "description",
              "src_ip", "dest_ip", "agent_id", "proto", "raw"):
        assert k in plain
    assert "mitre_attack_ids" in NORMALIZED_KEYS
    assert "tactics" in NORMALIZED_KEYS


def test_mitre_tactics_derived_from_ids():
    assert mitre_tactics_for(["T1059.001"]) == ["execution"]
    assert "defense-evasion" in mitre_tactics_for(["T1078"])
    assert mitre_tactics_for([]) == []


def test_rule_mitre_fields_in_event_and_outbox(db):
    """(a) Règle avec mitre_attack_ids -> alerte normalisée + payload contiennent les IDs."""
    _mk_rule(
        db, "mitre-rule",
        conditions=[{"field": "category", "op": "eq", "value": "malware"}],
        mitre_ids=["T1059.001", "T1078"],
        tactics=["execution", "defense-evasion"],
    )
    captured = []

    def handler(channel, event):
        captured.append(event)

    event_bus.subscribe(CHANNEL_RULE_MATCH, handler)
    try:
        matched, n = evaluate_normalized_alert(
            build_normalized_alert({"tenant_id": "default", "category": "malware"}))
        assert n == 1
        assert matched[0]["mitre_attack_ids"] == ["T1059.001", "T1078"]
        assert matched[0]["tactics"] == ["execution", "defense-evasion"]

        assert len(captured) == 1
        ev = captured[0]
        assert ev.normalized_alert["mitre_attack_ids"] == ["T1059.001", "T1078"]
        assert ev.normalized_alert["tactics"] == ["execution", "defense-evasion"]

        # payload durable (outbox) contient aussi les IDs
        outbox = db.query(RuleMatchOutbox).order_by(RuleMatchOutbox.id.desc()).first()
        payload = json.loads(outbox.payload)
        assert payload["normalized_alert"]["mitre_attack_ids"] == ["T1059.001", "T1078"]
        assert payload["matched_rules"][0]["mitre_attack_ids"] == ["T1059.001", "T1078"]
    finally:
        event_bus.unsubscribe(CHANNEL_RULE_MATCH, handler)


# ── R2) GET /api/rules/coverage ──────────────────────────────────────

def test_coverage_contract(client, db):
    """(b) /api/rules/coverage retourne la structure exacte du contrat."""
    # 3 règles ENABLED avec la tactique "execution" : 2 avec T1059, 1 avec T1204
    for name, cond, ids in (
        ("cov-1", "a", ["T1059.001"]),
        ("cov-2", "b", ["T1059"]),
        ("cov-3", "c", ["T1204"]),
    ):
        r = client.post("/api/rules", headers=HEADERS, json={
            "name": name,
            "enabled": True,
            "severity": 5,
            "conditions": [{"field": "category", "op": "eq", "value": cond}],
            "mitre_attack_ids": ids,
            "tactics": ["execution"],
        })
        assert r.status_code == 201, r.text
        assert r.json()["mitre_attack_ids"] == ids  # persistance CRUD

    # règle disabled : ne doit PAS compter
    _mk_rule(db, "cov-disabled", conditions=[{"field": "category", "op": "eq", "value": "d"}],
             mitre_ids=["T1059"], tactics=["execution"], enabled=False)

    r = client.get("/api/rules/coverage", headers=HEADERS)
    assert r.status_code == 200, r.text
    data = r.json()
    assert set(data.keys()) == {"tactics"}
    exec_t = data["tactics"]["execution"]
    assert set(exec_t.keys()) == {"total_rules", "techniques"}
    assert exec_t["total_rules"] == 3
    assert exec_t["techniques"]["T1059"]["name"] == "Command and Scripting Interpreter"
    assert exec_t["techniques"]["T1059"]["rule_count"] == 2
    assert exec_t["techniques"]["T1204"]["name"] == "User Execution"
    assert exec_t["techniques"]["T1204"]["rule_count"] == 1


def test_coverage_tenant_scoping(client, db):
    """Le coverage respecte le scoping tenant (globales + tenant courant)."""
    db.add(Tenant(id="tenant-a", company_name="Tenant A", email="a@example.com",
                  plan="trial", status="active"))
    db.commit()
    _mk_rule(db, "global-exec", conditions=[{"field": "category", "op": "eq", "value": "g"}],
             mitre_ids=["T1059"], tactics=["execution"])
    _mk_rule(db, "tenant-a-defev", conditions=[{"field": "category", "op": "eq", "value": "t"}],
             mitre_ids=["T1078"], tactics=["defense-evasion"], tenant_id="tenant-a")

    # tenant "default" (X-API-Key sans X-Tenant-ID) : voit la globale, pas tenant-a
    r = client.get("/api/rules/coverage", headers=HEADERS)
    data = r.json()
    assert data["tactics"]["execution"]["total_rules"] == 1
    assert "defense-evasion" not in data["tactics"]

    # tenant-a : voit sa règle + la globale
    r2 = client.get("/api/rules/coverage", headers={**HEADERS, "X-Tenant-ID": "tenant-a"})
    assert r2.status_code == 200, r2.text
    data2 = r2.json()
    assert data2["tactics"]["defense-evasion"]["total_rules"] == 1
    assert data2["tactics"]["execution"]["total_rules"] == 1


# ── R13) Corrélation séquence persistante ────────────────────────────

def test_sequence_correlation_persists_across_restart(db):
    """(c) La séquence survit à travers deux évaluations (même DB, nouvelle instance)."""
    rule = _mk_rule(
        db, "seq-persist",
        conditions=[{"field": "signature", "op": "eq", "value": "stage-A"},
                    {"field": "signature", "op": "eq", "value": "stage-B"}],
        correlation=json.dumps({"window_seconds": 300, "sequence": [0, 1]}),
        mitre_ids=["T1059"], tactics=["execution"],
    )
    conditions = json.loads(rule.conditions)
    base = datetime.now(timezone.utc) - timedelta(seconds=10)

    ev_a = build_normalized_alert({
        "tenant_id": "default", "signature": "stage-A",
        "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
        "timestamp": (base + timedelta(seconds=1)).isoformat(),
    })
    corr1 = WindowedCorrelator()
    assert corr1.evaluate(rule, ev_a, conditions) is False

    # "restart" : nouvelle instance du corrélateur, même DB
    corr2 = WindowedCorrelator()
    ev_b = build_normalized_alert({
        "tenant_id": "default", "signature": "stage-B",
        "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
        "timestamp": (base + timedelta(seconds=2)).isoformat(),
    })
    assert corr2.evaluate(rule, ev_b, conditions) is True

    # anti re-fire persistant dans la même fenêtre
    ev_c = build_normalized_alert({
        "tenant_id": "default", "signature": "stage-B",
        "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
        "timestamp": (base + timedelta(seconds=3)).isoformat(),
    })
    assert corr2.evaluate(rule, ev_c, conditions) is False

    # l'état est bien en DB
    assert db.query(CorrelationState).filter(CorrelationState.rule_id == rule.id).count() >= 3


# ── R13) corrélation par agrégat (count) ─────────────────────────────

def test_count_correlation_threshold(db):
    """(d) L'agrégat count déclenche après le seuil et pas avant."""
    rule = _mk_rule(
        db, "count-rule",
        conditions=[{"field": "category", "op": "eq", "value": "brute-force"}],
        correlation=json.dumps({"count": 3, "window_seconds": 60}),
        mitre_ids=["T1110"], tactics=["credential-access"],
    )
    conditions = json.loads(rule.conditions)
    corr = WindowedCorrelator()

    for _ in range(2):
        ev = build_normalized_alert({"tenant_id": "default", "category": "brute-force"})
        assert corr.evaluate(rule, ev, conditions) is False

    ev = build_normalized_alert({"tenant_id": "default", "category": "brute-force"})
    assert corr.evaluate(rule, ev, conditions) is True

    # un événement non conforme ne compte pas
    ev_other = build_normalized_alert({"tenant_id": "default", "category": "other"})
    assert corr.evaluate(rule, ev_other, conditions) is False


def test_count_correlation_via_engine(db):
    """(d) Wiring moteur : une règle count passe par le corrélateur et déclenche au seuil."""
    _mk_rule(
        db, "count-engine",
        conditions=[{"field": "category", "op": "eq", "value": "scan"}],
        correlation=json.dumps({"count": 2, "window_seconds": 60}),
    )
    matched, n = evaluate_normalized_alert(
        build_normalized_alert({"tenant_id": "default", "category": "scan"}))
    assert n == 0

    matched, n = evaluate_normalized_alert(
        build_normalized_alert({"tenant_id": "default", "category": "scan"}))
    assert n == 1
    assert matched[0]["correlation"] is True