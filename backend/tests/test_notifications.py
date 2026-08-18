"""
R3 — Notifications — tests.

Run with: python -m pytest tests/test_notifications.py -q

Pattern (SQLite temp DB) :
  - DATABASE_URL surchargée AVANT tout import app.* (settings lit les env vars
    en priorité sur .env).
  - `import app.models` AVANT `Base.metadata.create_all(bind=engine)` pour
    enregistrer les modèles existants + NotificationChannel/NotificationDedup.
"""
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

TEST_DB = os.path.join(tempfile.gettempdir(), "r3_notifications_test.db")
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

from app.core.db import Base, engine, SessionLocal  # noqa: E402
import app.models  # noqa: E402, F401 — modèles existants AVANT create_all
from app.domain.models import NotificationChannel, NotificationDedup  # noqa: E402
from app.infrastructure.notifications.crypto import (  # noqa: E402
    decrypt_config,
    encrypt_config,
    mask_config,
)
from app.infrastructure.notifications.dedup import (  # noqa: E402
    compute_fingerprint,
    is_duplicate,
    prune_dedup,
)
from app.infrastructure.notifications.rate_limit import is_rate_limited  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _require_sqlite():
    """Si un autre module de test a déjà importé app avec Postgres, on skippe."""
    if "sqlite" not in str(engine.url):
        pytest.skip("R3 tests require SQLite DATABASE_URL (run this module alone)")


@pytest.fixture(scope="module", autouse=True)
def _ensure_tables():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db(_ensure_tables):
    s = SessionLocal()
    yield s
    s.close()


# ── Fingerprint ───────────────────────────────────────────────────────

def test_fingerprint_deterministic_and_normalized():
    a = compute_fingerprint("TENANT", "8.8.8.8", "1.1.1.1", "ET SCAN", 42)
    b = compute_fingerprint("tenant", "8.8.8.8", "1.1.1.1", "et scan", 42)
    c = compute_fingerprint("tenant", "8.8.8.8", "1.1.1.1", "et scan", 43)
    assert a == b                      # déterministe + normalisé (case/strip)
    assert a != c                      # rule_id différent => empreinte différente
    assert len(a) == 64                # sha256 hex
    # None -> "" normalisé
    d = compute_fingerprint("t", None, None, None, None)
    e = compute_fingerprint("t", "", "", "", "")
    assert d == e


# ── Déduplication ─────────────────────────────────────────────────────

def test_is_duplicate_first_insert_then_duplicate(db):
    fp = compute_fingerprint("default", "8.8.8.8", "1.1.1.1", "sig", 1)
    assert is_duplicate(db, "default", fp, 1, window_seconds=300) is False
    assert is_duplicate(db, "default", fp, 1, window_seconds=300) is True
    # Canal différent => pas un doublon
    assert is_duplicate(db, "default", fp, 2, window_seconds=300) is False
    # window_seconds <= 0 => déduplication désactivée
    assert is_duplicate(db, "default", fp, 1, window_seconds=0) is False


def test_is_duplicate_expired_window_allows_again(db):
    fp = compute_fingerprint("default", "9.9.9.9", "1.1.1.1", "sig", 1)
    assert is_duplicate(db, "default", fp, 1, window_seconds=300) is False
    # Vieillit l'entrée au-delà de la fenêtre
    row = db.query(NotificationDedup).filter(
        NotificationDedup.fingerprint == fp,
        NotificationDedup.channel_id == 1,
    ).first()
    row.first_seen = datetime.now(timezone.utc) - timedelta(seconds=600)
    db.commit()
    # La purge opportuniste supprime l'entrée expirée => insertion OK
    assert is_duplicate(db, "default", fp, 1, window_seconds=300) is False


def test_prune_dedup(db):
    old = NotificationDedup(
        tenant_id="default", fingerprint="old-fp", channel_id=1,
        first_seen=datetime.now(timezone.utc) - timedelta(hours=48),
    )
    fresh = NotificationDedup(
        tenant_id="default", fingerprint="fresh-fp", channel_id=1,
        first_seen=datetime.now(timezone.utc),
    )
    db.add_all([old, fresh])
    db.commit()
    pruned = prune_dedup(db, max_age_hours=24)
    assert pruned >= 1
    assert db.query(NotificationDedup).filter(
        NotificationDedup.fingerprint == "old-fp").count() == 0
    assert db.query(NotificationDedup).filter(
        NotificationDedup.fingerprint == "fresh-fp").count() == 1


# ── Rate limit (Redis mocké) ──────────────────────────────────────────

def test_rate_limit_mock_redis():
    r = MagicMock()
    r.incr.return_value = 1
    assert is_rate_limited(r, 7, limit_per_minute=10) is False
    r.incr.return_value = 10
    assert is_rate_limited(r, 7, limit_per_minute=10) is False
    r.incr.return_value = 11
    assert is_rate_limited(r, 7, limit_per_minute=10) is True
    # limit <= 0 => jamais limité (aucun appel Redis)
    assert is_rate_limited(r, 7, limit_per_minute=0) is False
    r.incr.assert_called()  # les appels précédents ont bien INCR


def test_rate_limit_fail_open_on_redis_error():
    import redis
    r = MagicMock()
    r.incr.side_effect = redis.ConnectionError("down")
    assert is_rate_limited(r, 7, limit_per_minute=10) is False


# ── Crypto / masquage ─────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    cfg = {"host": "smtp.example.com", "password_secret": "hunter2"}
    blob = encrypt_config(cfg)
    assert blob != json.dumps(cfg)          # bien chiffré
    assert decrypt_config(blob) == cfg      # round-trip


def test_mask_config():
    cfg = {"host": "smtp.example.com", "password_secret": "hunter2",
           "username": "soc", "token_secret": "abc123"}
    masked = mask_config(cfg)
    assert masked["password_secret"] == "***"
    assert masked["token_secret"] == "***"
    assert masked["host"] == "smtp.example.com"
    assert masked["username"] == "soc"
    # valeurs vides non masquées
    assert mask_config({"password_secret": ""})["password_secret"] == ""


# ── Modèles ───────────────────────────────────────────────────────────

def test_notification_models_registered():
    cols = set(NotificationChannel.__table__.columns.keys())
    assert {"id", "tenant_id", "name", "channel_type", "config", "enabled",
            "rate_limit_per_minute", "dedup_window_seconds"} <= cols
    dcols = set(NotificationDedup.__table__.columns.keys())
    assert {"fingerprint", "channel_id", "first_seen"} <= dcols