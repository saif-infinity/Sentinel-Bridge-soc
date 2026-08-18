"""Tests for TimescaleDB helpers (SQLite mode = no-ops)."""
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from app.db import Base
from app.domain.models import Alert, SuricataAlert
from app.infrastructure.timescale import ensure_timescaledb, _is_postgresql


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=eng)
    return eng


def test_is_postgresql_false_sqlite(engine):
    assert not _is_postgresql(engine)


def test_ensure_timescaledb_noop_sqlite(engine):
    """On SQLite, ensure_timescaledb should be a no-op (no crash)."""
    ensure_timescaledb(engine)
    # Verify tables still exist and are queryable
    with Session(engine) as db:
        db.execute(text("SELECT 1 FROM alerts LIMIT 0"))
        db.execute(text("SELECT 1 FROM suricata_alerts LIMIT 0"))


def test_alert_composite_pk_declaration():
    """Alert model should declare composite PK (id, timestamp)."""
    from sqlalchemy import inspect as sa_inspect
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    inspector = sa_inspect(engine)
    pk_cols = inspector.get_pk_constraint("alerts")["constrained_columns"]
    assert "id" in pk_cols
    assert "timestamp" in pk_cols
    assert "tenant_id" not in pk_cols


def test_suricata_alert_composite_pk_declaration():
    """SuricataAlert model should declare composite PK (id, timestamp)."""
    from sqlalchemy import inspect as sa_inspect
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    inspector = sa_inspect(engine)
    pk_cols = inspector.get_pk_constraint("suricata_alerts")["constrained_columns"]
    assert "id" in pk_cols
    assert "timestamp" in pk_cols
    assert "tenant_id" not in pk_cols


def test_alert_insert_without_id_works(engine):
    """Composite PK must still auto-generate id on insert (SQLite has no autoincrement for composite PKs)."""
    from datetime import datetime, timezone
    with Session(engine) as db:
        a = Alert(tenant_id="default", description="test", severity=5,
                  timestamp=datetime.now(timezone.utc))
        db.add(a)
        db.commit()
        db.refresh(a)
        assert a.id is not None
        assert isinstance(a.id, int)
        s = SuricataAlert(tenant_id="default", event_type="alert", alert_msg="test",
                          timestamp=datetime.now(timezone.utc))
        db.add(s)
        db.commit()
        db.refresh(s)
        assert s.id is not None
        assert isinstance(s.id, int)