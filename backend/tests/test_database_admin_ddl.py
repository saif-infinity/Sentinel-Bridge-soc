"""Regression tests for the admin database-browser DDL endpoints.

Two things were broken before:
  * `ALLOWED_TYPES` was declared but NEVER used — `col.type` and `col.default`
    were interpolated straight into `CREATE TABLE`, i.e. SQL injection from the
    admin console.
  * `PROTECTED_TABLES` was a hand-maintained list of 25 names while the ORM
    declares 46 tables, so 22 real tables were droppable over HTTP.

Run: cd backend && pytest tests/test_database_admin_ddl.py -q
"""
import pytest
from fastapi import HTTPException

from app.core.db import Base
from app.interface.api.database import (
    ALLOWED_TYPES,
    _protected_tables,
    _validate_column_type,
    _validate_default,
)


# ── column types ───────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("text", "TEXT"),
    ("TEXT", "TEXT"),
    ("  varchar(255) ", "VARCHAR(255)"),
    ("character varying(64)", "CHARACTER VARYING(64)"),
    ("numeric(10,2)", "NUMERIC(10, 2)"),
    ("timestamp with time zone", "TIMESTAMP WITH TIME ZONE"),
    ("double precision", "DOUBLE PRECISION"),
    ("jsonb", "JSONB"),
    ("uuid", "UUID"),
    ("boolean", "BOOLEAN"),
])
def test_accepts_and_normalises_allowed_types(raw, expected):
    assert _validate_column_type(raw) == expected


@pytest.mark.parametrize("raw", [
    "integer); DROP TABLE tenants; --",
    "text DEFAULT (SELECT password_hash FROM tenant_users LIMIT 1)",
    "varchar(255); DELETE FROM alerts",
    "integer PRIMARY KEY",          # constraints come from the dedicated fields
    "serial",                       # not in ALLOWED_TYPES
    "text(10)",                     # text takes no size modifier
    "pg_sleep(10)",
    "",
])
def test_rejects_injected_or_unlisted_types(raw):
    with pytest.raises(HTTPException) as exc:
        _validate_column_type(raw)
    assert exc.value.status_code == 400


# ── defaults ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw", ["now()", "CURRENT_TIMESTAMP", "gen_random_uuid()", "0", "-1.5", "'pending'", "true", "false"])
def test_accepts_safe_defaults(raw):
    assert _validate_default(raw)


@pytest.mark.parametrize("raw", [
    "(SELECT 1)",
    "now()); DROP TABLE tenants; --",
    "'a'; DROP TABLE tenants; --",
    "gen_random_uuid()::text",
    "current_user",
])
def test_rejects_expression_defaults(raw):
    with pytest.raises(HTTPException) as exc:
        _validate_default(raw)
    assert exc.value.status_code == 400


# ── protected tables can no longer drift ───────────────────────────────
def test_every_orm_table_is_protected_from_drop():
    declared = set(Base.metadata.tables.keys())
    assert declared, "ORM metadata is empty — models were not imported"
    protected = _protected_tables()
    missing = sorted(declared - protected)
    assert not missing, f"these application tables are droppable over HTTP: {missing}"


@pytest.mark.parametrize("table", [
    "tenants", "tenant_users", "alerts", "cases", "investigations",
    "response_runs", "registration_requests", "notification_channels",
    "honeypot_events", "agents",
])
def test_sensitive_tables_are_protected(table):
    assert table in _protected_tables()


def test_allowed_types_is_actually_enforced():
    # The set existed before but nothing consulted it; make sure that cannot regress.
    assert "text" in ALLOWED_TYPES
    with pytest.raises(HTTPException):
        _validate_column_type("definitely_not_a_pg_type")
