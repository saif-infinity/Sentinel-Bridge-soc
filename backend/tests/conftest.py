"""Pytest configuration — makes the suite importable and hermetic.

Why this file exists
--------------------
`app/core/config.py` declares 8 fields with NO default:

    JWT_SECRET_KEY, API_KEY, WAZUH_PASS, WAZUH_INDEXER_PASS,
    SURICATA_PASS, WAZUH_SSH_PASS, ADMIN_API_KEY, ADMIN_JWT_SECRET

`Settings` is instantiated at *import time* (`settings = Settings()`), so every one
of the 14 existing test modules fails at COLLECTION with a pydantic ValidationError
before a single test runs (verified: `pytest --collect-only tests/test_timescale.py`
on a clean checkout errors out). CI supplied only 4 of the 8 and there was no
conftest, so the `test-backend` job could never have passed.

Contract: values already present in the environment WIN (CI supplies a real
PostgreSQL/TimescaleDB DSN and a Redis URL). Everything else gets a throwaway
default so `pytest` works on a laptop with no `.env` file.
"""
import os

# Must happen before any `app.*` import — pytest loads conftest.py first.
_TEST_DEFAULTS = {
    # ── the 8 required secrets ────────────────────────────────────────────
    "JWT_SECRET_KEY": "test-only-jwt-secret-not-for-production-0000000000",
    "API_KEY": "test-only-api-key",
    "ADMIN_API_KEY": "test-only-admin-api-key",
    "ADMIN_JWT_SECRET": "test-only-admin-jwt-secret-0000000000000000000",
    "WAZUH_PASS": "test-only",
    "WAZUH_INDEXER_PASS": "test-only",
    "SURICATA_PASS": "test-only",
    "WAZUH_SSH_PASS": "test-only",
    # ── infrastructure the suite talks to (CI overrides both) ─────────────
    "DATABASE_URL": "postgresql+pg8000://postgres:test-password-ci-only@localhost:5432/postgres_test",
    "REDIS_URL": "redis://localhost:6379/0",
    # ── never let a test run believe it is in production ──────────────────
    "ENVIRONMENT": "test",
    # ── keep optional integrations OFF so tests do not hit the network ────
    "ENABLE_WAZUH_SOURCE": "False",
    "ENABLE_SURICATA_SOURCE": "False",
    "ENABLE_HOST_AGENT_SOURCE": "False",
    "THREAT_INTEL_ENABLED": "false",
    "REGISTRATION_REQUIRES_APPROVAL": "False",
    # No SUPER_ADMIN_PASSWORD: bootstrap.run_startup() must not seed an account
    # during tests (it logs a warning instead).
}

for _key, _value in _TEST_DEFAULTS.items():
    os.environ.setdefault(_key, _value)
