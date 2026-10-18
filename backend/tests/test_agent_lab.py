"""Tests lab agent — enroll, revoke, heartbeat, telemetry ack, TI private IP guard.
Reproductible, non-destructif, sans réseau externe.
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
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(tempfile.gettempdir(), 'sentinel_agent_lab_test.db')}"

from fastapi.testclient import TestClient  # noqa: E402

import app.domain.pipeline_models  # noqa: F401
import app.domain.rule_models  # noqa: F401
import app.models  # noqa: F401
from app.core.config import settings  # noqa: E402
from app.core.db import Base, SessionLocal, engine  # noqa: E402
from app.interface.main import app  # noqa: E402

API_KEY = settings.API_KEY.get_secret_value()
HEADERS = {"X-API-Key": API_KEY, "X-Tenant-ID": "default"}

# Ensure sqlite
if "sqlite" not in str(engine.url):
    raise RuntimeError("agent lab tests require SQLite (run this module alone)")

Base.metadata.create_all(bind=engine)
client = TestClient(app)


def test_enroll_and_revoke_cycle():
    # Enroll
    r = client.post("/api/agent/enroll", headers=HEADERS, json={"agent_id": "ut-agent-01", "label": "UT"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert "token" in j
    token = j["token"]
    assert token.startswith("sb_")
    assert j["agent_id"] == "ut-agent-01"

    # Status shows agent
    r2 = client.get("/api/agent/status", headers=HEADERS)
    assert r2.status_code == 200
    agents = r2.json()
    # agent list is array
    assert any(a["agent_id"] == "ut-agent-01" for a in agents)

    # Heartbeat with token
    hb = client.post("/api/agent/heartbeat", headers={"X-Agent-Token": token, "X-Tenant-ID": "default"}, json={"agent_id": "ut-agent-01", "hostname": "pc-test"})
    assert hb.status_code == 200, hb.text

    # Revoke
    r3 = client.post("/api/agent/revoke", headers=HEADERS, json={"agent_id": "ut-agent-01"})
    assert r3.status_code == 200
    assert r3.json()["revoked"] >= 1

    # Heartbeat should now fail (revoked)
    hb2 = client.post("/api/agent/heartbeat", headers={"X-Agent-Token": token}, json={"agent_id": "ut-agent-01"})
    assert hb2.status_code == 403


def test_telemetry_seq_ack():
    # Enroll fresh
    r = client.post("/api/agent/enroll", headers=HEADERS, json={"agent_id": "ut-agent-seq"})
    token = r.json()["token"]
    headers_agent = {"X-Agent-Token": token, "X-Tenant-ID": "default"}

    # First telemetry seq=1
    t1 = client.post("/api/agent/telemetry", headers=headers_agent, json={
        "agent_id": "ut-agent-seq", "seq": 1,
        "hostname": "pc-seq", "os": "Windows 11", "arch": "x64", "version": "1.0.0",
        "system_logs": [{"ts": "2026-01-01T00:00:00Z", "detail": "Test log", "severity": "info"}],
        "processes": [{"pid": 123, "name": "test.exe"}],
    })
    assert t1.status_code == 200, t1.text
    assert t1.json()["ack_seq"] == 1

    # Duplicate seq should be deduped
    t2 = client.post("/api/agent/telemetry", headers=headers_agent, json={
        "agent_id": "ut-agent-seq", "seq": 1,
        "system_logs": [{"detail": "dup"}],
    })
    assert t2.status_code == 200
    assert t2.json().get("deduped") is True


def test_private_ip_not_sent_to_ti():
    """TI must return unknown for private IPs without calling provider."""
    from app.infrastructure.threat_intel.private_ip import is_private_or_reserved
    assert is_private_or_reserved("192.168.1.10") is True
    assert is_private_or_reserved("10.0.0.5") is True
    assert is_private_or_reserved("127.0.0.1") is True
    assert is_private_or_reserved("8.8.8.8") is False

    from unittest.mock import patch
    db = SessionLocal()
    from app.infrastructure.threat_intel.client import lookup_ip
    with patch("app.infrastructure.threat_intel.client.fetch_abuseipdb") as mock_fetch:
        result = lookup_ip(db, "default", "192.168.1.10")
        assert result["verdict"] == "unknown"
        # Private IP must NOT trigger fetch
        mock_fetch.assert_not_called()
        assert result.get("reason") == "private_ip"
    db.close()


def test_normalization_host_agent():
    from app.application.normalization import normalize_event
    raw = {
        "category": "system_log",
        "detail": "Failed logon",
        "severity": "high",
        "agent_id": "pc-01",
        "tenant_id": "default",
        "src_ip": "10.0.0.5",
    }
    norm = normalize_event(raw, "host-agent")
    assert norm["event.category"] == "system_log"
    assert norm["description"] == "Failed logon"
    assert norm["agent_id"] == "pc-01"
    assert norm["host"]["name"] == "pc-01"  # fallback to agent_id
