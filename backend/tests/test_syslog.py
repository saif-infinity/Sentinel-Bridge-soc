"""Tests for R10 syslog ingestion components."""
import json
from unittest.mock import MagicMock

import pytest

from app.application.normalization import map_syslog, normalize_event
from app.infrastructure.syslog.protocol import parse_rfc3164, parse_rfc5424, parse_syslog
from app.infrastructure.syslog.tenant_resolver import configure, resolve_tenant


class TestSyslogProtocol:
    def test_parse_rfc5424_basic(self):
        msg = '<13>1 2024-01-15T10:30:00Z myhost myapp 1234 - - Hello world'
        result = parse_rfc5424(msg)
        assert result is not None
        assert result["hostname"] == "myhost"
        assert result["appname"] == "myapp"
        assert "Hello world" in result.get("message", "")

    def test_parse_rfc3164_basic(self):
        msg = '<34>Oct 11 22:14:15 mymachine su: root failed'
        result = parse_rfc3164(msg)
        assert result is not None
        assert result["hostname"] == "mymachine"
        assert result["appname"] == "su"

    def test_parse_syslog_fallback(self):
        result = parse_syslog("totally not syslog")
        assert "message" in result
        assert result["rfc"] == "raw"

    def test_parse_syslog_rfc5424_preferred(self):
        msg = '<13>1 2024-01-15T10:30:00Z host app 1 - - test'
        result = parse_syslog(msg)
        assert result["rfc"] == "5424"


class TestTenantResolver:
    def setup_method(self):
        configure({"192.168.1.0/24": "tenant-a", "10.0.0.0/8": "tenant-b"}, "default")

    def test_resolve_cidr_match(self):
        assert resolve_tenant("192.168.1.100") == "tenant-a"
        assert resolve_tenant("10.0.0.1") == "tenant-b"

    def test_resolve_fallback(self):
        assert resolve_tenant("172.16.0.1") == "default"

    def test_resolve_invalid_ip(self):
        assert resolve_tenant("not-an-ip") == "default"

    def test_no_mappings(self):
        configure(None, "fallback-tenant")
        assert resolve_tenant("192.168.1.1") == "fallback-tenant"


class TestMapSyslog:
    def test_basic_mapping(self):
        raw = {
            "message": "Connection refused",
            "source_ip": "192.168.1.10",
            "severity": 3,
            "hostname": "firewall-01",
            "appname": "iptables",
        }
        result = map_syslog(raw)
        assert result["description"] == "Connection refused"
        assert result["src_ip"] == "192.168.1.10"
        assert result["severity"] == 9  # syslog severity 3 → normalized 9
        assert result["proto"] == "syslog"
        assert result["host"]["name"] == "firewall-01"

    def test_normalize_event_syslog_source(self):
        raw = {
            "message": "test alert",
            "source_ip": "10.0.0.1",
            "severity": 0,
            "hostname": "host",
            "appname": "test",
        }
        result = normalize_event(raw, source="syslog")
        assert result["description"] == "test alert"
        assert result["severity"] == 15  # syslog 0=crit → 15


class TestStreamHelpers:
    def test_publish_event(self):
        from app.infrastructure.syslog.stream import publish_event

        r = MagicMock()
        r.xadd.return_value = "123-0"
        msg_id = publish_event(r, {"message": "hello", "tenant_id": "t1"})
        assert msg_id == "123-0"
        # payload is JSON-serialized (fields passed positionally)
        fields = r.xadd.call_args.args[1]
        assert "payload" in fields
        assert json.loads(fields["payload"])["message"] == "hello"

    def test_send_to_dlq(self):
        from app.infrastructure.syslog.stream import send_to_dlq

        r = MagicMock()
        r.xadd.return_value = "dlq-1"
        msg_id = send_to_dlq(r, "orig-1", "boom", "{}")
        assert msg_id == "dlq-1"
        fields = r.xadd.call_args.args[1]
        assert fields["original_id"] == "orig-1"
        assert fields["error"] == "boom"

    def test_ensure_group_idempotent(self):
        from redis import ResponseError

        from app.infrastructure.syslog.stream import ensure_group

        r = MagicMock()
        r.xgroup_create.side_effect = ResponseError("BUSYGROUP Consumer Group name already exists")
        ensure_group(r)  # must not raise

        r.xgroup_create.side_effect = ResponseError("OTHER error")
        with pytest.raises(ResponseError):
            ensure_group(r)
