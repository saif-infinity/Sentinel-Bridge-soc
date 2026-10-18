"""Tests des sérialiseurs JSONL, CEF, syslog RFC 5424 et Sentinel Bridge."""

from __future__ import annotations

import json
import re

import pytest

from labtools.events import generate_events
from labtools.formats import (
    FORMATS,
    format_event,
    format_record,
    render_records,
    sentinel_payload,
)
from labtools.scenarios import get_scenario

SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) - (?P<msgid>\S+) - (?P<rest>.+)$"
)


@pytest.fixture(scope="module")
def events():
    return generate_events(
        get_scenario("auth-bruteforce"), count=4, seed=11, start="2026-02-03T04:05:06Z"
    )


def test_jsonl_roundtrip(events):
    line = format_event(events[0], "jsonl")
    data = json.loads(line)
    assert data == events[0].to_dict()


def test_jsonl_one_line_per_event(events):
    text = render_records([event.to_dict() for event in events], "jsonl")
    assert len(text.splitlines()) == 4
    assert all(json.loads(line)["severity"] for line in text.splitlines())


def test_cef_header_and_extensions(events):
    line = format_event(events[0], "cef")
    assert line.startswith("CEF:0|LabTools|test-tools-collecter|")
    assert "|auth-bruteforce|ssh_login|" in line
    assert "externalId=" in line
    assert "dvchost=bastion-01.lab.local" in line
    assert "suser=" in line
    assert "cs1Label=MITRE" in line
    assert "T1110" in line


def test_cef_escapes_separators():
    record = {
        "scenario": "test|pipe",
        "action": "a=b",
        "message": "ligne 1\nligne 2 = ok",
        "severity": "high",
    }
    line = format_record(record, "cef")
    header, extensions = line.rsplit("|", 1)
    assert "test\\|pipe" in header
    assert "msg=ligne 1\\nligne 2 \\= ok" in extensions


def test_syslog_shape(events):
    line = format_event(events[0], "syslog")
    match = SYSLOG_RE.match(line)
    assert match, line
    priority = int(match.group("pri"))
    assert priority == 13 * 8 + 5  # facility audit, severity notice
    assert match.group("ts") == "2026-02-03T04:05:06.000Z"
    assert match.group("host") == "bastion-01.lab.local"
    assert match.group("app") == "labtools"
    assert 'msg="Failed password' in match.group("rest")
    assert "src=" in match.group("rest")
    assert "mitre=T1110" in match.group("rest")


@pytest.mark.parametrize(
    ("severity", "score"),
    [("low", 3), ("medium", 6), ("high", 9), ("critical", 12)],
)
def test_sentinel_severity_mapping(events, severity, score):
    event = events[0].to_dict()
    event["severity"] = severity
    payload = sentinel_payload(event)
    assert payload["severity"] == score
    assert payload["source"] == "manual"
    assert payload["signature"] == "auth-bruteforce:ssh_login"
    assert payload["raw"]["severity"] == severity
    assert payload.get("dest_ip") is None


def test_sentinel_payload_contract(events):
    payload = sentinel_payload(events[0].to_dict())
    allowed = {
        "source", "severity", "signature", "description", "src_ip",
        "dest_ip", "proto", "category", "raw",
    }
    assert set(payload) <= allowed
    assert 1 <= len(payload["description"]) <= 500
    assert len(payload["signature"]) <= 255
    json.dumps(payload)  # sérialisable


def test_unknown_format_rejected(events):
    with pytest.raises(ValueError, match="format inconnu"):
        format_record(events[0].to_dict(), "xml")


def test_all_formats_are_supported(events):
    for fmt in FORMATS:
        assert format_event(events[0], fmt)


def test_sentinel_handles_missing_fields():
    payload = sentinel_payload(
        {"scenario": "custom", "action": "test", "message": "ok", "severity": "weird"}
    )
    assert payload["severity"] == 6
    assert "src_ip" not in payload
    assert "dest_ip" not in payload
