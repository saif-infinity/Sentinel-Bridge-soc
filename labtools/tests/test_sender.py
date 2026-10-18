"""Tests de l'envoi HTTP et de l'analyse des en-têtes."""

from __future__ import annotations

import json

import pytest

from labtools.safety import SafetyError
from labtools.sender import HttpDeliverer, SendError, parse_headers


def test_send_single_record(http_collector):
    deliverer = HttpDeliverer(http_collector.url)
    result = deliverer.send_record({"hello": "lab", "n": 1})
    assert result.status == 200
    assert result.duration_ms >= 0
    assert len(http_collector.server.requests) == 1
    request = http_collector.server.requests[0]
    assert request.path == "/api/pipeline/ingest"
    assert json.loads(request.text) == {"hello": "lab", "n": 1}
    assert "application/json" in request.headers["content-type"]


def test_send_batch(http_collector):
    deliverer = HttpDeliverer(http_collector.url)
    deliverer.send_batch([{"i": 1}, {"i": 2}, {"i": 3}])
    body = json.loads(http_collector.server.requests[0].text)
    assert body == [{"i": 1}, {"i": 2}, {"i": 3}]


def test_custom_headers(http_collector):
    deliverer = HttpDeliverer(
        http_collector.url, headers={"X-API-Key": "secret-lab", "X-Label": "test"}
    )
    deliverer.send_record({"ok": True})
    headers = http_collector.server.requests[0].headers
    assert headers["x-api-key"] == "secret-lab"
    assert headers["x-label"] == "test"


def test_http_error_is_reported(http_collector):
    http_collector.server.response_status = 500
    http_collector.server.response_body = b'{"detail":"boom"}'
    deliverer = HttpDeliverer(http_collector.url)
    with pytest.raises(SendError, match="HTTP 500"):
        deliverer.send_record({"ok": True})


def test_connection_refused(closed_port):
    deliverer = HttpDeliverer(f"http://127.0.0.1:{closed_port}/ingest", timeout=0.5)
    with pytest.raises(SendError, match="envoi impossible"):
        deliverer.send_record({"ok": True})


def test_public_url_refused():
    with pytest.raises(SafetyError, match="Cible publique"):
        HttpDeliverer("https://example.com/hook")


@pytest.mark.parametrize("url", ["ftp://localhost/x", "http://user:pw@localhost/x"])
def test_invalid_urls(url):
    with pytest.raises(SafetyError):
        HttpDeliverer(url)


def test_invalid_timeout():
    with pytest.raises(ValueError):
        HttpDeliverer("http://127.0.0.1:1/x", timeout=0)


def test_parse_headers():
    assert parse_headers(["X-API-Key: abc", "X-Trace:  a:b "]) == {
        "X-API-Key": "abc",
        "X-Trace": "a:b",
    }


@pytest.mark.parametrize("raw", ["sans-deux-points", ": vide"])
def test_parse_headers_invalid(raw):
    with pytest.raises(ValueError):
        parse_headers([raw])
