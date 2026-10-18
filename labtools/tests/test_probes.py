"""Tests des sondes TCP et du parseur de ports."""

from __future__ import annotations

import pytest

from labtools.probes import (
    TOP_PORTS,
    format_results,
    parse_ports,
    probe_port,
    scan_ports,
)
from labtools.safety import SafetyError


def test_parse_simple_list():
    assert parse_ports("443,22,80,22") == [22, 80, 443]


def test_parse_ranges_and_top():
    ports = parse_ports("1-5,top")
    assert {1, 2, 3, 4, 5} <= set(ports)
    assert set(TOP_PORTS) <= set(ports)


def test_parse_reversed_range():
    assert parse_ports("10-8") == [8, 9, 10]


@pytest.mark.parametrize(
    "spec", ["", "abc", "0", "70000", "10-70000", "1-20000", "1,,x"]
)
def test_parse_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_probe_closed_port(closed_port):
    result = probe_port("127.0.0.1", closed_port, timeout=0.5)
    assert result.status == "closed"
    assert result.port == closed_port
    assert result.latency_ms is not None


def test_probe_open_port(listening_port):
    result = probe_port("127.0.0.1", listening_port, timeout=0.5)
    assert result.status == "open"
    assert result.as_dict()["host"] == "127.0.0.1"


def test_probe_public_refused():
    with pytest.raises(SafetyError):
        probe_port("8.8.8.8", 53, timeout=0.2)


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_probe_port_bounds(port):
    with pytest.raises(ValueError):
        probe_port("127.0.0.1", port)


def test_scan_local_ports(listening_port, closed_port):
    results = scan_ports(
        "127.0.0.1", [listening_port, closed_port], timeout=0.5, workers=4
    )
    assert [item.port for item in results] == sorted([listening_port, closed_port])
    statuses = {item.port: item.status for item in results}
    assert statuses[listening_port] == "open"
    assert statuses[closed_port] == "closed"


def test_scan_public_refused():
    with pytest.raises(SafetyError):
        scan_ports("8.8.8.8", [53, 443], timeout=0.1)


def test_scan_workers_bounds():
    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", [80], workers=0)
    with pytest.raises(ValueError):
        scan_ports("127.0.0.1", [80], workers=999)


def test_format_results(listening_port, closed_port):
    results = scan_ports(
        "127.0.0.1", [listening_port, closed_port], timeout=0.5, workers=4
    )
    table = format_results(results)
    assert "HÔTE" in table
    assert "open" in table
    assert "PORT" in table
    only_open = format_results(results, open_only=True)
    assert "open" in only_open
    assert str(closed_port) not in only_open
