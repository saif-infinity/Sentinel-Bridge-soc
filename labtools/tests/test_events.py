"""Tests du modèle d'événement et de la génération déterministe."""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from labtools.events import (
    SEVERITIES,
    Event,
    generate_events,
    iso_z,
    parse_time,
)
from labtools.scenarios import SCENARIOS, get_scenario


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_builtin_scenario_generates_valid_events(name):
    scenario = get_scenario(name)
    events = generate_events(scenario, count=25, seed=7, start="2026-01-02T03:04:05Z")
    assert len(events) == 25
    for event in events:
        assert isinstance(event, Event)
        assert event.scenario == name
        assert event.severity in SEVERITIES
        assert event.category
        assert event.action
        assert event.message
        assert event.event_id
        uuid.UUID(event.event_id)  # identifiant valide
        assert name in event.tags
        assert isinstance(event.mitre, list)
        assert isinstance(event.details, dict)
        # Aucune adresse de documentation ne doit être une adresse publique réelle.
        for field in ("src_ip", "dst_ip"):
            value = getattr(event, field)
            if value:
                assert value.split(".")[0] in {"10", "192", "198", "203"}


def test_generation_is_deterministic():
    scenario = get_scenario("auth-bruteforce")
    first = generate_events(scenario, count=12, seed=3, start="2026-05-01T00:00:00Z")
    second = generate_events(scenario, count=12, seed=3, start="2026-05-01T00:00:00Z")
    assert [event.to_dict() for event in first] == [event.to_dict() for event in second]


def test_different_seed_changes_content():
    scenario = get_scenario("web-attack")
    first = generate_events(scenario, count=5, seed=1, start="2026-05-01T00:00:00Z")
    second = generate_events(scenario, count=5, seed=2, start="2026-05-01T00:00:00Z")
    assert [event.src_ip for event in first] != [event.src_ip for event in second]


def test_timestamps_are_ordered_and_follow_interval():
    scenario = get_scenario("port-scan")
    events = generate_events(
        scenario, count=4, seed=1, interval=30, start="2026-03-04T05:06:07Z"
    )
    moments = [parse_time(event.timestamp) for event in events]
    assert moments[0].isoformat() == "2026-03-04T05:06:07+00:00"
    for previous, current in zip(moments[:-1], moments[1:], strict=True):
        assert current - previous == timedelta(seconds=30)


def test_iso_z_format():
    moment = parse_time("2026-01-02T03:04:05.678+01:00")
    assert iso_z(moment) == "2026-01-02T02:04:05.678Z"


def test_naive_timestamp_is_considered_utc():
    assert parse_time("2026-01-02T03:04:05").isoformat() == "2026-01-02T03:04:05+00:00"


@pytest.mark.parametrize("value", ["", "hier", "2026-13-40T99:00:00Z"])
def test_invalid_timestamp_rejected(value):
    with pytest.raises(ValueError):
        parse_time(value)


@pytest.mark.parametrize("count", [0, -3, 100_001])
def test_count_bounds(count):
    with pytest.raises(ValueError):
        generate_events(get_scenario("beacon"), count=count)


def test_negative_interval_rejected():
    with pytest.raises(ValueError):
        generate_events(get_scenario("beacon"), count=2, interval=-1)


def test_host_override_applies():
    events = generate_events(
        get_scenario("dns-tunnel"), count=3, host="pc-test.lab.local"
    )
    assert all(event.host == "pc-test.lab.local" for event in events)


def test_field_types_are_stable():
    event = generate_events(get_scenario("credential-dump"), count=1)[0]
    data = event.to_dict()
    for key in (
        "timestamp", "event_id", "scenario", "category", "action", "outcome",
        "severity", "host", "message", "source", "tags", "mitre", "details",
    ):
        assert key in data
    assert data["source"] == "labtools"
    assert isinstance(data["details"], dict)
    assert isinstance(data["tags"], list)
