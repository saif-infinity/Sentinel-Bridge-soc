"""Tests des scénarios intégrés et du chargeur de scénarios personnalisés."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from labtools.events import generate_events
from labtools.scenarios import SCENARIOS, get_scenario, load_custom_scenario

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_all_builtins_have_metadata():
    assert len(SCENARIOS) >= 8
    for name, scenario in SCENARIOS.items():
        assert scenario.name == name
        assert scenario.title
        assert scenario.description
        assert scenario.mitre
        assert scenario.default_host
        assert scenario.default_interval >= 0


def test_unknown_scenario_suggests_close_name():
    with pytest.raises(ValueError, match="Vouliez-vous dire"):
        get_scenario("port-scann")


def test_unknown_scenario_lists_choices():
    with pytest.raises(ValueError, match="Disponibles"):
        get_scenario("zzz")


def _write(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _minimal(**overrides):
    data = {
        "name": "custom-test",
        "title": "Test",
        "events": [{"category": "lab", "action": "ping", "message": "essai {index}"}],
    }
    data.update(overrides)
    return data


def test_load_example_file():
    scenario = load_custom_scenario(EXAMPLES / "custom-scenario.json")
    assert scenario.name == "custom-powershell"
    events = generate_events(scenario, count=7, seed=1)
    assert len(events) == 7
    assert events[0].message.endswith("attempt 1) on win-lab-01.lab.local")
    assert events[0].details["encoded_command"] is True
    # Le premier événement (count=2) se répète, puis vient le second.
    assert events[1].message.startswith("Encoded PowerShell")
    assert events[2].message.startswith("PowerShell downloaded")
    assert events[3].message.startswith("Encoded PowerShell")


def test_defaults_are_merged(tmp_path):
    path = _write(
        tmp_path,
        {
            "name": "custom-defaults",
            "events": [{"message": "essai {index}"}],
            "defaults": {
                "category": "endpoint",
                "action": "observe",
                "severity": "high",
                "user": "analyst",
                "tags": ["custom"],
                "details": {"a": 1},
            },
        },
    )
    scenario = load_custom_scenario(path)
    event = generate_events(scenario, count=1)[0]
    assert event.severity == "high"
    assert event.category == "endpoint"
    assert event.action == "observe"
    assert event.user == "analyst"
    assert event.details == {"a": 1}
    assert "custom" in event.tags


def test_count_expands_cycle(tmp_path):
    payload = _minimal()
    payload["events"][0]["count"] = 3
    path = _write(tmp_path, payload)
    scenario = load_custom_scenario(path)
    events = generate_events(scenario, count=5)
    assert events[0].message == "essai 1"
    assert events[2].message == "essai 3"
    assert events[3].message == "essai 4"


def test_custom_mitre_defaults_to_header(tmp_path):
    path = _write(tmp_path, _minimal(mitre=["T1059"]))
    scenario = load_custom_scenario(path)
    assert generate_events(scenario, count=1)[0].mitre == ["T1059"]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"name": "x"}, "name"),
        (_minimal(name="Bad Name"), "name"),
        (_minimal(events=[]), "events"),
        (_minimal(events=[{"category": "lab"}]), "message"),
        (_minimal(events=[{"message": "ok"}]), "category"),
        (_minimal(events=[{"message": "ok", "category": "lab", "action": "run", "severity": "urgent"}]), "gravité"),
        (_minimal(extra=1), "inconnu"),
        (_minimal(events=[{"message": "{inconnu}", "category": "lab"}]), "placeholder"),
        (_minimal(events=[{"message": "ok", "category": "lab", "count": 0}]), "count"),
        (_minimal(events=[{"message": "ok", "category": "lab", "tags": "x"}]), "liste"),
    ],
)
def test_invalid_custom_scenarios(tmp_path, payload, message):
    path = _write(tmp_path, payload)
    with pytest.raises(ValueError, match=message):
        load_custom_scenario(path)


def test_missing_file():
    with pytest.raises(ValueError, match="introuvable"):
        load_custom_scenario("/nonexistent/scenario.json")


def test_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON invalide"):
        load_custom_scenario(path)
