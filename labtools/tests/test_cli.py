"""Tests de bout en bout de la CLI."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from labtools.cli import main
from labtools.events import SEVERITIES

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "COMMANDE" in capsys.readouterr().out


def test_create_jsonl_on_stdout(capsys):
    code = main(["create", "-s", "web-attack", "-n", "3", "--start", "2026-01-01T00:00:00Z"])
    assert code == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 3
    events = [json.loads(line) for line in lines]
    assert all(event["scenario"] == "web-attack" for event in events)
    assert events[0]["timestamp"] == "2026-01-01T00:00:00.000Z"
    assert all(event["severity"] in SEVERITIES for event in events)


def test_create_to_file(tmp_path, capsys):
    output = tmp_path / "nested" / "events.jsonl"
    code = main(["create", "-s", "beacon", "-n", "2", "-o", str(output)])
    assert code == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2
    assert "écrite" in capsys.readouterr().err


@pytest.mark.parametrize("fmt", ["jsonl", "cef", "syslog", "sentinel"])
def test_create_all_formats(fmt, capsys):
    assert main(["create", "-s", "dns-tunnel", "-n", "1", "--format", fmt]) == 0
    assert capsys.readouterr().out.strip()


def test_create_unknown_scenario(capsys):
    assert main(["create", "-s", "nope"]) == 1
    assert "inconnu" in capsys.readouterr().err


def test_create_invalid_count(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["create", "-s", "beacon", "-n", "0"])
    assert excinfo.value.code == 2


def test_create_with_custom_scenario(capsys):
    code = main(
        [
            "create",
            "--scenario-file",
            str(EXAMPLES / "custom-scenario.json"),
            "-n",
            "2",
            "--start",
            "2026-01-01T00:00:00Z",
        ]
    )
    assert code == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["scenario"] == "custom-powershell"


def test_list(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "auth-bruteforce" in out
    assert "SCÉNARIO" in out


def test_list_json(capsys):
    assert main(["list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) >= 8
    assert {"name", "title", "mitre", "default_host"} <= set(data[0])


def test_validate_example(capsys):
    assert main(["validate", str(EXAMPLES / "custom-scenario.json")]) == 0
    out = capsys.readouterr().out
    assert "OK" in out
    assert "custom-powershell" in out


def test_validate_invalid_file(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    assert main(["validate", str(path)]) == 1
    assert "name" in capsys.readouterr().err


def test_catalog(capsys):
    assert main(["catalog", "--category", "reseau"]) == 0
    out = capsys.readouterr().out
    assert "scapy" in out.lower()
    assert "outil(s) affiché(s)" in out


def test_catalog_json(capsys):
    assert main(["catalog", "--search", "python", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data
    assert all("python" in json.dumps(tool).lower() for tool in data)


def test_catalog_details(capsys):
    assert main(["catalog", "--id", "scapy"]) == 0
    assert "Scapy" in capsys.readouterr().out


def test_catalog_unknown_id(capsys):
    assert main(["catalog", "--id", "nope"]) == 1
    assert "inconnu" in capsys.readouterr().err


def test_probe_open_port(listening_port, capsys):
    assert main(["probe", f"127.0.0.1:{listening_port}", "--timeout", "0.5"]) == 0
    assert "open" in capsys.readouterr().out


def test_probe_closed_port_exit_code(closed_port, capsys):
    assert main(["probe", f"127.0.0.1:{closed_port}", "--timeout", "0.5"]) == 1
    assert "closed" in capsys.readouterr().out


def test_probe_json(closed_port, capsys):
    main(["probe", "127.0.0.1", "--port", str(closed_port), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "closed"
    assert data["host"] == "127.0.0.1"


def test_probe_requires_port(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["probe", "127.0.0.1"])
    assert "port requis" in str(excinfo.value)


def test_probe_url(listening_port, capsys):
    assert main(["probe", f"http://127.0.0.1:{listening_port}/health"]) == 0
    assert "open" in capsys.readouterr().out


def test_probe_public_refused(capsys):
    assert main(["probe", "8.8.8.8:53"]) == 1
    assert "Cible publique" in capsys.readouterr().err


def test_scan_closed_port(closed_port, capsys):
    assert main(["scan", "127.0.0.1", "--ports", str(closed_port)]) == 0
    out = capsys.readouterr().out
    assert "closed" in out
    assert "0/1" in out


def test_scan_json(listening_port, capsys):
    assert main(
        ["scan", "127.0.0.1", "--ports", str(listening_port), "--json"]
    ) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["status"] == "open"


def test_scan_invalid_ports(capsys):
    assert main(["scan", "127.0.0.1", "--ports", "abc"]) == 1
    assert "port invalide" in capsys.readouterr().err


def test_send_requires_url(monkeypatch):
    monkeypatch.delenv("LABTOOLS_URL", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(["send", "-s", "beacon", "-n", "1"])
    assert "URL requise" in str(excinfo.value)


def test_send_single_records(http_collector, capsys):
    code = main(
        [
            "send", "-s", "auth-bruteforce", "-n", "3",
            "--url", http_collector.url,
            "--header", "X-API-Key: test-key",
        ]
    )
    assert code == 0
    requests = http_collector.server.requests
    assert len(requests) == 3
    payload = json.loads(requests[0].text)
    assert payload["source"] == "manual"
    assert payload["signature"] == "auth-bruteforce:ssh_login"
    assert payload["raw"]["scenario"] == "auth-bruteforce"
    assert requests[0].headers["x-api-key"] == "test-key"
    assert "envoyé(s) vers" in capsys.readouterr().out


def test_send_batch(http_collector):
    code = main(
        [
            "send", "-s", "web-attack", "-n", "4",
            "--url", http_collector.url, "--batch",
        ]
    )
    assert code == 0
    assert len(http_collector.server.requests) == 1
    body = json.loads(http_collector.server.requests[0].text)
    assert isinstance(body, list)
    assert len(body) == 4


def test_send_jsonl(http_collector):
    code = main(
        [
            "send", "-s", "beacon", "-n", "2", "--format", "jsonl",
            "--url", http_collector.url,
        ]
    )
    assert code == 0
    body = json.loads(http_collector.server.requests[0].text)
    assert body["scenario"] == "beacon"


def test_send_api_key_from_env(http_collector, monkeypatch):
    monkeypatch.setenv("LABTOOLS_API_KEY", "env-key")
    assert main(["send", "-s", "beacon", "-n", "1", "--url", http_collector.url]) == 0
    assert http_collector.server.requests[0].headers["x-api-key"] == "env-key"


def test_send_dry_run(http_collector, capsys):
    assert main(
        ["send", "-s", "beacon", "-n", "2", "--url", http_collector.url, "--dry-run"]
    ) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["source"] == "manual"
    assert "dry-run" in output.err
    assert http_collector.server.requests == []


def test_send_failure_exit_code(http_collector, capsys):
    http_collector.server.response_status = 500
    code = main(["send", "-s", "beacon", "-n", "2", "--url", http_collector.url])
    assert code == 1
    assert "échec" in capsys.readouterr().err


def test_send_connection_error(closed_port, capsys):
    assert main(
        ["send", "-s", "beacon", "-n", "1", "--url", f"http://127.0.0.1:{closed_port}/x"]
    ) == 1
    assert "envoi impossible" in capsys.readouterr().err


def test_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "labtools" in capsys.readouterr().out


def test_unknown_command():
    with pytest.raises(SystemExit) as excinfo:
        main(["frobnicate"])
    assert excinfo.value.code == 2


def test_socket_not_leaked(listening_port):
    """Vérifie que la fixture de port libre reste utilisable après un scan."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        assert client.connect_ex(("127.0.0.1", listening_port)) == 0
