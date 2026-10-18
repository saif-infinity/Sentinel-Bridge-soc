"""Sérialisation des événements : JSONL, CEF, syslog RFC 5424, Sentinel Bridge."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .events import (
    SEVERITIES,
    SEVERITY_TO_CEF,
    SEVERITY_TO_SENTINEL,
    SEVERITY_TO_SYSLOG,
)

FORMATS = ("jsonl", "cef", "syslog", "sentinel")

CEF_FACILITY = 13  # log audit


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _cef_header(value: Any) -> str:
    return _text(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_ext(value: Any) -> str:
    return (
        _text(value)
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _epoch_ms(timestamp: Any) -> int | None:
    if not timestamp:
        return None
    try:
        moment = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def _syslog_host(host: Any) -> str:
    cleaned = _text(host).replace(" ", "_").replace("\n", "")
    return cleaned or "-"


def _format_cef(record: Mapping[str, Any]) -> str:
    severity = str(record.get("severity", "medium"))
    score = SEVERITY_TO_CEF.get(severity, 5)
    header = "|".join(
        (
            "CEF:0",
            "LabTools",
            "test-tools-collecter",
            __version__,
            _cef_header(record.get("scenario", "labtools")),
            _cef_header(record.get("action", "event")),
            str(score),
        )
    )
    extensions: list[str] = []
    fields = (
        ("externalId", record.get("event_id")),
        ("rt", _epoch_ms(record.get("timestamp"))),
        ("cat", record.get("category")),
        ("dvchost", record.get("host")),
        ("src", record.get("src_ip")),
        ("spt", record.get("src_port")),
        ("dst", record.get("dst_ip")),
        ("dpt", record.get("dst_port")),
        ("suser", record.get("user")),
        ("proto", record.get("protocol")),
        ("act", record.get("action")),
        ("outcome", record.get("outcome")),
        ("msg", record.get("message")),
    )
    for key, value in fields:
        if value is None or value == "":
            continue
        extensions.append(f"{key}={_cef_ext(value)}")
    mitre = record.get("mitre") or []
    if mitre:
        extensions.append("cs1Label=MITRE")
        extensions.append(f"cs1={_cef_ext(','.join(str(item) for item in mitre))}")
    return f"{header}|{' '.join(extensions)}"


def _format_syslog(record: Mapping[str, Any]) -> str:
    severity = str(record.get("severity", "medium"))
    syslog_severity = SEVERITY_TO_SYSLOG.get(severity, 5)
    priority = CEF_FACILITY * 8 + syslog_severity
    timestamp = record.get("timestamp") or "-"
    hostname = _syslog_host(record.get("host"))
    app_name = "labtools"
    msgid = _text(record.get("scenario", "lab"))[:32] or "-"
    parts = [
        f"category={record.get('category', '-')}",
        f"action={record.get('action', '-')}",
        f"outcome={record.get('outcome', '-')}",
    ]
    for key, field in (
        ("src", "src_ip"),
        ("dst", "dst_ip"),
        ("dpt", "dst_port"),
        ("suser", "user"),
        ("proto", "protocol"),
    ):
        value = record.get(field)
        if value not in (None, ""):
            parts.append(f"{key}={value}")
    mitre = record.get("mitre") or []
    if mitre:
        parts.append(f"mitre={','.join(str(item) for item in mitre)}")
    message = _text(record.get("message", "")).replace('"', "'").replace("\n", " ")
    parts.append(f'msg="{message}"')
    return f"<{priority}>1 {timestamp} {hostname} {app_name} - {msgid} - {' '.join(parts)}"


def sentinel_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    """Construit un corps compatible avec ``POST /api/pipeline/ingest``."""

    severity = str(record.get("severity", "medium"))
    if severity not in SEVERITIES:
        severity = "medium"
    signature = f"{record.get('scenario', 'labtools')}:{record.get('action', 'event')}"
    payload: dict[str, Any] = {
        "source": "manual",
        "severity": SEVERITY_TO_SENTINEL[severity],
        "signature": signature[:255],
        "description": _text(record.get("message", ""))[:500],
        "category": _text(record.get("category", ""))[:100] or None,
        "raw": dict(record),
    }
    optional = {
        "src_ip": record.get("src_ip"),
        "dest_ip": record.get("dst_ip"),
        "proto": record.get("protocol"),
    }
    for key, value in optional.items():
        if value not in (None, ""):
            payload[key] = str(value)[:45] if key != "proto" else str(value)[:20]
    return {key: value for key, value in payload.items() if value is not None}


def format_record(record: Mapping[str, Any], fmt: str) -> str:
    """Sérialise un événement (objet ou dict) dans le format demandé."""

    if fmt == "jsonl":
        return json.dumps(dict(record), ensure_ascii=False)
    if fmt == "cef":
        return _format_cef(record)
    if fmt == "syslog":
        return _format_syslog(record)
    if fmt == "sentinel":
        return json.dumps(sentinel_payload(record), ensure_ascii=False)
    raise ValueError(f"format inconnu « {fmt} » ; attendu : {', '.join(FORMATS)}")


def format_event(event: Any, fmt: str) -> str:
    """Sérialise un :class:`labtools.events.Event`."""

    return format_record(event.to_dict(), fmt)


def render_records(records: Iterable[Mapping[str, Any]], fmt: str) -> str:
    """Sérialise une séquence d'événements, une ligne par événement."""

    return "\n".join(format_record(record, fmt) for record in records)
