"""Syslog message parsers: RFC 5424 (primary) + RFC 3164 fallback."""
import re
from datetime import UTC, datetime
from typing import Any

try:
    from syslog_rfc5424_parser import ParseError as SyslogParseError
    from syslog_rfc5424_parser import SyslogMessage
except ImportError:
    SyslogMessage = None  # type: ignore
    SyslogParseError = Exception  # type: ignore

# RFC 3164 patterns
_PRIORITY_RE = re.compile(r"^<(\d+)>")
_RFC3164_TS_RE = re.compile(
    r"^<\d+>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
)

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "security",
    14: "console", 15: "solaris-cron", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}

# RFC 5424 severity names → numeric 0-7 (0=emerg, 7=debug)
_SEVERITY_NAMES = {
    "emerg": 0, "emergency": 0, "panic": 0,
    "alert": 1,
    "crit": 2, "critical": 2,
    "err": 3, "error": 3,
    "warning": 4, "warn": 4,
    "notice": 5,
    "info": 6, "informational": 6,
    "debug": 7,
}


def _parse_priority(pri: int) -> dict:
    return {
        "facility": _FACILITY_NAMES.get(pri >> 3, f"unknown({pri >> 3})"),
        "severity": pri & 0x7,
    }


def parse_rfc5424(raw: str) -> dict[str, Any] | None:
    """Parse RFC 5424 syslog message. Returns None on parse failure."""
    if SyslogMessage is None:
        return None
    try:
        msg = SyslogMessage.parse(raw)
        d = msg.as_dict()
        # Normalize to our common format
        sev = d.get("severity", 6)
        if isinstance(sev, str):
            sev = _SEVERITY_NAMES.get(sev.lower(), 6)
        result = {
            "facility": d.get("facility", "unknown"),
            "severity": sev,
            "hostname": d.get("hostname", ""),
            "appname": d.get("appname", ""),
            "procid": d.get("procid"),
            "msgid": d.get("msgid", ""),
            "message": d.get("msg", ""),
            "timestamp": d.get("timestamp"),
            "structured_data": d.get("sd"),
        }
        return result
    except (SyslogParseError, Exception):
        return None


def parse_rfc3164(raw: str) -> dict[str, Any] | None:
    """Parse RFC 3164 syslog message (fallback). Returns None on failure."""
    pri_match = _PRIORITY_RE.match(raw)
    if not pri_match:
        return None
    pri = int(pri_match.group(1))
    pri_info = _parse_priority(pri)

    m = _RFC3164_TS_RE.match(raw)
    if not m:
        # Minimal fallback: just extract priority and message
        body = _PRIORITY_RE.sub("", raw, count=1).strip()
        return {**pri_info, "hostname": "", "appname": "", "message": body, "timestamp": None}

    ts_str, hostname, appname, procid, message = m.groups()

    # Parse timestamp (no year in RFC 3164!)
    now = datetime.now(UTC)
    try:
        ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(tzinfo=UTC)
        ts = ts.replace(year=now.year)
        # Handle Dec→Jan rollover
        if ts.month == 1 and now.month == 12:
            ts = ts.replace(year=now.year - 1)
    except ValueError:
        ts = None

    return {
        **pri_info,
        "hostname": hostname or "",
        "appname": appname or "",
        "procid": procid,
        "message": message or "",
        "timestamp": ts.isoformat() if ts else None,
    }


def parse_syslog(raw: str) -> dict[str, Any]:
    """Parse syslog message trying RFC 5424 first, then RFC 3164 fallback.
    Always returns a dict (never None)."""
    result = parse_rfc5424(raw)
    if result is not None:
        result["rfc"] = "5424"
        return result

    result = parse_rfc3164(raw)
    if result is not None:
        result["rfc"] = "3164"
        return result

    # Complete fallback: raw message
    return {
        "facility": "unknown",
        "severity": 6,
        "hostname": "",
        "appname": "",
        "message": raw.strip(),
        "timestamp": None,
        "rfc": "raw",
    }
