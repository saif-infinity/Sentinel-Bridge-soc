"""Collector journaux système — Windows Event Log / Linux journald (lecture seule)."""
import datetime
import platform


def collect_system_logs(max_lines: int = 100) -> list[dict]:
    """Collecte journaux système récents (sans envoi auto de logs bruts complets en TI)."""
    import pathlib
    events = []
    system = platform.system()

    if system == "Linux":
        # journalctl ou /var/log/syslog
        # Essai 1: journalctl --no-pager -n 100 --output=json (si disponible)
        try:
            import subprocess, json as _json
            result = subprocess.run(
                ["journalctl", "--no-pager", "-n", str(max_lines), "--output=json", "--priority=warning"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line=line.strip()
                    if not line:
                        continue
                    try:
                        j = _json.loads(line)
                        msg = j.get("MESSAGE") or j.get("SYSLOG_IDENTIFIER") or line[:300]
                        events.append({
                            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "source": "journald",
                            "severity": "warning",
                            "detail": msg[:500],
                            "host": j.get("_HOSTNAME"),
                            "_raw": j if len(events) < 5 else None,  # limiter raw
                        })
                    except Exception:
                        continue
                if events:
                    return events[:max_lines]
        except FileNotFoundError:
            pass
        except Exception:
            pass
        # Fallback: /var/log/syslog
        for path in ["/var/log/syslog", "/var/log/messages"]:
            p = pathlib.Path(path)
            if p.exists():
                try:
                    lines = p.read_text(errors="ignore").splitlines()[-max_lines:]
                    for line in lines:
                        if not line.strip():
                            continue
                        events.append({
                            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "source": "syslog",
                            "severity": "info",
                            "detail": line[:500],
                        })
                    break
                except Exception:
                    continue

    elif system == "Windows":
        try:
            import win32evtlog  # type: ignore
            server = "localhost"
            for logtype in ["System", "Application"]:
                hand = win32evtlog.OpenEventLog(server, logtype)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                records = win32evtlog.ReadEventLog(hand, flags, 0)
                for rec in (records or [])[:30]:
                    # Filtre: Error/Warning
                    if rec.EventType in (1, 2):  # 1=Error, 2=Warning
                        desc = " ".join(rec.StringInserts or [])[:500] if rec.StringInserts else rec.SourceName
                        events.append({
                            "ts": rec.TimeGenerated.isoformat() if hasattr(rec.TimeGenerated, 'isoformat') else datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "source": f"Windows/{logtype}",
                            "severity": "high" if rec.EventType == 1 else "medium",
                            "detail": f"{rec.SourceName}: {desc}",
                            "event_type": "system_log",
                        })
                win32evtlog.CloseEventLog(hand)
                if len(events) >= max_lines:
                    break
        except ImportError:
            # pywin32 non installé — fallback: pas de logs, mais agent reste utile
            events.append({
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": "windows",
                "severity": "info",
                "detail": f"Agent Windows {platform.node()} — pywin32 non installé, logs système non collectés (installer pywin32 pour activer)",
                "event_type": "info",
            })
        except Exception as e:
            events.append({
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": "windows",
                "severity": "warning",
                "detail": f"Lecture EventLog échouée: {e}",
                "event_type": "error",
            })

    else:
        events.append({
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": platform.system().lower(),
            "severity": "info",
            "detail": f"Collecte système minimale sur {platform.system()} — non implémenté en détail",
        })

    return events[:max_lines]
