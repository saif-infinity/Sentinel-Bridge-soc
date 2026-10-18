"""Collector connexions réseau — psutil.net_connections, sans scan actif."""
import datetime

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def collect_network(max_count: int = 500) -> list[dict]:
    """
    Liste les connexions réseau établies du host (pas de scan des voisins).
    Respecte la consigne: uniquement le PC où l'agent est installé.
    """
    if not HAS_PSUTIL:
        return []
    out = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            if len(out) >= max_count:
                break
            # Filtrer selon statut si besoin — on garde tout pour visibilité
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            out.append({
                "proto": "tcp" if conn.type == 1 else "udp" if conn.type == 2 else str(conn.type),
                "laddr": laddr,
                "raddr": raddr,
                "status": conn.status,
                "pid": conn.pid,
                "src_ip": conn.laddr.ip if conn.laddr else None,
                "dest_ip": conn.raddr.ip if conn.raddr else None,
                "src_port": conn.laddr.port if conn.laddr else None,
                "dest_port": conn.raddr.port if conn.raddr else None,
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "severity": "info",
            })
    except (psutil.AccessDenied, PermissionError):
        # Sur Windows sans admin, net_connections peut échouer — retourner vide, pas d'erreur
        return []
    return out


def collect_auth_events() -> list[dict]:
    """
    Stub pour auth events — sur Windows: Security Event Log (4624/4625), sur Linux: /var/log/auth.log
    Implémentation minimale: retourne vide si non privilégié, sinon lit les dernières lignes.
    Pour lab, on peut étendre avec win32evtlog sur Windows.
    """
    import platform
    import pathlib
    events = []
    system = platform.system()
    if system == "Linux":
        # Try /var/log/auth.log or secure
        for log_path in ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"]:
            p = pathlib.Path(log_path)
            if p.exists():
                try:
                    lines = p.read_text(errors="ignore").splitlines()[-20:]
                    for line in lines:
                        if "Failed" in line or "Accepted" in line or "failure" in line.lower():
                            events.append({
                                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "source": "auth.log",
                                "severity": "medium" if "Failed" in line else "info",
                                "detail": line[:500],
                                "event_type": "authentication",
                                "proto": "ssh",
                            })
                    break
                except Exception:
                    continue
        events = events[:50]
    elif system == "Windows":
        # Sur Windows, nécessite win32evtlog (pywin32) — optionnel
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
            server = "localhost"
            logtype = "Security"
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            for rec in (records or [])[:30]:
                # 4624 = logon, 4625 = failed logon
                eid = rec.EventID & 0xFFFF
                if eid in (4624, 4625, 4648, 4672):
                    desc = " ".join(rec.StringInserts or [])[:500] if rec.StringInserts else f"Event {eid}"
                    events.append({
                        "ts": rec.TimeGenerated.isoformat() if hasattr(rec.TimeGenerated, 'isoformat') else datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "source": "Windows Security",
                        "severity": "high" if eid == 4625 else "info",
                        "detail": desc,
                        "event_type": "logon" if eid == 4624 else "failed_logon",
                        "user": rec.StringInserts[5] if rec.StringInserts and len(rec.StringInserts) > 5 else None,
                    })
            win32evtlog.CloseEventLog(hand)
        except ImportError:
            # pywin32 non installé — pas bloquant
            pass
        except Exception:
            pass
    return events[:50]
