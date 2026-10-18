"""Config loader — JSON / YAML tolerant, LAN-first."""
import json
import os
import pathlib
import platform
from dataclasses import dataclass, asdict


DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8001",
    "agent_id": "",
    "token": "",
    "tenant_id": "default",
    "verify_tls": True,
    "heartbeat_interval_secs": 30,
    "telemetry_interval_secs": 30,
    "orders_interval_secs": 10,
    "http_timeout_secs": 15,
    # Collecte configurable
    "enable_system_logs": True,
    "enable_auth_logs": True,
    "enable_processes": True,
    "enable_network": True,
    "max_processes": 500,
    "batch_size": 50,
    "queue_max_events": 5000,
    "queue_max_bytes": 20 * 1024 * 1024,
    "log_level": "INFO",
}


def _hostname() -> str:
    try:
        return platform.node() or os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "unknown"
    except Exception:
        return "unknown"


def load_config(path: str | None = None) -> dict:
    """Charge config depuis fichier JSON (priorité: path > ./config.json > /etc/sentinel-agent/config.json)."""
    candidates = []
    if path:
        candidates.append(pathlib.Path(path))
    candidates.append(pathlib.Path("config.json"))
    candidates.append(pathlib.Path("agent/config.json"))
    candidates.append(pathlib.Path("/etc/sentinel-agent/config.json"))
    candidates.append(pathlib.Path(os.path.expanduser("~/.sentinel-agent/config.json")))

    cfg = dict(DEFAULT_CONFIG)
    src = None
    for p in candidates:
        if p.exists():
            src = p
            break
    if src:
        try:
            with open(src, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    if k in cfg or k in ("api_url", "api_key"):  # legacy alias
                        if k == "api_url":
                            cfg["server_url"] = v
                        elif k == "api_key":
                            # legacy global API key → token
                            if not cfg.get("token"):
                                cfg["token"] = v
                        else:
                            cfg[k] = v
                    else:
                        cfg[k] = v
            cfg["_config_path"] = str(src)
        except Exception as e:
            raise RuntimeError(f"Impossible de lire {src}: {e}")
    else:
        cfg["_config_path"] = "(defaults)"

    # Validation douce
    if not cfg.get("agent_id"):
        cfg["agent_id"] = _hostname().lower().replace(" ", "-")[:64] or "host-01"
    if not cfg.get("server_url"):
        raise ValueError("server_url manquant — doit être l'IP LAN du serveur, ex: http://192.168.1.50:8001")
    if "localhost" in cfg["server_url"] or "127.0.0.1" in cfg["server_url"]:
        # Warning, not error — lab dev may use it, but document LAN
        cfg["_warn_localhost"] = True

    # Env overrides (CI/dev)
    for k in list(cfg.keys()):
        env_key = f"SENTINEL_{k.upper()}"
        if os.getenv(env_key):
            val = os.getenv(env_key)
            # coerce bool
            if val.lower() in ("true", "false", "1", "0", "yes", "no"):
                cfg[k] = val.lower() in ("true", "1", "yes")
            else:
                try:
                    cfg[k] = int(val)
                except ValueError:
                    cfg[k] = val
    return cfg


def save_config(cfg: dict, path: str) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Never write _internal keys
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
