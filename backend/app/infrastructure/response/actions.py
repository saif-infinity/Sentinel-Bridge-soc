"""F5 — Response Agent infrastructure actions.

Extracted Wazuh API + active-response actions. SSH actions live in ssh_actions.py.
"""
import base64
import logging
from typing import Any, Dict, Optional, Tuple

import httpx

from ...infrastructure.wazuh.ssl_context import ssl_ctx
from ...config import settings
from ...application.system_config import get_config_value
from ...db import SessionLocal

logger = logging.getLogger(__name__)


def wazuh_token(base: str, user: str, password: str) -> str:
    """Get Wazuh API token (sync, reused from executor.py)."""
    auth_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    with httpx.Client(verify=ssl_ctx, timeout=10.0) as client:
        r = client.get(
            f"{base.rstrip('/')}/security/user/authenticate",
            headers={"Authorization": f"Basic {auth_b64}"},
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


def wazuh_active_response(db, base: str, ip: str, action: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Execute Wazuh active-response command. action='add'|'remove'."""
    user = get_config_value(db, "wazuh_api", "user", "wazuh")
    password = get_config_value(db, "wazuh_api", "password", "")
    token = wazuh_token(base, user, password)
    cmd = "add" if action == "add" else "remove"
    payload = {
        "command": cmd,
        "arguments": ["-", ip, "block"],
        "alert": {"data": {"srcip": ip}},
    }
    try:
        with httpx.Client(verify=ssl_ctx, timeout=15.0) as client:
            resp = client.post(
                f"{base.rstrip('/')}/active-response",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return True, {"blocked": ip, "http": resp.status_code}, None
    except Exception as e:
        return False, None, str(e)


def wazuh_block(db, ip: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Block an IP via Wazuh active-response."""
    base = get_config_value(db, "wazuh_api", "base_url", "https://localhost:55000")
    return wazuh_active_response(db, base, ip, "add")


def wazuh_unblock(db, ip: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Unblock an IP via Wazuh active-response."""
    base = get_config_value(db, "wazuh_api", "base_url", "https://localhost:55000")
    return wazuh_active_response(db, base, ip, "remove")


def wazuh_isolate_agent(db, agent_id: str, isolate: bool = True) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """Isolate or restore a Wazuh agent.

    Primary: Wazuh API endpoint PUT/DELETE /agents/{id}/isolation (per design).
    Fallback: active-response commands isolate-wazuh / restore-wazuh.
    """
    base = get_config_value(db, "wazuh_api", "base_url", "https://localhost:55000")
    try:
        token = wazuh_token(base, get_config_value(db, "wazuh_api", "user", "wazuh"), get_config_value(db, "wazuh_api", "password", ""))
        with httpx.Client(verify=ssl_ctx, timeout=15.0) as client:
            url = f"{base.rstrip('/')}/agents/{agent_id}/isolation"
            if isolate:
                resp = client.put(url, headers={"Authorization": f"Bearer {token}"})
            else:
                resp = client.delete(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code in (200, 201, 204):
                return True, {"isolated": isolate, "agent_id": agent_id, "method": "api"}, None
    except Exception as e:
        logger.warning("Wazuh isolation API failed (%s), falling back to active-response", e)

    # Fallback: active-response
    cmd = "isolate-wazuh" if isolate else "restore-wazuh"
    try:
        token = wazuh_token(base, get_config_value(db, "wazuh_api", "user", "wazuh"), get_config_value(db, "wazuh_api", "password", ""))
        with httpx.Client(verify=ssl_ctx, timeout=15.0) as client:
            resp = client.post(
                f"{base.rstrip('/')}/active-response",
                json={"command": cmd, "arguments": ["-", agent_id]},
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return True, {"isolated": isolate, "agent_id": agent_id, "method": "active_response"}, None
    except Exception as e:
        return False, None, str(e)


def ssh_connect(host: str, port: int, user: str, password: str):
    """Create a paramiko SSH client connection."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=10, banner_timeout=200, look_for_keys=False, allow_agent=False)
    return client