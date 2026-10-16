"""F5 — Response Agent action registry.

Design: an ACTIONS dict registry — each entry maps action_type to handler metadata.
All action handlers are registered at module import time.
"""
import logging
import threading
from collections.abc import Callable

from ...application.system_config import get_config_value
from ...domain.investigations import Investigation
from ...domain.models import Case, NotificationChannel
from ...domain.response import ResponseRun
from ...infrastructure.notifications.crypto import decrypt_config
from ...infrastructure.notifications.senders import send_email, send_telegram, send_webhook
from ...infrastructure.response.actions import (
    wazuh_block,
    wazuh_isolate_agent,
    wazuh_unblock,
)
from ...infrastructure.response.ssh_actions import quarantine_file, restart_service, unquarantine_file

logger = logging.getLogger(__name__)

ActionHandler = Callable[..., tuple[bool, dict | None, str | None]]

ACTIONS: dict = {}


def register(action_type: str, *, handler: ActionHandler, requires_approval: bool,
             timeout_seconds: int, inverse: str | None, implemented: bool) -> None:
    ACTIONS[action_type] = {
        "handler": handler,
        "requires_approval": requires_approval,
        "timeout_seconds": timeout_seconds,
        "inverse": inverse,
        "implemented": implemented,
    }


def get_action(action_type: str) -> dict | None:
    return ACTIONS.get(action_type)


def _notify_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    try:
        tenant_id = run.tenant_id or "default"
        db.flush()
        channel = db.query(NotificationChannel).filter(
            NotificationChannel.tenant_id == tenant_id,
            NotificationChannel.enabled.is_(True),
        ).first()
        if channel:
            cfg = decrypt_config(channel.config)
            subject = f"[SOC] Response action: {run.action_type}"
            body = f"Action {run.action_type} executed on investigation {run.investigation_id}"
            if channel.channel_type == "email":
                send_email(cfg, subject, body)
            elif channel.channel_type == "slack":
                send_webhook(cfg.get("webhook_url", ""), {"text": body})
            elif channel.channel_type == "telegram":
                send_telegram(cfg.get("token_secret", ""), cfg.get("chat_id", ""), body)
            elif channel.channel_type == "webhook":
                send_webhook(cfg.get("url", ""), {"subject": subject, "text": body})
        return True, {"notified": True, "action": "notify"}, None
    except Exception as e:
        return False, None, str(e)


def _monitor_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    return True, {"note": "monitoring recommended"}, None


def _escalate_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    try:
        inv_id = run.investigation_id
        if inv_id:
            inv = db.query(Investigation).filter(Investigation.id == inv_id).first()
            if inv and inv.case_id:
                case = db.query(Case).filter(Case.id == inv.case_id).first()
                if case:
                    case.severity = min(15, case.severity + 1)
        return True, {"escalated": True, "case_severity_bumped": True}, None
    except Exception as e:
        return False, None, str(e)


def _block_ip_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    target = run.target or params.get("ip")
    if not target:
        return False, None, "no target IP specified"
    return wazuh_block(db, target)


def _unblock_ip_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    target = run.target or params.get("ip")
    if not target:
        return False, None, "no target IP specified"
    return wazuh_unblock(db, target)


def _isolate_agent_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    target = run.target or params.get("agent_id")
    if not target:
        return False, None, "no agent_id specified"
    return wazuh_isolate_agent(db, target, isolate=True)


def _restore_agent_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    target = run.target or params.get("agent_id")
    if not target:
        return False, None, "no agent_id specified"
    return wazuh_isolate_agent(db, target, isolate=False)


def _quarantine_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    quarantine_dir = get_config_value(db, "response", "quarantine_dir", "/var/quarantine", tenant_id=run.tenant_id or "default")
    target = run.target or params.get("path")
    if not target:
        return False, None, "no file path specified"
    return quarantine_file(db, run.tenant_id or "default", host="localhost", path=target, quarantine_dir=quarantine_dir)


def _unquarantine_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    original_path = run.target or params.get("original_path")
    quarantine_path = params.get("quarantine_path")
    expected_sha256 = params.get("sha256") or params.get("expected_sha256")
    if not original_path or not quarantine_path or not expected_sha256:
        return False, None, "missing quarantine metadata for rollback"
    return unquarantine_file(
        db, run.tenant_id or "default", host="localhost",
        original_path=original_path, quarantine_path=quarantine_path,
        expected_sha256=expected_sha256,
    )


def _restart_service_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    target = run.target or params.get("service")
    if not target:
        return False, None, "no service specified"
    return restart_service(db, run.tenant_id or "default", host="localhost", service=target)


def _run_playbook_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    try:
        from ...domain.soar import Playbook, PlaybookRun
        playbook_id = params.get("playbook")
        if isinstance(playbook_id, int):
            playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        else:
            playbook = db.query(Playbook).filter(Playbook.name == str(playbook_id)).first()
        if playbook is None:
            return False, None, "playbook not found"
        run_id = run.id
        synthetic_event_id = f"resp:{run_id}"
        pb_run = PlaybookRun(
            playbook_id=playbook.id,
            event_id=synthetic_event_id,
            tenant_id=run.tenant_id or "default",
            triggered_by="response_agent",
            event_payload=params or {},
            status="approved" if not playbook.requires_approval else "pending_approval",
        )
        db.add(pb_run)
        db.flush()
        if not playbook.requires_approval:
            from ...application.soar.executor import execute_playbook
            threading.Thread(target=execute_playbook, args=(pb_run.id,), daemon=True).start()
        db.commit()
        return True, {"playbook_run_id": pb_run.id, "event_id": synthetic_event_id}, None
    except Exception as e:
        return False, None, str(e)


def _firewall_acl_handler(db, run: ResponseRun, params: dict) -> tuple[bool, dict | None, str | None]:
    return False, None, "not_implemented"


register("notify", handler=_notify_handler, requires_approval=False, timeout_seconds=10, inverse=None, implemented=True)
register("monitor", handler=_monitor_handler, requires_approval=False, timeout_seconds=5, inverse=None, implemented=True)
register("escalate", handler=_escalate_handler, requires_approval=False, timeout_seconds=10, inverse=None, implemented=True)
register("block_ip", handler=_block_ip_handler, requires_approval=True, timeout_seconds=15, inverse="unblock_ip", implemented=True)
register("unblock_ip", handler=_unblock_ip_handler, requires_approval=False, timeout_seconds=15, inverse=None, implemented=True)
register("isolate_agent", handler=_isolate_agent_handler, requires_approval=True, timeout_seconds=15, inverse="restore_agent", implemented=True)
register("restore_agent", handler=_restore_agent_handler, requires_approval=False, timeout_seconds=15, inverse=None, implemented=True)
register("quarantine", handler=_quarantine_handler, requires_approval=True, timeout_seconds=15, inverse="unquarantine_file", implemented=True)
register("unquarantine_file", handler=_unquarantine_handler, requires_approval=False, timeout_seconds=15, inverse=None, implemented=True)
register("restart_service", handler=_restart_service_handler, requires_approval=True, timeout_seconds=30, inverse=None, implemented=True)
register("run_playbook", handler=_run_playbook_handler, requires_approval=False, timeout_seconds=60, inverse=None, implemented=True)
register("firewall_acl", handler=_firewall_acl_handler, requires_approval=True, timeout_seconds=10, inverse="unapply_acl", implemented=False)
