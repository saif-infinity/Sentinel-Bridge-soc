"""F3 — Mini-SOAR : exécuteur de playbooks, consommateur du contrat F1.

Contrat consommé (F1, lecture seule) :
  - CHANNEL_RULE_MATCH / RuleMatchEvent / event_bus  (app.application.events)
  - RuleMatchOutbox  (app.domain.rule_models) — status pending|consumed|failed

Le handler est SYNCHRONE (F1 publish_sync invoque les handlers sync en ligne).
Les runs approuvés s'exécutent dans un thread daemon (jamais dans le event loop
ni dans le request cycle). Idempotence : UNIQUE(event_id, playbook_id) + garde
par requête AVANT insert (double-dispatch pompe/live impossible).
"""
import base64
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict

import httpx
from sqlalchemy import or_

from ...application.events import CHANNEL_RULE_MATCH, RuleMatchEvent
from ...application.system_config import get_config_value
from ...db import SessionLocal
from ...domain.soar import Playbook, PlaybookRun, PlaybookStepResult
from ...infrastructure.wazuh.ssl_context import ssl_ctx

logger = logging.getLogger(__name__)

# Allowlist stricte — jamais d'exécution arbitraire
ALLOWED_TASKS = {"reload_suricata", "run_nmap"}


def _render(template: str, ctx: Dict[str, str]) -> str:
    """Rendu {{placeholder}} depuis le snapshot normalized_alert.

    Convention UI : double accolades. Conversion {{x}} -> {x} puis str.format_map
    (template inconnu => placeholder conservé tel quel, jamais d'exception)."""
    if not template:
        return template
    try:
        return template.replace("{{", "{").replace("}}", "}").format_map(_SafeDict(ctx))
    except (KeyError, ValueError):
        return template


class _SafeDict(dict):
    def __missing__(self, key):
        return "{{" + key + "}}"


def _matches_trigger(playbook: Playbook, event: RuleMatchEvent) -> bool:
    sources = playbook.trigger_sources or []
    if sources and event.source not in sources:
        return False
    rule_ids = playbook.trigger_rule_ids or []
    matched_ids = {
        r.get("rule_id") for r in (event.matched_rules or []) if isinstance(r, dict)
    }
    if rule_ids and not (set(rule_ids) & matched_ids):
        return False
    min_sev = playbook.trigger_min_severity
    if min_sev is not None:
        sev = max(
            (int(r.get("rule_severity") or 0) for r in (event.matched_rules or []) if isinstance(r, dict)),
            default=0,
        )
        if sev < min_sev:
            return False
    return True


def _soar_enabled(db, tenant_id: str) -> bool:
    return get_config_value(db, "soar", "enabled", "true", tenant_id=tenant_id).lower() in ("true", "1", "yes")


def _runs_today(db, tenant_id: str) -> int:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return db.query(PlaybookRun.id).filter(
        PlaybookRun.tenant_id == tenant_id, PlaybookRun.created_at >= start
    ).count()


def on_rule_match(channel: str, event: RuleMatchEvent) -> None:
    """Handler SYNC abonné à CHANNEL_RULE_MATCH (event_bus.publish_sync).

    Garde anti-double-dispatch : un run existe déjà pour event_id ? -> return.
    """
    if channel != CHANNEL_RULE_MATCH:
        return

    db = SessionLocal()
    try:
        tenant_id = event.tenant_id or "default"
        if not _soar_enabled(db, tenant_id):
            return

        existing = db.query(PlaybookRun.id).filter(PlaybookRun.event_id == event.event_id).first()
        if existing:
            logger.info("Event %s déjà traité — dispatch ignoré", event.event_id)
            return

        playbooks = (
            db.query(Playbook)
            .filter(Playbook.enabled.is_(True), or_(Playbook.tenant_id.is_(None), Playbook.tenant_id == tenant_id))
            .all()
        )
        matched = [p for p in playbooks if _matches_trigger(p, event)]
        if not matched:
            return

        max_daily = int(float(get_config_value(db, "soar", "max_runs_per_day", "50", tenant_id=tenant_id)))
        budget = max_daily - _runs_today(db, tenant_id)
        if budget <= 0:
            logger.warning("Quota SOAR atteint pour %s (%d/jour)", tenant_id, max_daily)
            return

        for playbook in matched[:budget]:
            requires_approval = playbook.requires_approval or (
                get_config_value(db, "soar", "requires_approval", "false", tenant_id=tenant_id).lower() == "true"
            )
            rule_id = None
            if event.matched_rules and isinstance(event.matched_rules[0], dict):
                rule_id = event.matched_rules[0].get("rule_id")

            run = PlaybookRun(
                playbook_id=playbook.id,
                event_id=event.event_id,
                tenant_id=tenant_id,
                triggered_by=rule_id,
                event_payload=event.normalized_alert if isinstance(event.normalized_alert, dict) else {},
                status="pending_approval" if requires_approval else "approved",
            )
            db.add(run)
            try:
                db.commit()
            except Exception:
                db.rollback()
                logger.warning("Run dupliqué (event %s, playbook %s) — ignoré", event.event_id, playbook.id)
                continue

            if not requires_approval:
                threading.Thread(target=execute_playbook, args=(run.id,), daemon=True).start()
    except Exception:
        logger.exception("on_rule_match échoué (event %s)", getattr(event, "event_id", "?"))
    finally:
        db.close()


def _base_context(run: PlaybookRun, step_index: int) -> Dict[str, str]:
    payload = run.event_payload or {}
    ctx = {str(k): str(v) for k, v in payload.items() if v is not None}
    ctx.update({
        "tenant_id": run.tenant_id,
        "event_id": run.event_id,
        "rule_id": run.triggered_by or "",
        "playbook_id": str(run.playbook_id),
        "run_id": str(run.id),
        "step_index": str(step_index),
    })
    return ctx


def execute_playbook(run_id: int) -> None:
    """Exécute les steps d'un run approuvé (thread daemon)."""
    db = SessionLocal()
    try:
        run = db.query(PlaybookRun).get(run_id)
        if run is None:
            return
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        db.commit()

        steps = (run.playbook.steps or []) if run.playbook else []
        max_steps = int(float(get_config_value(db, "soar", "max_steps_per_run", "10", tenant_id=run.tenant_id)))
        default_timeout = int(float(
            get_config_value(db, "soar", "default_timeout_seconds", "30", tenant_id=run.tenant_id)
        ))

        for idx, step in enumerate(steps[:max_steps]):
            run.current_step_index = idx
            db.commit()
            started = time.monotonic()
            result = _run_step(db, run, idx, step, default_timeout)
            duration_ms = int((time.monotonic() - started) * 1000)
            db.add(PlaybookStepResult(
                run_id=run.id,
                step_index=idx,
                step_type=step.get("type", "unknown"),
                status=result["status"],
                output=json.dumps(result.get("output", {}), default=str),
                error=result.get("error"),
                duration_ms=duration_ms,
            ))
            db.commit()
            if result["status"] == "failed":
                run.status = "failed"
                break
        else:
            run.status = "success"
        run.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        logger.exception("Exécution playbook %s échouée", run_id)
        try:
            run = db.query(PlaybookRun).get(run_id)
            if run:
                run.status = "failed"
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
    finally:
        db.close()


def _run_step(db, run: PlaybookRun, idx: int, step: Dict[str, Any], default_timeout: int) -> Dict[str, Any]:
    step_type = step.get("type")
    params = step.get("params") or {}
    timeout = int(step.get("timeout_seconds") or default_timeout)
    ctx = _base_context(run, idx)

    try:
        if step_type == "notify":
            from ...application.action_logger import log_action
            message = _render(params.get("message", ""), ctx)
            log_action(db, username="soar", action="playbook.notify", details=message,
                       resource=f"run:{run.id}", tenant_id=run.tenant_id)
            return {"status": "success", "output": {"message": message}}

        if step_type == "log":
            message = _render(params.get("message", ""), ctx)
            logger.info("[PLAYBOOK run=%s] %s", run.id, message)
            return {"status": "success", "output": {"logged": message}}

        if step_type == "sleep":
            time.sleep(min(timeout, 60))
            return {"status": "success", "output": {"slept_seconds": timeout}}

        if step_type == "run_task":
            return _run_task(db, run, params, ctx)

        if step_type == "block_ip":
            return _block_ip(db, run, params, ctx)

        return {"status": "failed", "error": "type de step inconnu: %s" % step_type}
    except Exception as e:
        logger.exception("Step %d du run %s échoué", idx, run.id)
        return {"status": "failed", "error": str(e)}


def _run_task(db, run: PlaybookRun, params: Dict[str, Any], ctx: Dict[str, str]) -> Dict[str, Any]:
    task_name = params.get("task")
    if task_name not in ALLOWED_TASKS:
        return {"status": "failed", "error": "tâche non autorisée: %s" % task_name}

    if task_name == "reload_suricata":
        # À CONFIRMER à l'implémentation : signature exacte du service Suricata
        # (app/application/suricata/...). Import lazy + échec gracieux.
        from ...application.suricata.service import suricata_service
        result = suricata_service.reload_ruleset()
        return {"status": "success", "output": {"reloaded": True, "detail": str(result)}}

    if task_name == "run_nmap":
        from ...infrastructure.jobs.nmap_tasks import run_nmap_task
        target = _render(params.get("target", ""), ctx)
        if hasattr(run_nmap_task, "delay"):
            run_nmap_task.delay(target=target, tenant_id=run.tenant_id)
            return {"status": "success", "output": {"dispatched": True, "target": target}}
        return {"status": "failed", "error": "run_nmap_task indisponible"}

    return {"status": "failed", "error": "tâche inconnue: %s" % task_name}


def _wazuh_token(base: str, user: str, password: str) -> str:
    auth_b64 = base64.b64encode(f"{user}:{password}".encode()).decode()
    with httpx.Client(verify=ssl_ctx, timeout=10.0) as client:
        r = client.get(
            f"{base.rstrip('/')}/security/user/authenticate",
            headers={"Authorization": f"Basic {auth_b64}"},
        )
        r.raise_for_status()
        return r.json()["data"]["token"]


def _block_ip(db, run: PlaybookRun, params: Dict[str, Any], ctx: Dict[str, str]) -> Dict[str, Any]:
    """Blocage actif : POST /active-response de l'API Wazuh (token Bearer).

    WazuhAPIClient (F1) n'expose AUCUNE méthode active-response (vérifié) —
    appel direct, même transport (ssl_ctx) et même auth (token) que le client.
    """
    ip = _render(params.get("ip", "{{src_ip}}"), ctx)
    agent_id = params.get("agent_id") or ctx.get("agent_id") or "000"
    base = get_config_value(db, "wazuh_api", "base_url", "https://localhost:55000", tenant_id=run.tenant_id)
    user = get_config_value(db, "wazuh_api", "user", "wazuh", tenant_id=run.tenant_id)
    password = get_config_value(db, "wazuh_api", "password", "", tenant_id=run.tenant_id)

    token = _wazuh_token(base, user, password)
    payload = {
        "command": "add",
        "arguments": ["-", ip, "block"],
        "alert": {"data": {"srcip": ip}},
        "agents": [{"id": agent_id}],
    }
    with httpx.Client(verify=ssl_ctx, timeout=15.0) as client:
        resp = client.post(
            f"{base.rstrip('/')}/active-response",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
    return {"status": "success", "output": {"blocked": ip, "agent_id": agent_id, "http": resp.status_code}}
