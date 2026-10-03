"""F5 — Thin sync subscriber for investigation trigger.

Reads config and dispatches via Celery .delay(). Never does heavy work.
"""
import logging

from ...application.events import CHANNEL_RULE_MATCH, RuleMatchEvent
from ...application.system_config import get_config_value
from ...db import SessionLocal
from ...core.celery import celery_app

logger = logging.getLogger(__name__)


def on_rule_match_investigate(channel: str, event: RuleMatchEvent) -> None:
    """Thin sync handler: check config gates and .delay() the Celery task."""
    if channel != CHANNEL_RULE_MATCH:
        return

    try:
        tenant_id = event.tenant_id or "default"
        db = SessionLocal()
        try:
            # Config gates
            enabled = get_config_value(db, "investigation", "enabled", "true", tenant_id=tenant_id)
            if enabled.lower() not in ("true", "1", "yes"):
                return

            # Severity gate
            min_sev = int(get_config_value(db, "investigation", "min_severity", "8", tenant_id=tenant_id))
            max_rule_sev = max(
                (int(r.get("rule_severity", 0)) for r in (event.matched_rules or []) if isinstance(r, dict)),
                default=0,
            )
            # Rules tagged "investigate" bypass the severity gate
            has_investigate_tag = any(
                "investigate" in (r.get("tags") or [])
                for r in (event.matched_rules or [])
                if isinstance(r, dict)
            )
            if not has_investigate_tag and max_rule_sev < min_sev:
                return
        finally:
            db.close()

        # Dispatch — thin: just .delay()
        from ...infrastructure.jobs.investigation_tasks import run_investigation
        run_investigation.delay(event_id=event.event_id, tenant_id=tenant_id)
    except Exception as e:
        logger.warning("Investigation dispatch failed for %s: %s", getattr(event, "event_id", "?"), e)