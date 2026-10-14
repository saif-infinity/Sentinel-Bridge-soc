"""F5 — Celery tasks for automated investigation.

- jobs.investigation.run_investigation: main entry point
- jobs.investigation.backfill_uninvestigated: periodic backfill
- jobs.investigation.retry_stuck: retry stuck running investigations
"""
import json
import logging
from datetime import UTC, datetime, timedelta

from ...application.system_config import get_config_value
from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.investigations import Investigation
from ...domain.rule_models import RuleMatchOutbox

logger = logging.getLogger(__name__)


@celery_app.task(name="jobs.investigation.run_investigation", queue="investigation")
def run_investigation(event_id: str, tenant_id: str) -> dict:
    """Run investigation for a RuleMatchEvent (called from Celery)."""
    from ...application.investigations.orchestrator import run_investigation_for_event
    return run_investigation_for_event(event_id, tenant_id)


@celery_app.task(name="jobs.investigation.backfill_uninvestigated", queue="celery")
def backfill_uninvestigated() -> dict:
    """Backfill: find rule_match_events not referenced by any investigation.

    Uses LEFT JOIN on the payload — NEVER marks rows consumed, NEVER touches status column.
    Re-checks severity gate before enqueuing.
    """
    db = SessionLocal()
    try:
        since_hours = int(get_config_value(db, "investigation", "dedup_window_hours", "24", tenant_id="default"))
        cutoff = datetime.now(UTC) - timedelta(hours=since_hours)

        # Find outbox events not linked to any investigation, within dedup window
        rows = (
            db.query(RuleMatchOutbox)
            .outerjoin(Investigation, Investigation.event_id == RuleMatchOutbox.event_id)
            .filter(Investigation.id.is_(None))
            .filter(RuleMatchOutbox.created_at >= cutoff)
            .filter(RuleMatchOutbox.status == "pending")
            .order_by(RuleMatchOutbox.created_at)
            .limit(50)
            .all()
        )

        enqueued = 0
        for row in rows:
            try:
                payload = json.loads(row.payload or "{}")
                tenant_id = payload.get("tenant_id", "default")
                matched_rules = payload.get("matched_rules", [])

                # Re-check severity gate
                min_sev = int(get_config_value(db, "investigation", "min_severity", "8", tenant_id=tenant_id))
                max_rule_sev = max(
                    (int(r.get("rule_severity", 0)) for r in matched_rules if isinstance(r, dict)),
                    default=0,
                )
                if max_rule_sev < min_sev:
                    continue

                from ...core.celery import celery_app
                celery_app.send_task("jobs.investigation.run_investigation", args=[row.event_id, tenant_id])
                enqueued += 1
            except Exception as e:
                logger.warning("Backfill event %s failed: %s", row.event_id, e)

        db.commit()
        return {"status": "ok", "enqueued": enqueued, "checked": len(rows)}
    except Exception:
        logger.exception("Backfill uninvestigated failed")
        return {"status": "error"}
    finally:
        db.close()


@celery_app.task(name="jobs.investigation.retry_stuck", queue="celery")
def retry_stuck() -> dict:
    """Mark investigations status='running' older than N minutes as failed."""
    db = SessionLocal()
    try:
        stuck_minutes = 60  # default
        try:
            cfg = get_config_value(db, "investigation", "dedup_window_hours", "24", tenant_id="default")
            cfg_minutes = int(cfg) * 60
            if cfg_minutes >= 10:
                stuck_minutes = cfg_minutes
        except (ValueError, TypeError):
            pass

        cutoff = datetime.now(UTC) - timedelta(minutes=stuck_minutes)
        stuck = db.query(Investigation).filter(
            Investigation.status == "running",
            Investigation.updated_at < cutoff,
        ).all()

        marked = 0
        for inv in stuck:
            inv.status = "failed"
            inv.missing_steps = json.dumps(["timeout"])
            inv.completed_at = datetime.now(UTC)
            marked += 1

        db.commit()
        return {"status": "ok", "marked_failed": marked}
    except Exception:
        logger.exception("Retry stuck investigations failed")
        return {"status": "error"}
    finally:
        db.close()
