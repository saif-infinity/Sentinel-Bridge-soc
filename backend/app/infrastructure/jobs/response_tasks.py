"""F5 — Celery tasks for the response agent.

Includes worker-side subscriber registration at module import time.
"""
import logging
from datetime import UTC, datetime, timedelta

from ...application.system_config import get_config_value
from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.response import ResponseRun

logger = logging.getLogger(__name__)


@celery_app.task(name="jobs.response.execute_run")
def execute_run(run_id: int) -> dict:
    """Execute a ResponseRun."""
    from ...application.response.executor import execute_response_run
    return execute_response_run(run_id)


@celery_app.task(name="jobs.response.process_pending")
def process_pending() -> dict:
    """Process pending recommendations across all tenants."""
    db = SessionLocal()
    try:
        tenants = ["default"]
        try:
            from ...domain.models import Tenant
            tenants += [r[0] for r in db.query(Tenant.id).all() if r[0] not in tenants]
        except Exception:
            pass

        total = 0
        for tenant_id in tenants:
            try:
                from ...application.response.executor import process_pending_recommendations
                count = process_pending_recommendations(db, tenant_id=tenant_id, limit=50)
                total += count
            except Exception as e:
                logger.warning("process_pending for %s failed: %s", tenant_id, e)
        db.commit()
        return {"status": "ok", "processed": total}
    except Exception:
        logger.exception("process_pending failed")
        return {"status": "error"}
    finally:
        db.close()


@celery_app.task(name="jobs.response.retry_stuck")
def retry_stuck() -> dict:
    """Mark stuck response runs and recommendations."""
    db = SessionLocal()
    try:
        approval_timeout = int(get_config_value(db, "response", "approval_timeout_hours", "24", tenant_id="default")) * 60
        if approval_timeout < 10:
            approval_timeout = 60

        cutoff = datetime.now(UTC) - timedelta(minutes=approval_timeout)

        # Reject pending_approval runs older than timeout
        stuck_approval = db.query(ResponseRun).filter(
            ResponseRun.status == "pending_approval",
            ResponseRun.created_at < cutoff,
        ).all()
        for run in stuck_approval:
            run.status = "rejected"
            db.commit()

            # Dismiss the recommendation
            try:
                from ...domain.investigations import InvestigationRecommendation
                rec = db.query(InvestigationRecommendation).filter(
                    InvestigationRecommendation.id == run.recommendation_id,
                ).first()
                if rec:
                    rec.status = "dismissed"
                    rec.resolved_at = datetime.now(UTC)
                    db.commit()
            except Exception:
                db.rollback()

        # Fail running runs older than 30min
        stuck_running = db.query(ResponseRun).filter(
            ResponseRun.status == "running",
            ResponseRun.started_at < datetime.now(UTC) - timedelta(minutes=30),
        ).all()
        for run in stuck_running:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            db.commit()

        return {"status": "ok", "rejected": len(stuck_approval), "failed": len(stuck_running)}
    except Exception:
        logger.exception("retry_stuck failed")
        return {"status": "error"}
    finally:
        db.close()


# Worker-side subscriber registration
# The orchestrator runs in the Celery worker process.
# Bootstrap subscribers (in API process) never see investigation complete events.
def _register_worker_subscriber():
    """Register the on_investigation_complete handler on the Celery worker."""
    try:
        from ...application.events import CHANNEL_INVESTIGATION_COMPLETE, event_bus
        from ...application.response.handler import on_investigation_complete
        event_bus.subscribe(CHANNEL_INVESTIGATION_COMPLETE, on_investigation_complete)
        logger.info("Worker-side investigation complete subscriber registered")
    except Exception as e:
        logger.warning("Failed to register worker subscriber: %s", e)


_register_worker_subscriber()
