"""F1 — Tâche Celery du sweep de rattrapage du moteur de règles."""
import logging

from ...core.celery import celery_app
from ...db import SessionLocal
from .engine import run_catch_up_sweep

logger = logging.getLogger(__name__)


@celery_app.task(name="jobs.rules.catch_up_sweep")
def catch_up_sweep_task(tenant_id: str = "default", since_minutes: int = 60):
    db = SessionLocal()
    try:
        report = run_catch_up_sweep(db, tenant_id, since_minutes)
        logger.info("Sweep règles terminé pour %s: %s", tenant_id, report)
        return report
    except Exception as e:
        logger.exception("Sweep règles échoué pour %s: %s", tenant_id, e)
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
