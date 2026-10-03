"""F5 — Tâche Celery d'auto-analyse IA (burst par agent).

Le cœur vit dans application/ai_auto/service.py ; ce module enregistre la
tâche jobs.ai_alert_burst sur celery_app et ré-exporte le runner pour le
point d'entrée API (interface/api/ai_auto.py).
"""
import logging

from ...core.celery import celery_app
from ...application.ai_auto.service import run_agent_burst_analysis  # noqa: F401  # ré-export

logger = logging.getLogger(__name__)


@celery_app.task(name="jobs.ai_alert_burst")
def ai_alert_burst_task(agent_id: str, tenant_id: str = "default"):
    """Analyse IA d'un burst d'alertes sur un agent (appelé aussi en inline)."""
    try:
        return run_agent_burst_analysis(agent_id, tenant_id)
    except Exception as e:
        logger.error("jobs.ai_alert_burst échoué agent=%s: %s", agent_id, e)
        return {"status": "error", "error": str(e)[:200]}