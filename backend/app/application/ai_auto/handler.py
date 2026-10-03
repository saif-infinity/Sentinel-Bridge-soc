"""F5 — Handler de CHANNEL_ALERT_INGESTED : déclenche l'auto-analyse IA.

SYNCHRONE (comme on_rule_match) — ne doit jamais bloquer le pipeline :
  - lit la config ai_auto (tenant) ; `enabled=false` → no-op immédiat.
  - ignore les événements sans agent_id.
  - délègue à la tâche Celery jobs.ai_alert_burst si le broker est joignable,
    sinon exécution inline dans un thread daemon (motif F3).
Ne lève jamais d'exception (le bus journalise et continue).
"""
import logging
import threading

logger = logging.getLogger(__name__)


def _db_count_quick():
    # Import différé pour éviter tout cycle au chargement du module.
    from ...db import SessionLocal
    return SessionLocal()


def on_alert_ingested(channel: str, event: dict) -> None:
    """Handler SYNC abonné à CHANNEL_ALERT_INGESTED (event_bus.publish_local)."""
    try:
        from ...core.config import settings
        from ..system_config import get_config_value
        from .service import load_ai_auto_config

        tenant_id = str(event.get("tenant_id") or "default")
        agent_id = event.get("agent_id")
        if not agent_id:
            return

        db = _db_count_quick()
        try:
            cfg = load_ai_auto_config(db, tenant_id)
            if not cfg["enabled"]:
                return
            # Seuil : le nombre d'alertes du burst dépassé → déclenchement.
            from .service import collect_recent_alerts

            rows = collect_recent_alerts(
                db, tenant_id, str(agent_id),
                severity_min=cfg["severity_min"],
                window_minutes=cfg["window_minutes"],
                limit=cfg["send_count"],
            )
            if len(rows) < int(cfg["threshold"]):
                return

            # Single-flight : analyse déjà en cours pour cet agent ?
            from ...domain.models import AgentAiAnalysis

            running = (
                db.query(AgentAiAnalysis)
                .filter(
                    AgentAiAnalysis.tenant_id == tenant_id,
                    AgentAiAnalysis.agent_id == str(agent_id),
                    AgentAiAnalysis.status == "running",
                )
                .first()
            )
            if running is not None:
                return
        finally:
            db.close()

        _dispatch_analysis(str(agent_id), tenant_id)
    except Exception as e:
        logger.warning("ai_auto: handler on_alert_ingested échoué (non bloquant): %s", e)


def _dispatch_analysis(agent_id: str, tenant_id: str) -> None:
    """Tente Celery ; sinon thread daemon inline (faille douce si broker absent)."""
    try:
        from ...infrastructure.jobs.ai_alert_burst import ai_alert_burst_task

        ai_alert_burst_task.delay(agent_id, tenant_id)
        return
    except Exception:
        # Broker injoignable (pas de Redis) → exécution locale non bloquante.
        try:
            from ...application.ai_auto.service import run_agent_burst_analysis

            threading.Thread(
                target=run_agent_burst_analysis,
                args=(agent_id, tenant_id),
                daemon=True,
                name=f"ai-auto-{tenant_id}-{agent_id}",
            ).start()
        except Exception as e:
            logger.error("ai_auto: dispatch inline échoué: %s", e)