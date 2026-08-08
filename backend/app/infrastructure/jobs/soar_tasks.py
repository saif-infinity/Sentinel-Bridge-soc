"""F3 — Pompe de secours durable : rejoue l'outbox F1 (status pending) vers
l'exécuteur. La voie live (publish_sync) est principale ; ce beat est le filet
de sécurité (worker mort, catch-up, etc.). Le handler est idempotent
(UNIQUE(event_id, playbook_id)) : rejeu = no-op.
"""
import json
import logging

from ...application.events import RuleMatchEvent
from ...application.soar.executor import on_rule_match
from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.rule_models import RuleMatchOutbox

logger = logging.getLogger(__name__)

BATCH_SIZE = 100


@celery_app.task(name="jobs.soar.poll_rule_match_events")
def poll_rule_match_events():
    db = SessionLocal()
    processed = {"consumed": 0, "failed": 0}
    try:
        rows = (
            db.query(RuleMatchOutbox)
            .filter(RuleMatchOutbox.status == "pending")
            .order_by(RuleMatchOutbox.created_at)
            .limit(BATCH_SIZE)
            .all()
        )
        for row in rows:
            try:
                payload = json.loads(row.payload or "{}")
                event = RuleMatchEvent(**payload)          # champs du dataclass F1
                on_rule_match(row.channel or "rules.match", event)
                row.status = "consumed"
                processed["consumed"] += 1
            except Exception as e:
                logger.warning("Rejeu outbox %s échoué: %s", row.id, e)
                row.status = "failed"                      # colonne F1 : pas de champ erreur
                processed["failed"] += 1
            db.commit()
        return {"status": "ok", **processed}
    except Exception:
        logger.exception("Pompe outbox SOAR échouée")
        return {"status": "error"}
    finally:
        db.close()
