"""R3 — Dispatch des notifications : lecture DB + enqueue Celery (THIN).

Appelé depuis engine.evaluate_normalized_alert(). Ne fait AUCUN envoi réseau :
uniquement lecture des canaux + déduplication + rate limit + .delay().
"""
import json
import logging

from ...db import SessionLocal
from ...domain.models import NotificationChannel
from ...domain.rule_models import Rule
from .dedup import compute_fingerprint, is_duplicate
from .rate_limit import get_redis_client, is_rate_limited

logger = logging.getLogger(__name__)


def _wants_notify(rule) -> bool:
    """True si la règle a action_flags.notify=true."""
    try:
        flags = json.loads(rule.action_flags or "{}")
    except (TypeError, ValueError):
        flags = {}
    return bool(flags.get("notify"))


def dispatch_notifications(tenant_id: str, matched_rules: list,
                           normalized_alert: dict, event_id: str) -> int:
    """Enqueue une tâche Celery notifications.send par (règle notifiable × canal).

    Retourne le nombre de tâches enqueueées. Ne lève JAMAIS : les erreurs sont
    loggées et le pipeline d'ingestion continue.
    """
    if not matched_rules:
        return 0
    db = SessionLocal()
    enqueued = 0
    try:
        rule_ids = [r.get("rule_id") for r in matched_rules if r.get("rule_id")]
        if not rule_ids:
            return 0
        notify_rule_ids = {
            r.id for r in db.query(Rule).filter(Rule.id.in_(rule_ids)).all()
            if _wants_notify(r)
        }
        if not notify_rule_ids:
            return 0
        channels = (
            db.query(NotificationChannel)
            .filter(NotificationChannel.tenant_id == tenant_id,
                    NotificationChannel.enabled == True)  # noqa: E712
            .all()
        )
        if not channels:
            return 0
        r = get_redis_client()
        from ..jobs.notification_tasks import send_notification  # import local : léger

        for rule in matched_rules:
            if rule.get("rule_id") not in notify_rule_ids:
                continue
            fingerprint = compute_fingerprint(
                tenant_id,
                normalized_alert.get("src_ip"),
                normalized_alert.get("dest_ip"),
                normalized_alert.get("signature") or normalized_alert.get("description"),
                rule.get("rule_id"),
            )
            for channel in channels:
                try:
                    if is_duplicate(db, tenant_id, fingerprint, channel.id,
                                    channel.dedup_window_seconds):
                        continue
                    if is_rate_limited(r, channel.id, channel.rate_limit_per_minute):
                        continue
                    send_notification.delay(
                        channel_id=channel.id,
                        tenant_id=tenant_id,
                        event_id=event_id,
                        rule=rule,
                        normalized_alert=normalized_alert,
                    )
                    enqueued += 1
                except Exception as e:
                    logger.warning("Dispatch canal %s échoué: %s",
                                   getattr(channel, "id", "?"), e)
        return enqueued
    except Exception as e:
        logger.warning("Dispatch notifications échoué: %s", e)
        return 0
    finally:
        db.close()
