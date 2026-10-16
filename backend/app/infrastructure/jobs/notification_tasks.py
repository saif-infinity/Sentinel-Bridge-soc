"""R3 — Tâche Celery d'envoi de notification (notifications.send).

Charge le canal, vérifie le tenant, déchiffre la config, formate l'alerte et
appelle le sender adapté. Log un warning après 5 échecs consécutifs.
"""
import logging

from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.models import NotificationChannel
from ..notifications.crypto import decrypt_config
from ..notifications.senders import send_email, send_slack, send_telegram, send_webhook

logger = logging.getLogger(__name__)

FAILURE_THRESHOLD = 5
_consecutive_failures = 0


def _format_alert(rule: dict, normalized_alert: dict) -> tuple[str, str]:
    """Sujet + corps du message (signature, sévérité, src_ip, description)."""
    signature = (
        normalized_alert.get("signature")
        or normalized_alert.get("description")
        or rule.get("rule_name")
        or "Alerte SOC"
    )
    severity = (
        normalized_alert.get("normalized_severity")
        or normalized_alert.get("severity")
        or rule.get("rule_severity")
        or 5
    )
    src_ip = normalized_alert.get("src_ip") or "inconnu"
    description = (
        normalized_alert.get("description")
        or normalized_alert.get("signature")
        or ""
    )
    subject = f"[SOC] {signature} (sévérité {severity})"
    body = (
        f"Alerte SOC — {signature}\n"
        f"Sévérité : {severity}\n"
        f"IP source : {src_ip}\n"
        f"Règle : {rule.get('rule_name', '')}\n"
        f"Description : {description}\n"
    )
    return subject, body


def _send(channel_type: str, config: dict, subject: str, body: str) -> bool:
    """Route vers le sender adapté selon channel_type."""
    if channel_type == "email":
        return send_email(config, subject, body)
    if channel_type == "webhook":
        return send_webhook(config.get("url", ""),
                            {"subject": subject, "text": body},
                            config.get("headers"))
    if channel_type == "telegram":
        return send_telegram(config.get("token_secret", ""),
                             config.get("chat_id", ""), body)
    if channel_type == "slack":
        return send_slack(config.get("webhook_url", ""), body)
    logger.warning("notifications.send: type de canal inconnu '%s'", channel_type)
    return False


@celery_app.task(name="notifications.send")
def send_notification(channel_id: int, tenant_id: str, event_id: str,
                      rule: dict, normalized_alert: dict):
    global _consecutive_failures
    db = SessionLocal()
    try:
        channel = (
            db.query(NotificationChannel)
            .filter(NotificationChannel.id == channel_id)
            .first()
        )
        if channel is None:
            logger.warning("notifications.send: canal %s introuvable", channel_id)
            return {"status": "error", "reason": "channel_not_found"}
        if channel.tenant_id != tenant_id:
            logger.warning("notifications.send: tenant mismatch canal %s", channel_id)
            return {"status": "error", "reason": "tenant_mismatch"}
        config = decrypt_config(channel.config)
        subject, body = _format_alert(rule, normalized_alert)
        ok = _send(channel.channel_type, config, subject, body)
        if ok:
            _consecutive_failures = 0
            return {"status": "ok", "channel_id": channel_id, "event_id": event_id}
        _consecutive_failures += 1
        if _consecutive_failures >= FAILURE_THRESHOLD:
            logger.warning(
                "notifications.send: %d échecs consécutifs — vérifier les canaux",
                _consecutive_failures,
            )
        return {"status": "error", "channel_id": channel_id, "event_id": event_id}
    except Exception as e:
        _consecutive_failures += 1
        logger.warning("notifications.send canal %s échoué: %s", channel_id, e)
        return {"status": "error", "channel_id": channel_id, "message": str(e)}
    finally:
        db.close()
