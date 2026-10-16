"""R3 — Envoi effectif des notifications (wrappers sync, sûrs en Celery --pool=solo).

Chaque fonction est synchrone et exécute sa coroutine dans un event loop frais
(asyncio.run) — compatible avec le pool solo de Celery (pas de loop actif).
"""
import asyncio
import logging

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 10.0


def _run(coro):
    """Exécute une coroutine dans un event loop neuf (sûr en pool solo)."""
    return asyncio.run(coro)


def send_email(config: dict, subject: str, body: str) -> bool:
    """Envoi SMTP via aiosmtplib.

    - use_tls=True  => SMTPS direct (port 465).
    - start_tls=True (défaut) => STARTTLS après connexion (port 587).
    - recipients : str ou liste (clés "recipients" / "to").
    """
    import aiosmtplib

    host = config.get("host", "localhost")
    port = int(config.get("port", 587))
    username = config.get("username")
    password = config.get("password_secret")
    use_tls = bool(config.get("use_tls", False))
    start_tls = bool(config.get("start_tls", True))
    sender = config.get("from") or username or "soc@localhost"
    recipients = config.get("recipients") or config.get("to")
    if isinstance(recipients, str):
        recipients = [recipients]
    if not recipients:
        logger.warning("send_email: aucun destinataire configuré")
        return False

    async def _send():
        smtp = aiosmtplib.SMTP(hostname=host, port=port, use_tls=use_tls)
        await smtp.connect()
        try:
            if start_tls and not use_tls:
                await smtp.starttls()
            if username:
                await smtp.login(username, password or "")
            message = (
                f"Subject: {subject}\r\n"
                f"From: {sender}\r\n"
                f"To: {', '.join(recipients)}\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
                f"{body}"
            )
            await smtp.sendmail(sender, recipients, message)
        finally:
            smtp.close()
        return True

    try:
        return _run(_send())
    except Exception as e:
        logger.warning("send_email échoué: %s", e)
        return False


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=5),
       reraise=True)
def _webhook_post(url: str, payload: dict, headers: dict | None) -> httpx.Response:
    with httpx.Client(timeout=HTTP_TIMEOUT) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp


def send_webhook(url: str, payload: dict, headers: dict | None = None) -> bool:
    """POST JSON sur un webhook générique, 3 tentatives (tenacity)."""
    if not url:
        logger.warning("send_webhook: URL manquante")
        return False
    try:
        _webhook_post(url, payload, headers)
        return True
    except Exception as e:
        logger.warning("send_webhook échoué après retries: %s", e)
        return False


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    """POST sur l'API Telegram Bot (sendMessage)."""
    if not token or not chat_id:
        logger.warning("send_telegram: token/chat_id manquant")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            resp = client.post(url, json={"chat_id": chat_id, "text": text})
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.warning("send_telegram échoué: %s", e)
        return False


def send_slack(webhook_url: str, text: str) -> bool:
    """POST sur un webhook Slack (Incoming Webhook)."""
    if not webhook_url:
        logger.warning("send_slack: webhook_url manquant")
        return False
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT) as client:
            resp = client.post(webhook_url, json={"text": text})
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.warning("send_slack échoué: %s", e)
        return False
