"""F5 — Reporting Subsystem : report delivery.

Handles sending reports to recipients via email/webhook/telegram/slack.
"""
import json
import logging
from datetime import UTC, datetime

from ...application.system_config import get_config_value
from ...db import SessionLocal
from ...domain.reporting import Report, ReportLog, ReportRecipient
from ...infrastructure.notifications.senders import send_email, send_slack, send_telegram, send_webhook

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _get_channel_config(db, tenant_id: str, channel: str) -> dict | None:
    """Read channel configuration from SystemConfig."""
    section = f"report_{channel}"
    config_value = get_config_value(db, section, "config", tenant_id=tenant_id)
    if config_value:
        try:
            return json.loads(config_value)
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def send_report(report_id: int, tenant_id: str, channel: str = "email") -> bool:
    """Send a generated report to recipients via the specified channel.

    Returns True if at least one recipient was successfully notified.
    """
    db = SessionLocal()
    try:
        report = db.query(Report).filter(
            Report.id == report_id, Report.tenant_id == tenant_id
        ).first()
        if report is None:
            logger.warning("Report %s not found", report_id)
            return False
        if report.content is None and report.file_path is None:
            logger.warning("Report %s has no content", report_id)
            return False

        # Find recipients for this report
        recipients = db.query(ReportRecipient).filter(
            ReportRecipient.report_id == report_id,
            ReportRecipient.tenant_id == tenant_id,
        ).all()

        if not recipients:
            # Try to find schedule-based recipients
            if report.schedule_id:
                recipients = db.query(ReportRecipient).filter(
                    ReportRecipient.schedule_id == report.schedule_id,
                    ReportRecipient.tenant_id == tenant_id,
                ).all()

        if not recipients:
            logger.info("No recipients for report %s, sending to default", report_id)
            default_dest = get_config_value(db, "reporting", "default_recipient", tenant_id=tenant_id)
            if default_dest and channel == "email":
                db.add(ReportRecipient(
                    tenant_id=tenant_id,
                    report_id=report_id,
                    channel="email",
                    destination=default_dest,
                ))
                db.commit()
                recipients = db.query(ReportRecipient).filter(
                    ReportRecipient.report_id == report_id,
                    ReportRecipient.tenant_id == tenant_id,
                ).all()
            else:
                return False

        success = False
        body = report.content or ""
        title = report.title

        for recip in recipients:
            dest = recip.destination if hasattr(recip, "destination") else str(recip)
            try:
                if channel == "email":
                    config = _get_channel_config(db, tenant_id, "email") or {}
                    cfg = dict(config)
                    cfg.setdefault("from", "soc@localhost")
                    cfg.setdefault("recipients", dest if isinstance(dest, list) else [dest])
                    result = send_email(cfg, f"[Report] {title}", body)
                    success = success or result
                elif channel == "webhook":
                    result = send_webhook(dest, {"report_id": report_id, "title": title, "content": body}, None)
                    success = success or result
                elif channel == "telegram":
                    # dest is chat_id
                    result = send_telegram("", dest, f"[Report] {title}\n{body[:500]}")
                    success = success or result
                elif channel == "slack":
                    result = send_slack(dest, f"[Report] {title}\n{body[:500]}")
                    success = success or result

                # Update recipient status
                recip.status = "sent"
                recip.sent_at = _utcnow()
            except Exception as e:
                logger.warning("Failed to send report %s via %s to %s: %s", report_id, channel, dest, e)
                recip.status = "failed"
                recip.error = str(e)

        db.commit()

        # Log delivery
        detail = f"Sent via {channel} to {len(recipients)} recipient(s)"
        if not success:
            detail += " (some failures)"
        _log_delivery(db, tenant_id, report_id, "sent", detail if success else f"Delivery had errors: {detail}")

        return success
    except Exception as e:
        logger.exception("send_report failed for report %s", report_id)
        _log_delivery(db, tenant_id, report_id, "failed", str(e))
        db.rollback()
        return False
    finally:
        db.close()


def schedule_recipients(report_id: int, tenant_id: str,
                          recipients: list[dict], channel: str = "email") -> int:
    """Create ReportRecipient entries for a report.

    Each recipient dict should have a 'destination' key.
    Returns the number of recipients created.
    """
    db = SessionLocal()
    try:
        count = 0
        for recip in recipients:
            dest = recip.get("destination", "")
            if not dest:
                continue
            db.add(ReportRecipient(
                tenant_id=tenant_id,
                report_id=report_id,
                channel=channel,
                destination=dest,
            ))
            count += 1
        db.commit()
        return count
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _log_delivery(db, tenant_id: str, report_id: int, action: str,
                    detail: str = "", error: str | None = None) -> None:
    """Create a ReportLog entry for delivery."""
    db.add(ReportLog(
        tenant_id=tenant_id,
        report_id=report_id,
        action=action,
        detail=detail,
        error=error,
        initiated_by="reporting",
    ))
    db.commit()


def deliver_report_via_config(db, tenant_id: str, report_id: int) -> bool:
    """Deliver a report reading channel config from SystemConfig.

    Uses the 'reporting' section for default channel and recipients.
    """
    channel = get_config_value(db, "reporting", "default_channel", tenant_id=tenant_id, fallback="email")
    return send_report(report_id, tenant_id, channel)
