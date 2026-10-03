"""F5 — Thin sync subscriber for investigation complete events.

Registered worker-side (Celery worker), NOT in bootstrap.
The orchestrator runs in the Celery worker; bootstrap subscribers never see it.
Subscription is registered in response_tasks.py — the single worker-side point.
"""
import logging

from ...application.events import CHANNEL_INVESTIGATION_COMPLETE
from ...db import SessionLocal
from ...application.system_config import get_config_value
from ...domain.investigations import Investigation
from ...application.response.executor import process_pending_recommendations

logger = logging.getLogger(__name__)


def on_investigation_complete(channel: str, event) -> None:
    """Handle investigation complete events from the Celery worker."""
    if channel != CHANNEL_INVESTIGATION_COMPLETE:
        return

    try:
        # Extract payload from the event object
        if hasattr(event, "investigation_id"):
            investigation_id = event.investigation_id
            tenant_id = event.tenant_id
            case_id = getattr(event, "case_id", None)
            risk_level = getattr(event, "risk_level", None)
        else:
            # Fallback: event might be a dict
            investigation_id = event.get("investigation_id")
            tenant_id = event.get("tenant_id", "default")
            case_id = event.get("case_id")
            risk_level = event.get("risk_level")

        if not investigation_id:
            return

        db = SessionLocal()
        try:
            inv = db.query(Investigation).filter(
                Investigation.id == investigation_id,
                Investigation.tenant_id == tenant_id,
            ).first()
            if inv is None or inv.status != "awaiting_response":
                return

            # Process pending recommendations for THIS investigation (claim is
            # atomic — the beat safety net reuses the same path idempotently).
            processed = process_pending_recommendations(db, tenant_id=tenant_id,
                                                        limit=10, investigation_id=investigation_id)
            db.commit()
            logger.info("Investigation %s response processing complete (%d runs)", investigation_id, processed)
        finally:
            db.close()
    except Exception as e:
        logger.exception("on_investigation_complete failed for %s: %s",
                         getattr(event, "investigation_id", "?"), e)