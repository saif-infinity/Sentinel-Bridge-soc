"""F3 — Enrichissement intel périodique des alertes (celery beat).

Ne fait JAMAIS de réseau si THREAT_INTEL_ENABLED=False (tests / hors prod).
"""
import logging
from datetime import UTC, datetime

from ...config import settings
from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.models import Alert, SuricataAlert, Tenant
from ...infrastructure.threat_intel.client import ensure_intel_columns, lookup_ip

logger = logging.getLogger(__name__)

BATCH = 200


@celery_app.task(name="jobs.intel.enrich_alerts_intel")
def enrich_alerts_intel():
    if not settings.THREAT_INTEL_ENABLED:
        return {"status": "skipped", "reason": "THREAT_INTEL_ENABLED=false"}
    db = SessionLocal()
    enriched = {"alerts": 0, "suricata_alerts": 0}
    try:
        ensure_intel_columns(db)
        tenant_ids = ["default"]
        tenant_ids += [r[0] for r in db.query(Tenant.id).all() if r[0] not in tenant_ids]
        for tenant_id in tenant_ids:
            enriched["alerts"] += _enrich_table(db, tenant_id, Alert)
            enriched["suricata_alerts"] += _enrich_table(db, tenant_id, SuricataAlert)
        return {"status": "ok", **enriched}
    except Exception:
        logger.exception("Enrichissement intel échoué")
        return {"status": "error"}
    finally:
        db.close()


def _enrich_table(db, tenant_id: str, model) -> int:
    from sqlalchemy import desc
    rows = (
        db.query(model)
        .filter(model.tenant_id == tenant_id, model.intel_checked_at.is_(None))
        .order_by(desc(model.timestamp))
        .limit(BATCH)
        .all()
    )
    count = 0
    for row in rows:
        ip = getattr(row, "src_ip", None)
        if not ip:
            continue
        info = lookup_ip(db, tenant_id, ip)
        row.intel_score = info.get("risk_score")
        row.intel_verdict = info.get("verdict")
        row.intel_source = info.get("source_name")
        row.intel_checked_at = datetime.now(UTC)
        count += 1
        if count % 25 == 0:
            db.commit()
    db.commit()
    return count
