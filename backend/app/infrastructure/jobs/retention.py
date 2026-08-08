"""F1 — Rétention : purge périodique par tenant selon Tenant.retention_days.

Exécuté par celery beat (jobs.retention.run_retention).
SQLite-safe : suppression par lots via sous-requête d'IDs (jamais DELETE ... LIMIT).
"""
import logging
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from ...application.system_config import get_config_value
from ...core.celery import celery_app
from ...db import SessionLocal
from ...domain.models import (
    AccessLog, ActionLog, Alert, ConnectionLog, IaReport, SuricataAlert, SystemConfig, Tenant,
)
from ...domain.pipeline_models import PipelineEvent
from ...domain.rule_models import RuleMatchOutbox

logger = logging.getLogger(__name__)

# (modèle, colonne timestamp, libellé de rapport)
RETENTION_TABLES = [
    (Alert, "timestamp", "alerts"),
    (SuricataAlert, "timestamp", "suricata_alerts"),
    (ActionLog, "timestamp", "action_logs"),
    (AccessLog, "login_time", "access_logs"),
    (IaReport, "timestamp", "ia_reports"),
    (ConnectionLog, "start_time", "connection_logs"),
    (PipelineEvent, "timestamp", "pipeline_events"),
    (RuleMatchOutbox, "created_at", "rule_match_events"),
]

DEFAULT_RETENTION_CONFIG = {
    "grace_days": "1",
    "batch_size": "500",
}

RETENTION_CONFIG_LABELS = {
    "grace_days": "Jours de grâce ajoutés à la rétention",
    "batch_size": "Taille des lots de purge",
}


def ensure_retention_defaults(db, tenant_id: str = "default"):
    """Seed la section 'retention' dans SystemConfig (visible dans l'UI settings)."""
    existing = {r.key for r in db.query(SystemConfig).filter(
        SystemConfig.section == "retention", SystemConfig.tenant_id == tenant_id).all()}
    for key, value in DEFAULT_RETENTION_CONFIG.items():
        if key not in existing:
            db.add(SystemConfig(
                section="retention", key=key, value=value, is_secret=False,
                label=RETENTION_CONFIG_LABELS.get(key, key), tenant_id=tenant_id))
    db.commit()


def _retention_days_for(db, tenant_id: str) -> int:
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        return 365
    return int(tenant.retention_days or 7)


def run_retention_cleanup(db, tenant_id: str = "default", dry_run: bool = False) -> dict:
    """Purge les lignes du tenant plus vieilles que retention_days + grace_days.

    dry_run=True : compte sans supprimer (tests / simulation)."""
    grace = int(float(get_config_value(db, "retention", "grace_days",
                                       DEFAULT_RETENTION_CONFIG["grace_days"], tenant_id=tenant_id)))
    batch = int(float(get_config_value(db, "retention", "batch_size",
                                       DEFAULT_RETENTION_CONFIG["batch_size"], tenant_id=tenant_id)))
    days = _retention_days_for(db, tenant_id)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days + grace)

    report = {
        "tenant_id": tenant_id,
        "retention_days": days,
        "grace_days": grace,
        "cutoff": cutoff.isoformat(),
        "dry_run": dry_run,
        "deleted": {},
    }

    for model, col_name, label in RETENTION_TABLES:
        col = getattr(model, col_name)
        total = db.query(sa.func.count(model.id)).filter(
            model.tenant_id == tenant_id, col < cutoff).scalar() or 0
        if dry_run or total == 0:
            report["deleted"][label] = total
            continue
        deleted = 0
        while True:
            ids = [r[0] for r in db.query(model.id).filter(
                model.tenant_id == tenant_id, col < cutoff).limit(batch).all()]
            if not ids:
                break
            db.execute(sa.delete(model).where(model.id.in_(ids)))
            db.commit()
            deleted += len(ids)
            if len(ids) < batch:
                break
        report["deleted"][label] = deleted
        logger.info("Rétention %s/%s: %d ligne(s) purgée(s)", tenant_id, label, deleted)
    return report


@celery_app.task(name="jobs.retention.run_retention")
def run_retention_task():
    db = SessionLocal()
    try:
        report = {"status": "ok", "tenants": {}}
        tenant_ids = ["default"]
        tenant_ids += [r[0] for r in db.query(Tenant.id).all() if r[0] not in tenant_ids]
        for tid in tenant_ids:
            try:
                report["tenants"][tid] = run_retention_cleanup(db, tid)
            except Exception as e:
                logger.warning("Rétention %s échouée: %s", tid, e)
                report["tenants"][tid] = {"status": "error", "message": str(e)}
        return report
    except Exception as e:
        logger.exception("Tâche de rétention échouée: %s", e)
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
