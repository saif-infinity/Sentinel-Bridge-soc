"""F5 — Celery tasks for the reporting subsystem.

Includes worker-side subscriber registration at module import time.
"""
import json
import logging
from datetime import datetime, timezone

from ...core.celery import celery_app
from ...db import SessionLocal
from ...application.system_config import get_config_value
from ...application.reporting import generate_daily_report, generate_trends_report, \
    generate_case_closure_report, deliver_report_via_config
from ...domain.reporting import Report, ReportRecipient, ReportSchedule

logger = logging.getLogger(__name__)


@celery_app.task(name="jobs.reporting.generate_daily")
def generate_daily_report_task() -> dict:
    """Generate daily reports for all tenants."""
    db = SessionLocal()
    try:
        tenants = ["default"]
        try:
            from ...domain.models import Tenant
            tenants += [r[0] for r in db.query(Tenant.id).all() if r[0] not in tenants]
        except Exception:
            pass

        total = 0
        for tenant_id in tenants:
            try:
                generate_daily_report(db, tenant_id=tenant_id, params={"days_back": 1})
                total += 1
            except Exception as e:
                logger.warning("generate_daily_report for %s failed: %s", tenant_id, e)
        db.commit()
        return {"status": "ok", "generated": total}
    except Exception:
        logger.exception("generate_daily_report_task failed")
        return {"status": "error"}
    finally:
        db.close()


@celery_app.task(name="jobs.reporting.generate_trends")
def generate_trends_report_task() -> dict:
    """Generate trends reports for all tenants."""
    db = SessionLocal()
    try:
        tenants = ["default"]
        try:
            from ...domain.models import Tenant
            tenants += [r[0] for r in db.query(Tenant.id).all() if r[0] not in tenants]
        except Exception:
            pass

        total = 0
        for tenant_id in tenants:
            try:
                generate_trends_report(db, tenant_id=tenant_id, params={"days_back": 30})
                total += 1
            except Exception as e:
                logger.warning("generate_trends_report for %s failed: %s", tenant_id, e)
        db.commit()
        return {"status": "ok", "generated": total}
    except Exception:
        logger.exception("generate_trends_report_task failed")
        return {"status": "error"}
    finally:
        db.close()


@celery_app.task(name="jobs.reporting.deliver_pending")
def deliver_pending_reports_task() -> dict:
    """Deliver all pending reports to their recipients."""
    db = SessionLocal()
    try:
        pending_reports = db.query(Report).filter(
            Report.status == "generated",
        ).all()

        total = 0
        for report in pending_reports:
            try:
                result = deliver_report_via_config(db, report.tenant_id, report.id)
                if result:
                    report.status = "delivered"
                    total += 1
            except Exception as e:
                logger.warning("Deliver report %s failed: %s", report.id, e)
                report.status = "failed"
                report.error = str(e)[:500]
        db.commit()
        return {"status": "ok", "delivered": total}
    except Exception:
        logger.exception("deliver_pending_reports_task failed")
        return {"status": "error"}
    finally:
        db.close()


@celery_app.task(name="jobs.reporting.process_scheduled")
def process_scheduled_reports_task() -> dict:
    """Check and execute scheduled reports."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        schedules = db.query(ReportSchedule).filter(
            ReportSchedule.is_active == True,
            ReportSchedule.next_run_at <= now,
        ).all()

        executed = 0
        for schedule in schedules:
            try:
                params = {}
                try:
                    params = json.loads(schedule.params) if schedule.params else {}
                except (json.JSONDecodeError, TypeError):
                    pass

                if schedule.report_type == "daily":
                    generate_daily_report(db, tenant_id=schedule.tenant_id, params=params, schedule_id=schedule.id)
                elif schedule.report_type == "trends":
                    generate_trends_report(db, tenant_id=schedule.tenant_id, params=params, schedule_id=schedule.id)
                elif schedule.report_type == "case_closure":
                    if hasattr(schedule, "case_id") and schedule.case_id:
                        generate_case_closure_report(db, tenant_id=schedule.tenant_id, case_id=schedule.case_id, schedule_id=schedule.id)
                    else:
                        generate_daily_report(db, tenant_id=schedule.tenant_id, params=params, schedule_id=schedule.id)
                else:
                    generate_daily_report(db, tenant_id=schedule.tenant_id, params=params, schedule_id=schedule.id)

                schedule.last_run_at = now
                schedule.next_run_at = now
                executed += 1
            except Exception as e:
                logger.warning("Scheduled report %s failed: %s", schedule.id, e)

        db.commit()
        return {"status": "ok", "executed": executed}
    except Exception:
        logger.exception("process_scheduled_reports_task failed")
        return {"status": "error"}
    finally:
        db.close()


# Worker-side subscriber registration
def _register_worker_subscriber():
    """Register any worker-side subscribers for reporting events."""
    try:
        logger.info("Reporting worker subscriber registration skipped (no event bus)")
    except Exception as e:
        logger.warning("Failed to register worker subscriber: %s", e)


_register_worker_subscriber()
