from celery import Celery

from .config import settings

celery_app = Celery(
    "sentinel_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,
    task_soft_time_limit=540,
)

# F1 — Planification périodique (lancer avec : celery -A app.worker beat)
celery_app.conf.beat_schedule = {
    "retention-cleanup-every-6h": {
        "task": "jobs.retention.run_retention",
        "schedule": 6 * 60 * 60,
        "options": {"queue": "celery"},
    },
    "rules-catch-up-every-5m": {
        "task": "jobs.rules.catch_up_sweep",
        "schedule": 5 * 60,
        "options": {"queue": "celery"},
    },
    "soar-outbox-sweep-every-30s": {
        "task": "jobs.soar.poll_rule_match_events",
        "schedule": 30,
        "options": {"queue": "celery"},
    },
    "intel-enrich-every-5m": {
        "task": "jobs.intel.enrich_alerts_intel",
        "schedule": 5 * 60,
        "options": {"queue": "celery"},
    },
    "investigate-retry-stuck-every-5m": {
        "task": "jobs.investigation.retry_stuck",
        "schedule": 5 * 60,
        "options": {"queue": "celery"},
    },
    "investigate-backfill-every-5m": {
        "task": "jobs.investigation.backfill_uninvestigated",
        "schedule": 5 * 60,
        "options": {"queue": "celery"},
    },
    "response-process-pending-every-60s": {
        "task": "jobs.response.process_pending",
        "schedule": 60,
        "options": {"queue": "celery"},
    },
    "response-retry-stuck-every-600s": {
        "task": "jobs.response.retry_stuck",
        "schedule": 600,
        "options": {"queue": "celery"},
    },
    "reporting-generate-daily-every-86400s": {
        "task": "jobs.reporting.generate_daily",
        "schedule": 86400,
        "options": {"queue": "celery"},
    },
    "reporting-generate-trends-every-3600s": {
        "task": "jobs.reporting.generate_trends",
        "schedule": 3600,
        "options": {"queue": "celery"},
    },
    "reporting-deliver-pending-every-600s": {
        "task": "jobs.reporting.deliver_pending",
        "schedule": 600,
        "options": {"queue": "celery"},
    },
    "reporting-process-scheduled-every-300s": {
        "task": "jobs.reporting.process_scheduled",
        "schedule": 300,
        "options": {"queue": "celery"},
    },
}
