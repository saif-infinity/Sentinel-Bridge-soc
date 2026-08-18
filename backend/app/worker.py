from .infrastructure.jobs import ai_tasks  # noqa: F401  # registers tasks on celery_app (celery -A app.worker)
from .core.celery import celery_app
from .infrastructure.jobs.ai_tasks import (  # noqa: F401
    analyze_threat_task,
    analyze_network_global_task,
)
from .infrastructure.jobs import retention  # noqa: F401  # enregistre jobs.retention.run_retention
from .application.rules import tasks as rules_tasks  # noqa: F401  # enregistre jobs.rules.catch_up_sweep
from .infrastructure.jobs import soar_tasks  # noqa: F401
from .infrastructure.jobs import intel_tasks  # noqa: F401
from .infrastructure.jobs import syslog_process  # noqa: F401
