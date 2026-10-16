from .application.rules import tasks as rules_tasks  # noqa: F401  # enregistre jobs.rules.catch_up_sweep
from .infrastructure.jobs import (
    ai_alert_burst,  # noqa: F401  # enregistre jobs.ai_alert_burst
    ai_tasks,  # noqa: F401  # registers tasks on celery_app (celery -A app.worker)
    intel_tasks,  # noqa: F401
    investigation_tasks,  # noqa: F401
    notification_tasks,  # noqa: F401
    reporting_tasks,  # noqa: F401
    response_tasks,  # noqa: F401
    retention,  # noqa: F401  # enregistre jobs.retention.run_retention
    soar_tasks,  # noqa: F401
    syslog_process,  # noqa: F401
)
from .infrastructure.jobs.ai_tasks import (  # noqa: F401
    analyze_network_global_task,
    analyze_threat_task,
)
