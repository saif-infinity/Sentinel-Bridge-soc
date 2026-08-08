from .infrastructure.jobs import nmap_tasks  # noqa: F401  # registers deep_nmap_scan_task on nmap_celery
from .infrastructure.jobs.nmap_tasks import (  # noqa: F401
    nmap_celery,
    deep_nmap_scan_task,
)
