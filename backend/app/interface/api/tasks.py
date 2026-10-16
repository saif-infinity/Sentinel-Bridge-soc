import logging

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ...auth import get_api_key_or_jwt, has_scopes_or_api_key
from ...db import get_tenant_id
from ...infrastructure.jobs.nmap_tasks import deep_nmap_scan_task
from ...schemas import TaskResponse, ThreatAnalysisRequest
from ...worker import analyze_network_global_task, analyze_threat_task

logger = logging.getLogger(__name__)


class NmapScanRequest(BaseModel):
    target: str
    scan_type: str = "ports"

router = APIRouter(prefix="/api/tasks", tags=["Background Tasks"], dependencies=[Depends(has_scopes_or_api_key(["ai:generate"]))])

@router.post("/analyze-threat", response_model=TaskResponse)
async def trigger_ai_analysis(request: Request, threat_request: ThreatAnalysisRequest):
    """
    Déclenche une analyse IA en tâche de fond (Celery).
    Le backend récupère lui-même les 10 dernières alertes Wazuh critiques (level >= 7)
    depuis la base de données — aucune donnée frontend n'est utilisée.
    """
    tenant_id = get_tenant_id(request)
    task = analyze_threat_task.delay(tenant_id=tenant_id)
    return {"task_id": task.id, "status": "PENDING"}

@router.post("/analyze-network-global", response_model=TaskResponse)
async def trigger_global_network_analysis(request: Request):
    """
    Déclenche l'analyse réseau globale IA en tâche de fond (Celery).
    Le backend récupère les 10 dernières alertes Suricata critiques (severity >= 7)
    depuis la base de données — aucune donnée frontend n'est utilisée.
    """
    tenant_id = get_tenant_id(request)
    task = analyze_network_global_task.delay(tenant_id=tenant_id)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/status/{task_id}", dependencies=[Depends(get_api_key_or_jwt)])
async def get_task_status(task_id: str):
    """
    Check the status and result of a background task.
    """
    result = AsyncResult(task_id)
    response = {
        "task_id": task_id,
        "status": result.status,
        "result": result.result if result.ready() else None
    }
    return response

@router.post("/nmap-scan", response_model=TaskResponse)
async def trigger_nmap_scan(body: NmapScanRequest):
    """
    Triggers a deep Nmap scan in the background.
    """
    import ipaddress
    target = body.target
    scan_type = body.scan_type
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target IP/subnet")

    base_args = "-n -Pn -sS -T3 --privileged"
    if scan_type == "services":
        args = f"{base_args} -sV --version-intensity 5"
    elif scan_type == "os":
        args = f"{base_args} -O"
    elif scan_type == "vuln":
        args = f"{base_args} -sV --script=vuln"
    else:
        args = f"{base_args} -p 1-1000"

    task = deep_nmap_scan_task.delay(target, args)
    return {"task_id": task.id, "status": "PENDING"}
