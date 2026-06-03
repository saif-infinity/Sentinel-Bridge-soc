import logging
from fastapi import APIRouter, Depends
from typing import List, Optional
from ..worker import analyze_threat_task, deep_nmap_scan_task
from celery.result import AsyncResult
from ..auth import api_key_auth
from ..schemas import ThreatAnalysisRequest, TaskResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tasks", tags=["Background Tasks"], dependencies=[Depends(api_key_auth)])

@router.post("/analyze-threat", response_model=TaskResponse)
async def trigger_ai_analysis(request: ThreatAnalysisRequest):
    """
    Triggers a background AI analysis task.
    """
    task = analyze_threat_task.delay(request.timeline)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/status/{task_id}")
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
async def trigger_nmap_scan(target: str, scan_type: str = "ports"):
    """
    Triggers a deep Nmap scan in the background.
    """
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
