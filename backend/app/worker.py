from celery import Celery
import httpx
import json
import logging
import nmap
from .config import settings

logger = logging.getLogger(__name__)

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
    task_time_limit=300,
)

@celery_app.task(name="tasks.analyze_threat")
def analyze_threat_task(timeline_data):
    logger.info("Starting AI threat analysis background task...")

    timeline_str = "\n".join(timeline_data) if timeline_data else "No alerts in timeline."
    prompt = f"""You are a Senior SOC Analyst. Analyze the following security alert timeline and detect multi-layered attacks or lateral movement.

Timeline:
{timeline_str}

Provide a 'Security Incident Synthesis' in Markdown. Include:
## 1. Incident Summary
## 2. Threat Correlation
## 3. Action Plan

Be direct and concise."""

    try:
        with httpx.Client(timeout=300.0) as client:
            response = client.post(
                f"{settings.OLLAMA_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False
                }
            )

            if response.status_code == 200:
                result = response.json().get("response", "No response from AI")
                logger.info("AI Analysis completed successfully.")
                return {"status": "success", "analysis": result}
            else:
                logger.error("Ollama API error: %d", response.status_code)
                return {"status": "error", "message": f"Ollama HTTP {response.status_code}"}

    except httpx.ConnectError:
        logger.error("Could not connect to Ollama.")
        return {"status": "error", "message": "Ollama service not reachable."}
    except Exception as e:
        logger.exception("Unexpected error in AI task")
        return {"status": "error", "message": str(e)}

@celery_app.task(name="tasks.deep_nmap_scan")
def deep_nmap_scan_task(target, scan_args):
    logger.info("Starting deep Nmap scan on %s with args: %s", target, scan_args)

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=scan_args)

        results = []
        for host in nm.all_hosts():
            host_info = nm[host]
            addresses = host_info.get('addresses', {})
            mac = (addresses.get('mac') or host_info.get('mac') or 'UNKNOWN').upper()

            ports = []
            for proto in host_info.all_protocols():
                for port in host_info[proto].keys():
                    service = host_info[proto][port]['name']
                    product = host_info[proto][port].get('product', '')
                    ports.append(f"{port}/{proto}: {service} {product}")

            results.append({
                "ip": host,
                "mac": mac,
                "ports": ports,
                "os": host_info.get('osmatch', [{}])[0].get('name', 'Unknown') if host_info.get('osmatch') else 'Unknown'
            })

        logger.info("Deep scan completed. Found %d hosts.", len(results))
        return {"status": "success", "results": results}

    except Exception as e:
        logger.error("Nmap Task Failed: %s", e)
        return {"status": "error", "message": str(e)}
