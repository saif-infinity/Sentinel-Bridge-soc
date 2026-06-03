import httpx
import base64
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Device
from ..auth import api_key_auth
from ..services.wazuh_service import wazuh_service
import urllib3

# Désactive les avertissements pour les certificats SSL auto-signés de Wazuh
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/api/wazuh", tags=["Wazuh Orchestrator"], dependencies=[Depends(api_key_auth)])

@router.get("/topology")
async def get_network_topology():
    """ 
    Génère la topologie réseau dynamiquement en fonction des agents Wazuh 
    et de leurs sous-réseaux respectifs.
    """
    try:
        topology = await wazuh_service.get_topology()
        return topology
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/agents")
async def list_wazuh_agents():
    """
    Liste tous les agents Wazuh avec leur vraie IP (depuis le cache Syscollector).
    """
    try:
        agents = await wazuh_service.get_agents()
        enriched = []
        for a in agents:
            agent_id = a.get("id", "")
            cached = wazuh_service._agent_ip_cache.get(agent_id, {})
            enriched.append({
                "id": agent_id,
                "name": a.get("name", ""),
                "status": a.get("status", "unknown"),
                "wazuh_ip": a.get("ip", "any"),          # IP enregistrée par Wazuh (peut être virtuelle)
                "real_ip": cached.get("ip", "0.0.0.0"),   # IP physique réelle (Syscollector)
                "mac": cached.get("mac", "—"),
                "user": cached.get("user", "Unknown"),
                "os": a.get("os", {}).get("name", "") if isinstance(a.get("os"), dict) else "",
            })
        return enriched
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/refresh-cache")
async def refresh_agent_cache():
    """
    Force le rechargement du cache des identités réelles des agents Wazuh
    (IPs physiques, MACs, utilisateurs via Syscollector).
    """
    try:
        await wazuh_service.refresh_agent_cache()
        return {
            "status": "ok",
            "agents_cached": len(wazuh_service._agent_ip_cache),
            "cache": {
                agent_id: {
                    "real_ip": data.get("ip"),
                    "mac": data.get("mac"),
                    "user": data.get("user"),
                }
                for agent_id, data in wazuh_service._agent_ip_cache.items()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/alerts")
async def fetch_soc_alerts(db: Session = Depends(get_db)):
    alerts = await wazuh_service.get_active_alerts()
    return alerts

@router.get("/active-responses")
async def get_active_responses():
    return await wazuh_service.get_active_response_history()

@router.get("/ai-report/{agent_id}")
async def get_ai_behavioral_report(agent_id: str):
    """
    Streams a behavioral AI report for a specific agent (no timeout).
    """
    return StreamingResponse(
        wazuh_service.stream_ai_report(agent_id),
        media_type="text/plain; charset=utf-8"
    )

@router.get("/ai-report-global")
async def get_global_network_report():
    """
    Streams a global executive security report (no timeout).
    """
    return StreamingResponse(
        wazuh_service.stream_global_report(),
        media_type="text/plain; charset=utf-8"
    )
