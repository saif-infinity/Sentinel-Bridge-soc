import asyncio
import json
import logging
import re

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ...auth import has_scopes_or_api_key
from ...config import settings
from ...db import SessionLocal, get_db, get_tenant_id, query_with_tenant
from ...schemas import ThreatAnalysisRequest
from ...services.system_config_service import get_config_value


def _sanitize(text: str) -> str:
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    text = re.sub(r'<img[^>]*>', '', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
    return text.strip()[:500]


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyse", tags=["Analyse"], dependencies=[Depends(has_scopes_or_api_key(["ai:generate"]))])


async def _save_threat_report(content: str, tenant_id: str = "default"):
    db = SessionLocal()
    try:
        from ...models import IaReport
        report = IaReport(report_type="threat_analysis", content=content, tenant_id=tenant_id)
        db.add(report)
        db.commit()
        logger.info("Threat analysis report saved")
    except Exception as e:
        logger.error("Failed to save threat report: %s", e)
    finally:
        db.close()


async def _get_critical_wazuh_alerts(limit: int = 5, tenant_id: str = "default") -> list[str]:
    """Fetch most recent Wazuh alerts with severity >= 7, scoped by tenant."""
    db = SessionLocal()
    try:
        from ...models import Alert
        alerts = db.query(Alert).filter(Alert.severity >= 7, Alert.tenant_id == tenant_id).order_by(Alert.timestamp.desc()).limit(limit).all()
        if not alerts:
            return ["Aucune alerte Wazuh critique (level >= 7) trouvée."]
        return [f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Level {a.severity}: {_sanitize(a.description)} (src: {a.src_ip}, agent: {a.agent_id})" for a in alerts]
    finally:
        db.close()


@router.post("/analyze-threat")
async def analyze_threat(http_request: Request, analysis_request: ThreatAnalysisRequest, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(http_request)
    timeline_lines = await _get_critical_wazuh_alerts(5, tenant_id=tenant_id)
    timeline_str = "\n".join(timeline_lines)

    ollama_url = get_config_value(db, "ollama", "url", settings.OLLAMA_URL)
    ollama_model = get_config_value(db, "ollama", "model", settings.OLLAMA_MODEL)

    prompt = f"""You are a Senior SOC Analyst. Analyze these Wazuh alerts and detect threats.

Alerts:
{timeline_str}

Provide a Markdown report:
## 1. Summary
## 2. Threat Analysis
## 3. Actions

Be concise."""

    async def token_stream():
        tokens = []
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    f"{ollama_url}/api/generate",
                    json={
                        "model": ollama_model,
                        "prompt": prompt,
                        "stream": True,
                        "options": {"num_predict": 512, "temperature": 0.7}
                    },
                    timeout=120.0,
                ) as response:
                    if response.status_code != 200:
                        yield f"[Ollama Error: HTTP {response.status_code}]"
                        return
                    async for line in response.aiter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                token = data.get("response", "")
                                if token:
                                    tokens.append(token)
                                    yield token
                                if data.get("done", False):
                                    break
                            except json.JSONDecodeError:
                                pass
        except httpx.ConnectError:
            yield "\n\n**[Erreur: Ollama non démarré. Lancez: `ollama serve`]**"
        except Exception as e:
            logger.exception("Unexpected error in AI analysis")
            yield f"\n\n**[Erreur inattendue: {str(e)}]**"

        if tokens:
            asyncio.create_task(_save_threat_report("".join(tokens), tenant_id=tenant_id))

    return StreamingResponse(token_stream(), media_type="text/plain; charset=utf-8")

@router.get("/history")
def get_ia_history(request: Request, db: Session = Depends(get_db), limit: int = 50):
    """Récupère l'historique des rapports générés par l'IA (scoped by tenant)"""
    from ...models import IaReport
    reports = query_with_tenant(IaReport, request, db).order_by(IaReport.timestamp.desc()).limit(limit).all()
    return reports

