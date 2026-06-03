import logging
import asyncio
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from typing import List
import httpx
import json
from ..auth import api_key_auth
from ..config import settings
from ..schemas import ThreatAnalysisRequest
from ..db import SessionLocal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyse", tags=["Analyse"], dependencies=[Depends(api_key_auth)])


async def _save_threat_report(content: str):
    db = SessionLocal()
    try:
        from ..models import IaReport
        report = IaReport(report_type="threat_analysis", content=content)
        db.add(report)
        db.commit()
        logger.info("Threat analysis report saved")
    except Exception as e:
        logger.error("Failed to save threat report: %s", e)
    finally:
        db.close()


@router.post("/analyze-threat")
async def analyze_threat(request: ThreatAnalysisRequest):
    timeline_str = "\n".join(request.timeline) if request.timeline else "No alerts in timeline."
    prompt = f"""You are a Senior SOC Analyst. Analyze the following security alert timeline and detect multi-layered attacks or lateral movement.

Timeline:
{timeline_str}

Provide a 'Security Incident Synthesis' in Markdown. Include:
## 1. Incident Summary
## 2. Threat Correlation
## 3. Action Plan

Be direct and concise."""

    async def token_stream():
        tokens = []
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    f"{settings.OLLAMA_URL}/api/generate",
                    json={"model": settings.OLLAMA_MODEL, "prompt": prompt, "stream": True},
                    timeout=300.0,
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
            asyncio.create_task(_save_threat_report("".join(tokens)))

    return StreamingResponse(token_stream(), media_type="text/plain; charset=utf-8")
