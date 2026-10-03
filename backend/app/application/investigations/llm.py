"""F5 — LLM summary generation for investigations.

One-shot POST to Ollama /api/generate (stream=False).
Falls back to template if LLM unavailable.
"""
import logging
from typing import List

from ...db import SessionLocal
from ...config import settings
from ...application.system_config import get_config_value
from ...domain.investigations import Investigation, InvestigationEvidence

logger = logging.getLogger(__name__)


def generate_summary(
    db, tenant_id: str, investigation: Investigation, evidence_rows: List[InvestigationEvidence]
) -> str | None:
    """Generate a summary via Ollama. Returns None on failure (caller falls back)."""
    ollama_url = get_config_value(db, "ollama", "url", settings.OLLAMA_URL, tenant_id=tenant_id)
    ollama_model = get_config_value(db, "ollama", "model", settings.OLLAMA_MODEL, tenant_id=tenant_id)
    llm_timeout = int(get_config_value(db, "investigation", "llm_timeout_seconds", "120", tenant_id=tenant_id))

    prompt = _build_prompt(investigation, evidence_rows)

    try:
        import httpx
        payload = {
            "model": ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": 512, "temperature": 0.7},
        }
        with httpx.Client(timeout=llm_timeout) as client:
            r = client.post(
                f"{ollama_url.rstrip('/')}/api/generate",
                json=payload,
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response", "").strip() or None
    except Exception as e:
        logger.warning("LLM summary generation failed: %s", e)
        return None


def _build_prompt(investigation: Investigation, evidence_rows: List[InvestigationEvidence]) -> str:
    """Build a prompt from investigation state and evidence summaries."""
    lines = [
        "You are a Senior SOC Analyst. Summarize this investigation.",
        "",
        f"Investigation ID: {investigation.id}",
        f"Event ID: {investigation.event_id}",
        f"Risk Score: {investigation.risk_score}",
        f"Risk Level: {investigation.risk_level}",
        f"Trigger Alert Type: {investigation.trigger_alert_type} #{investigation.trigger_alert_id}",
        "",
        "Evidence collected:",
    ]
    for ev in evidence_rows:
        summary = ev.summary or ev.payload[:200] if ev.payload else ""
        lines.append(f"- [{ev.step_key}] ({ev.status}): {summary}")
    lines.append("")
    lines.append("Provide a concise 2-3 sentence summary of the security event.")
    return "\n".join(lines)