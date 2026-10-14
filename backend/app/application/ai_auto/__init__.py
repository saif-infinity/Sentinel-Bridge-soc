"""F5 — Auto-analyse IA (agent-centré). Voir service.py / handler.py."""
from .handler import on_alert_ingested  # noqa: F401
from .service import load_ai_auto_config, run_agent_burst_analysis  # noqa: F401

__all__ = ["load_ai_auto_config", "run_agent_burst_analysis", "on_alert_ingested"]
