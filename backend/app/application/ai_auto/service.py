"""F5 — Service d'auto-analyse IA (agent-centré).

Sur déclenchement (burst d'alertes sur un même agent), collecte les alertes
récentes de l'agent puis appelle le routeur HF (compatible OpenAI) et stocke
le résultat dans AgentAiAnalysis.

Détails de sécurité :
  - Le token HF n'est jamais journalisé ni exposé par l'API.
  - Si aucun token n'est configuré (tenant ni global), l'analyse est un no-op
    (retourne {"status": "disabled"}) — fail-open, aucune exception.
  - Single-flight : pas de nouvelle analyse tant qu'une analyse du même agent
    est encore en statut "running".
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ...db import SessionLocal
from ...domain.models import AgentAiAnalysis, Alert, SuricataAlert
from ...infrastructure.hf_router.client import call_hf_router
from ..system_config import get_config_value

logger = logging.getLogger(__name__)

AI_AUTO_SECTION = "ai_auto"


def load_ai_auto_config(db: Session, tenant_id: str, include_secrets: bool = False) -> dict:
    """Lit la config ai_auto effective (DB → defaults settings.AI_AUTO_DEFAULTS)."""
    from ...core.config import settings

    defaults = settings.AI_AUTO_DEFAULTS
    cfg = {
        "enabled": get_config_value(db, AI_AUTO_SECTION, "enabled", str(defaults["enabled"]).lower(), tenant_id).lower() in ("true", "1", "yes", "on"),
        "threshold": int(get_config_value(db, AI_AUTO_SECTION, "threshold", str(defaults["threshold"]), tenant_id)),
        "send_count": int(get_config_value(db, AI_AUTO_SECTION, "send_count", str(defaults["send_count"]), tenant_id)),
        "severity_min": int(get_config_value(db, AI_AUTO_SECTION, "severity_min", str(defaults["severity_min"]), tenant_id)),
        "window_minutes": int(get_config_value(db, AI_AUTO_SECTION, "window_minutes", str(defaults["window_minutes"]), tenant_id)),
        "model": get_config_value(db, AI_AUTO_SECTION, "model", defaults["model"], tenant_id),
        "url": get_config_value(db, AI_AUTO_SECTION, "url", defaults["url"], tenant_id),
    }
    if include_secrets:
        # Jamais exposé par l'API — utilisé uniquement côté exécution.
        cfg["token"] = get_config_value(db, AI_AUTO_SECTION, "token", settings.HF_TOKEN, tenant_id)
    return cfg


def _effective_token(cfg: dict, settings) -> str:
    """Token HF effectif : config tenant → settings global."""
    return cfg.get("token") or getattr(settings, "HF_TOKEN", "") or ""


def collect_recent_alerts(db: Session, tenant_id: str, agent_id: str,
                          severity_min: int, window_minutes: int, limit: int) -> list:
    """Alertes récentes de l'agent (Alert + SuricataAlert) dans la fenêtre.

    Filtre sur normalized_severity OU severity brute (les deux colonnes
    existent post-migration ; la brute couvre les lignes non normalisées).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    sev = int(severity_min)

    def _rows(model):
        return (
            db.query(model)
            .filter(
                model.tenant_id == tenant_id,
                model.agent_id == agent_id,
                or_(model.normalized_severity >= sev, model.severity >= sev),
                model.timestamp >= cutoff,
            )
            .order_by(model.timestamp.desc())
            .limit(limit)
            .all()
        )

    rows = []
    try:
        rows += _rows(Alert)
    except Exception as e:  # fail-open : une source ne doit pas bloquer l'autre
        logger.debug("ai_auto: collect Alert échoué: %s", e)
    try:
        rows += _rows(SuricataAlert)
    except Exception as e:
        logger.debug("ai_auto: collect SuricataAlert échoué: %s", e)

    rows.sort(key=lambda r: getattr(r, "timestamp", datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    return rows[:limit]


def _row_to_bullet(row) -> str:
    ts = getattr(row, "timestamp", None)
    ts_s = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "?"
    sev = int(getattr(row, "severity", 0) or 0)
    desc = getattr(row, "description", None) or getattr(row, "alert_msg", None) or ""
    src = getattr(row, "src_ip", None) or ""
    return f"- [{ts_s}] S{sev} {str(desc)[:200]} (src: {src})"


def run_agent_burst_analysis(agent_id: str, tenant_id: str = "default",
                             db: Session | None = None) -> dict:
    """Analyse IA d'un burst d'alertes sur un agent.

    Crée une ligne AgentAiAnalysis (status running → completed|error).
    Retour : {"status": "created"|"skipped"|"disabled"|"error", "analysis_id": int?}
    """
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        from ...core.config import settings
        from ..system_config import get_config_value as _gcv

        cfg = load_ai_auto_config(db, tenant_id, include_secrets=True)
        if not cfg["enabled"]:
            return {"status": "disabled"}

        token = _effective_token(cfg, settings)
        if not token:
            logger.info("ai_auto: pas de token HF configuré — analyse %s/%s non lancée", tenant_id, agent_id)
            return {"status": "disabled"}

        # Single-flight : une analyse de cet agent est déjà en cours ?
        running = (
            db.query(AgentAiAnalysis)
            .filter(
                AgentAiAnalysis.tenant_id == tenant_id,
                AgentAiAnalysis.agent_id == agent_id,
                AgentAiAnalysis.status == "running",
            )
            .first()
        )
        if running is not None:
            return {"status": "skipped", "analysis_id": running.id}

        rows = collect_recent_alerts(
            db, tenant_id, agent_id,
            severity_min=cfg["severity_min"],
            window_minutes=cfg["window_minutes"],
            limit=cfg["send_count"],
        )
        if not rows:
            return {"status": "skipped"}

        alerts_txt = "\n".join(_row_to_bullet(r) for r in rows)
        prompt = (
            "You are a Senior SOC Analyst. A burst of alerts hit one host. "
            "Analyze the alerts and produce a concise Markdown report.\n\n"
            f"Host/agent: {agent_id}\n"
            f"Time window: last {cfg['window_minutes']} minutes\n\n"
            f"Alerts ({len(rows)}):\n{alerts_txt}\n\n"
            "Report format:\n"
            "## 1. Summary\n"
            "## 2. Threat Analysis\n"
            "## 3. Recommended Actions\n\n"
            "Be concise, no preamble."
        )

        analysis = AgentAiAnalysis(
            tenant_id=tenant_id,
            agent_id=agent_id,
            severity_count=len(rows),
            alert_ids=json.dumps([int(getattr(r, "id", 0)) for r in rows if getattr(r, "id", None) is not None]),
            model=cfg["model"],
            status="running",
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        logger.info("ai_auto: analyse démarrée agent=%s tenant=%s (#%s, %d alertes)",
                    agent_id, tenant_id, analysis.id, len(rows))
        try:
            response = call_hf_router(
                prompt,
                model=cfg["model"],
                base_url=cfg["url"],
                token=token,
                system="You are a concise Senior SOC Analyst. Answer in Markdown.",
            )
            if response is None:
                raise RuntimeError("HF router returned no content")
            analysis.response = response
            analysis.status = "completed"
            analysis.analyzed_at = datetime.now(timezone.utc)
            db.commit()
            return {"status": "created", "analysis_id": analysis.id}
        except Exception as e:
            logger.error("ai_auto: analyse échouée agent=%s: %s", agent_id, e)
            analysis.status = "error"
            analysis.error = str(e)[:500]
            analysis.analyzed_at = datetime.now(timezone.utc)
            db.commit()
            return {"status": "error", "analysis_id": analysis.id, "error": str(e)[:200]}
    finally:
        if own_db:
            db.close()