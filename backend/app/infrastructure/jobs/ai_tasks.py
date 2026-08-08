import logging

from ...core.celery import celery_app
from ..ollama.client import _sanitize, _call_ollama

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  TÂCHE 1 : Analyse Threat Timeline (Wazuh, level >= 7)
# ─────────────────────────────────────────────────────────────

@celery_app.task(name="tasks.analyze_threat")
def analyze_threat_task(tenant_id: str = "default"):
    logger.info("Démarrage analyse IA Wazuh — récupération des 10 alertes critiques (level >= 7)...")

    from ...models import Alert
    from ...db import SessionLocal

    db = SessionLocal()
    try:
        alerts = (
            db.query(Alert)
            .filter(Alert.severity >= 7, Alert.tenant_id == tenant_id)
            .order_by(Alert.timestamp.desc())
            .limit(5)
            .all()
        )
        if not alerts:
            timeline_str = "Aucune alerte Wazuh critique (level >= 7) trouvée."
        else:
            timeline_str = "\n".join([
                f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] Level {a.severity}: "
                f"{_sanitize(a.description)} (src: {a.src_ip}, agent: {a.agent_id})"
                for a in alerts
            ])
    finally:
        db.close()

    prompt = f"""You are a Senior SOC Analyst. Analyze these Wazuh alerts and detect threats.

Alerts:
{timeline_str}

Provide a Markdown report:
## 1. Summary
## 2. Threat Analysis
## 3. Actions

Be concise."""

    try:
        result = _call_ollama(prompt)
        logger.info("Analyse Wazuh IA terminée avec succès.")

        from ...models import IaReport
        db = SessionLocal()
        try:
            db.add(IaReport(report_type="threat_analysis", content=result, tenant_id=tenant_id))
            db.commit()
        except Exception as e:
            logger.error("Sauvegarde rapport threat échouée : %s", e)
        finally:
            db.close()

        return {"status": "success", "analysis": result}

    except RuntimeError as e:
        logger.error("Erreur analyse Wazuh : %s", e)
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.exception("Erreur inattendue analyse Wazuh")
        return {"status": "error", "message": str(e)}


# ─────────────────────────────────────────────────────────────
#  TÂCHE 2 : Analyse Network Global (Suricata, severity >= 7)
# ─────────────────────────────────────────────────────────────

@celery_app.task(name="tasks.analyze_network_global")
def analyze_network_global_task(tenant_id: str = "default"):
    logger.info("Démarrage analyse IA réseau — récupération des 10 alertes Suricata critiques (severity >= 7)...")

    from ...models import SuricataAlert, Device
    from ...db import SessionLocal

    db = SessionLocal()
    try:
        suricata_alerts = (
            db.query(SuricataAlert)
            .filter(SuricataAlert.severity >= 7, SuricataAlert.tenant_id == tenant_id)
            .order_by(SuricataAlert.timestamp.desc())
            .limit(5)
            .all()
        )
        devices       = db.query(Device).filter(Device.tenant_id == tenant_id).all()
        total_devices = len(devices)
        online_devices = sum(1 for d in devices if d.is_online)
        wazuh_agents   = sum(1 for d in devices if d.is_wazuh_agent)

        if not suricata_alerts:
            alert_summary = "Aucune alerte Suricata critique (severity >= 7) trouvée."
        else:
            by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for a in suricata_alerts:
                s = int(a.severity or 0)
                if s >= 7:   by_sev["critical"] += 1
                elif s >= 5: by_sev["high"]     += 1
                elif s >= 3: by_sev["medium"]   += 1
                else:        by_sev["low"]      += 1

            recent_lines = [
                f"- [{a.timestamp.strftime('%H:%M')}] S{a.severity}: "
                f"{_sanitize(a.alert_msg)} ({a.src_ip}->{a.dest_ip} {a.proto})"
                for a in suricata_alerts
            ]
            alert_summary = (
                f"Critical:{by_sev['critical']} High:{by_sev['high']} "
                f"Medium:{by_sev['medium']} Low:{by_sev['low']}\n"
                + "\n".join(recent_lines)
            )
    except Exception as e:
        alert_summary = f"Erreur de récupération des données : {e}"
        total_devices, online_devices, wazuh_agents = 0, 0, 0
    finally:
        db.close()

    prompt = f"""You are a CISO writing an Executive Security Audit Report.

Network: {total_devices} devices, {online_devices} online, {wazuh_agents} agents.

Top Suricata Alerts:
{alert_summary}

Generate a Markdown report:
# Network Security Audit
## 1. Threat Posture
## 2. Key Indicators
## 3. Action Items

Professional CISO language, max 300 words."""

    try:
        result = _call_ollama(prompt)
        logger.info("Analyse réseau globale IA terminée avec succès.")

        from ...models import IaReport
        db = SessionLocal()
        try:
            db.add(IaReport(report_type="global_network", content=result, tenant_id=tenant_id))
            db.commit()
        except Exception as e:
            logger.error("Sauvegarde rapport global échouée : %s", e)
        finally:
            db.close()

        return {"status": "success", "analysis": result}

    except RuntimeError as e:
        logger.error("Erreur analyse réseau globale : %s", e)
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.exception("Erreur inattendue analyse réseau globale")
        return {"status": "error", "message": str(e)}



