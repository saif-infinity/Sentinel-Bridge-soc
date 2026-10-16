"""F5 — Evidence collection steps for investigations.

Each step is a function: (db, tenant_id, investigation, event) -> (step_key, evidence_payload | None, error | None).
"""
import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ...application.events import RuleMatchEvent
from ...application.system_config import get_config_value
from ...domain.investigations import Investigation
from ...domain.models import Alert, Asset, SuricataAlert
from ...infrastructure.threat_intel.client import lookup_ip

logger = logging.getLogger(__name__)


def step_threat_intel_src(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Lookup source IP via AbuseIPDB. Never raises."""
    src_ip = event.normalized_alert.get("src_ip")
    if not src_ip:
        return "ti:abuseipdb:src:-", None, None
    step_key = f"ti:abuseipdb:src:{src_ip}"
    try:
        info = lookup_ip(db, tenant_id, src_ip)
        payload = {"verdict": info.get("verdict"), "risk_score": info.get("risk_score"), "source_name": info.get("source_name")}
        summary = f"TI verdict: {info.get('verdict')} (risk {info.get('risk_score')})"
        return step_key, payload, None
    except Exception as e:
        logger.warning("TI lookup failed for src %s: %s", src_ip, e)
        return step_key, None, str(e)


def step_threat_intel_dest(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Lookup destination IP via AbuseIPDB. Never raises."""
    dest_ip = event.normalized_alert.get("dest_ip")
    if not dest_ip:
        return "ti:abuseipdb:dest:-", None, None
    step_key = f"ti:abuseipdb:dest:{dest_ip}"
    try:
        info = lookup_ip(db, tenant_id, dest_ip)
        payload = {"verdict": info.get("verdict"), "risk_score": info.get("risk_score"), "source_name": info.get("source_name")}
        summary = f"TI verdict: {info.get('verdict')} (risk {info.get('risk_score')})"
        return step_key, payload, None
    except Exception as e:
        logger.warning("TI lookup failed for dest %s: %s", dest_ip, e)
        return step_key, None, str(e)


def step_host_wazuh(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Resolve Wazuh agent identity via agent_id or IP → Device/Asset."""
    agent_id = event.normalized_alert.get("agent_id")
    src_ip = event.normalized_alert.get("src_ip")

    if agent_id:
        step_key = f"host:wazuh:{agent_id}"
        payload = {"agent_id": agent_id}
        try:
            # Check WazuhCache agent_ip_cache for known identities
            wzh = _get_wazuh_service()
            agent_cache = getattr(wzh, "_agent_ip_cache", {})
            identity = agent_cache.get(agent_id)
            if identity:
                payload.update(identity)
                return step_key, payload, None
            # Fallback to Asset lookup by IP
            if src_ip:
                asset = db.query(Asset).filter(Asset.ip == src_ip, Asset.tenant_id == tenant_id).first()
                if asset:
                    payload = {"ip": src_ip, "department": asset.department, "employee": asset.employee_name}
                    return step_key, payload, None
        except Exception as e:
            logger.warning("Wazuh agent lookup failed for %s: %s", agent_id, e)
            return step_key, None, str(e)
    elif src_ip:
        step_key = f"host:wazuh:{src_ip}"
        payload = None
        try:
            asset = db.query(Asset).filter(Asset.ip == src_ip, Asset.tenant_id == tenant_id).first()
            if asset:
                payload = {"ip": src_ip, "department": asset.department, "employee": asset.employee_name}
                return step_key, payload, None
        except Exception as e:
            logger.warning("Asset lookup failed for %s: %s", src_ip, e)
            return step_key, None, str(e)
    else:
        return "host:wazuh:unknown", None, None

    return step_key, payload, None


def _get_wazuh_service():
    """Lazy import of wazuh_service to avoid circular imports."""
    from ...application.wazuh.service import wazuh_service
    return wazuh_service


def step_asset(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Asset lookup by IP."""
    ip = event.normalized_alert.get("src_ip") or event.normalized_alert.get("dest_ip")
    if not ip:
        return "asset:-", None, None
    step_key = f"asset:{ip}"
    try:
        asset = db.query(Asset).filter(Asset.ip == ip, Asset.tenant_id == tenant_id).first()
        if asset:
            payload = {"ip": ip, "department": asset.department, "employee": asset.employee_name}
            summary = f"Asset {ip}: {asset.employee_name} / {asset.department}"
            return step_key, payload, None
        return step_key, None, None
    except Exception as e:
        logger.warning("Asset lookup failed for %s: %s", ip, e)
        return step_key, None, str(e)


def step_related_alerts(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Windowed query on Alert + SuricataAlert sharing src/dest IP."""
    src_ip = event.normalized_alert.get("src_ip")
    dest_ip = event.normalized_alert.get("dest_ip")
    if not src_ip and not dest_ip:
        return "corr:related:0:src:-", None, None

    window_min = int(get_config_value(db, "investigation", "related_window_minutes", "60", tenant_id=tenant_id))
    cutoff = datetime.now(UTC) - timedelta(minutes=window_min)

    src_ips = [ip for ip in [src_ip, dest_ip] if ip]
    conditions = []
    for ip in src_ips:
        conditions.append(Alert.src_ip == ip)
        conditions.append(SuricataAlert.src_ip == ip)
    if dest_ip:
        for ip in [dest_ip]:
            conditions.append(Alert.src_ip == ip)
            conditions.append(SuricataAlert.src_ip == ip)

    # Use OR for combining conditions
    query = db.query(Alert).filter(
        Alert.tenant_id == tenant_id,
        Alert.timestamp >= cutoff,
        or_(*conditions),
    )
    related_count = query.count()

    top_n = min(related_count, 10)
    related_alerts = query.order_by(Alert.timestamp.desc()).limit(top_n).all()

    step_key = f"corr:related:{window_min}:src:{src_ip or '-'}"
    payload = {"count": related_count, "window_minutes": window_min, "alert_ids": [a.id for a in related_alerts]}
    summary = f"{related_count} related alerts in {window_min}min window"
    return step_key, payload, None


def step_mitre_context(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> tuple[str, dict | None, str | None]:
    """Extract MITRE context from matched_rules."""
    matched_rules = event.matched_rules or []
    mitre_ids = []
    tactics = []
    for rule in matched_rules:
        if isinstance(rule, dict):
            ids = rule.get("mitre_attack_ids") or []
            if isinstance(ids, str):
                try:
                    ids = json.loads(ids)
                except (json.JSONDecodeError, TypeError):
                    ids = []
            mitre_ids.extend(ids)
            ts = rule.get("tactics") or []
            if isinstance(ts, str):
                try:
                    ts = json.loads(ts)
                except (json.JSONDecodeError, TypeError):
                    ts = []
            tactics.extend(ts)

    if not mitre_ids and not tactics:
        return "mitre:context", None, None

    step_key = "mitre:context"
    payload = {"mitre_attack_ids": list(set(mitre_ids)), "tactics": list(set(tactics))}
    summary = f"MITRE: {len(set(mitre_ids))} technique IDs, {len(set(tactics))} tactics"
    return step_key, payload, None
