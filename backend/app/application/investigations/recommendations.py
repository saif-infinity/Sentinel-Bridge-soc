"""F5 — Rule-based recommendation generation for investigations."""
import json
import logging
from typing import Dict, List

from sqlalchemy.orm import Session

from ...application.system_config import get_config_value
from ...domain.investigations import Investigation, InvestigationEvidence

logger = logging.getLogger(__name__)


def generate_recommendations(
    db: Session,
    tenant_id: str,
    investigation: Investigation,
    event,
    evidence_rows: List[InvestigationEvidence],
    score: int,
    level: str,
) -> List[Dict]:
    """Generate rule-based recommendations from investigation state."""
    recs: List[Dict] = []

    # Extract evidence data
    src_ip = event.normalized_alert.get("src_ip")
    dest_ip = event.normalized_alert.get("dest_ip")
    ti_verdict = "unknown"
    intel_risk = None
    is_wazuh_agent = False
    has_asset = False
    is_critical_asset = False

    for ev in evidence_rows:
        try:
            p = json.loads(ev.payload or "{}")
            if ev.step_key and ev.step_key.startswith("ti:"):
                ti_verdict = p.get("verdict", "unknown")
                intel_risk = p.get("risk_score")
            elif ev.step_key and ev.step_key.startswith("host:"):
                is_wazuh_agent = bool(p.get("agent_id") or p.get("ip"))
            elif ev.step_key and ev.step_key.startswith("asset:"):
                has_asset = True
                dept = p.get("department", "").lower()
                is_critical_asset = dept in ("it", "admin", "finance", "management")
        except (json.JSONDecodeError, TypeError):
            pass

    # ── block_ip: if TI verdict malicious ──
    if ti_verdict == "malicious" and src_ip:
        priority = 5 if is_critical_asset else 4
        confidence = (intel_risk or 80) / 100.0 if intel_risk else 0.9
        ti_evidence = _find_evidence_step(evidence_rows, "ti:")
        rationale = f"src IP flagged malicious by AbuseIPDB (evidence {ti_evidence})"
        recs.append({
            "action_type": "block_ip",
            "target": src_ip,
            "priority": priority,
            "confidence": round(min(confidence, 1.0), 2),
            "rationale": rationale,
            "source": "rule_based",
        })

    # ── isolate_agent: critical/high + wazuh agent + high trust ──
    if level in ("critical", "high") and is_wazuh_agent:
        confidence = 0.8 if level == "critical" else 0.6
        host_evidence = _find_evidence_step(evidence_rows, "host:")
        rationale = f"Critical asset has Wazuh agent — isolate (evidence {host_evidence})"
        recs.append({
            "action_type": "isolate_agent",
            "target": src_ip or dest_ip,
            "priority": 4 if level == "critical" else 3,
            "confidence": confidence,
            "rationale": rationale,
            "source": "rule_based",
        })

    # ── notify: always (priority 2) ──
    recs.append({
        "action_type": "notify",
        "target": None,
        "priority": 2,
        "confidence": 0.5,
        "rationale": f"Investigation {investigation.id} requires analyst review (risk: {level}, score: {score})",
        "source": "rule_based",
    })

    # ── monitor: fallback (priority 1) ──
    recs.append({
        "action_type": "monitor",
        "target": None,
        "priority": 1,
        "confidence": 0.4,
        "rationale": "Continuous monitoring recommended for this event",
        "source": "rule_based",
    })

    # ── run_playbook: if TI unknown and score high ──
    if ti_verdict == "unknown" and score >= 60:
        recs.append({
            "action_type": "run_playbook",
            "target": None,
            "priority": 3,
            "confidence": 0.5,
            "rationale": "TI unknown but score high — suggest playbook enrichment",
            "source": "rule_based",
        })

    return recs


def _find_evidence_step(evidence_rows: List[InvestigationEvidence], prefix: str) -> str:
    """Find the first evidence step_key matching a prefix."""
    for ev in evidence_rows:
        if ev.step_key and ev.step_key.startswith(prefix):
            return ev.step_key
    return "N/A"