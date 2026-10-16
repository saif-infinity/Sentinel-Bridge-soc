"""F5 — Weighted risk scoring for investigations.

All components normalized to [0, 1], score = Σ wᵢ·sᵢ × 100.
Missing components are renormalized out (their weight excluded).
"""
import json
import logging
import math

from sqlalchemy.orm import Session

from ...application.system_config import get_config_value

logger = logging.getLogger(__name__)

DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": 0.35,
    "threat_intel": 0.20,
    "host_criticality": 0.15,
    "correlated_alerts": 0.15,
    "mitre": 0.10,
    "recency": 0.05,
}

CRITICAL_DEPARTMENTS_DEFAULT = "it,admin,finance,management"

_MITRE_SCORES: dict[str, float] = {
    "initial-access": 1.0,
    "lateral-movement": 1.0,
    "execution": 0.9,
    "persistence": 0.9,
    "privilege-escalation": 0.8,
    "defense-evasion": 0.8,
}


def _load_weights(db: Session, tenant_id: str = "default") -> dict[str, float]:
    """Load optional override weights from investigation.weights config."""
    raw = get_config_value(db, "investigation", "weights", "{}", tenant_id=tenant_id)
    try:
        override = json.loads(raw)
        if isinstance(override, dict):
            return {k: float(v) for k, v in override.items() if k in DEFAULT_WEIGHTS}
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
    return DEFAULT_WEIGHTS.copy()


def _renormalize(weights_available: dict[str, float]) -> float:
    """Return the sum of available component weights for renormalisation."""
    total = sum(weights_available.values())
    return total if total > 0 else 1.0


def compute_risk_score(
    db: Session,
    tenant_id: str,
    *,
    severity: int = 0,
    intel_verdict: str = "unknown",
    intel_score: int | None = None,
    host_dept: str | None = None,
    is_wazuh_agent: bool = False,
    has_asset: bool = False,
    related_count: int = 0,
    mitre_tactics: list[str] | None = None,
    age_hours: float = 0.0,
    critical_departments: str | None = None,
) -> tuple[int, str, dict]:
    """Compute weighted risk score with renormalisation.

    Returns (score: int 0-100, level: str, breakdown: dict).
    """
    weights = _load_weights(db, tenant_id)
    crit_depts = critical_departments or CRITICAL_DEPARTMENTS_DEFAULT
    crit_dept_set = {d.strip().lower() for d in crit_depts.split(",") if d.strip()}
    mitre_tactics = mitre_tactics or []

    # Build available component scores and their weights
    available: dict[str, float] = {}
    breakdown: dict[str, dict] = {}

    # ── severity (0.35) ──
    sev_raw = severity
    sev_norm = min(max(sev_raw, 5) if sev_raw > 0 else 5, 15) / 15
    sev_score = min(max(sev_raw, 0), 15) / 15
    if sev_score > 0:
        available["severity"] = weights.get("severity", 0.35)
        breakdown["severity"] = {"weight": available["severity"], "score": sev_score, "source": "rule_severity"}

    # ── threat_intel (0.20) ──
    intel_map = {"malicious": 1.0, "suspicious": 0.6, "clean": 0.1, "unknown": 0.5}
    intel_score_val = intel_map.get(intel_verdict, 0.5)
    # If intel_score is present and verdict is not unknown, refine slightly
    if intel_verdict == "unknown" and intel_score is not None:
        intel_score_val = 0.5  # neutral for unknown
    if intel_verdict != "unknown" or intel_score is not None:
        available["threat_intel"] = weights.get("threat_intel", 0.20)
        breakdown["threat_intel"] = {"weight": available["threat_intel"], "score": intel_score_val, "source": intel_verdict}

    # ── host_criticality (0.15) ──
    host_score = 0.5  # default no asset
    if has_asset:
        if host_dept and host_dept.lower() in crit_dept_set:
            host_score = 1.0
        else:
            host_score = 0.7  # known dept
        if is_wazuh_agent:
            host_score = min(host_score + 0.1, 1.0)
    available["host_criticality"] = weights.get("host_criticality", 0.15)
    breakdown["host_criticality"] = {"weight": available["host_criticality"], "score": host_score, "source": host_dept or "no_asset"}

    # ── correlated_alerts (0.15) ──
    if related_count > 0:
        corr_score = min(math.log2(1 + related_count) / math.log2(51), 1.0)
        available["correlated_alerts"] = weights.get("correlated_alerts", 0.15)
        breakdown["correlated_alerts"] = {"weight": available["correlated_alerts"], "score": corr_score, "source": f"n={related_count}"}

    # ── mitre (0.10) ──
    if mitre_tactics:
        mitre_score = max(
            _MITRE_SCORES.get(t.lower(), 0.6) for t in mitre_tactics
        )
        available["mitre"] = weights.get("mitre", 0.10)
        breakdown["mitre"] = {"weight": available["mitre"], "score": mitre_score, "source": ", ".join(mitre_tactics)}
    else:
        # "none" = 0.5 default
        available["mitre"] = weights.get("mitre", 0.10)
        breakdown["mitre"] = {"weight": available["mitre"], "score": 0.5, "source": "none"}

    # ── recency (0.05) ──
    recency_score = max(0.0, 1.0 - age_hours / 24.0)
    available["recency"] = weights.get("recency", 0.05)
    breakdown["recency"] = {"weight": available["recency"], "score": recency_score, "source": f"{age_hours:.1f}h"}

    # ── Renormalise: divide by sum of available weights ──
    total_weight = sum(available.values())
    if total_weight <= 0:
        total_weight = 1.0

    raw_score = sum(available[k] * breakdown[k]["score"] for k in available) / total_weight
    final_score = int(min(max(raw_score * 100, 0), 100))

    # ── Level ──
    if final_score >= 80:
        level = "critical"
    elif final_score >= 60:
        level = "high"
    elif final_score >= 40:
        level = "medium"
    else:
        level = "low"

    return final_score, level, breakdown
