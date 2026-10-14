"""F5 — Deterministic template fallback for investigation summaries."""
import json

from ...application.events import RuleMatchEvent
from ...domain.investigations import Investigation


def template_summary(investigation: Investigation, event: RuleMatchEvent, evidence_rows: list) -> str:
    """Generate a deterministic summary string from investigation state."""
    src_ip = event.normalized_alert.get("src_ip", "-")
    dest_ip = event.normalized_alert.get("dest_ip", "-")
    signature = event.normalized_alert.get("signature") or event.normalized_alert.get("description") or "-"
    severity = investigation.risk_level or "unknown"

    # Extract TI verdict and related count from evidence
    ti_verdict = "unknown"
    n_alerts = 0
    employee = "-"
    department = "-"
    for ev in evidence_rows:
        try:
            p = json.loads(ev.payload or "{}")
            if ev.step_key and ev.step_key.startswith("ti:"):
                ti_verdict = p.get("verdict", "unknown")
            elif ev.step_key and ev.step_key.startswith("corr:"):
                n_alerts = p.get("count", 0)
            elif ev.step_key and ev.step_key.startswith("asset:"):
                employee = p.get("employee", "-")
                department = p.get("department", "-")
        except (json.JSONDecodeError, TypeError):
            pass

    return f"[{severity.upper()}] {signature} from {src_ip} to {dest_ip} — TI {ti_verdict}, {n_alerts} alertes corrélées, asset {employee}/{department}"
