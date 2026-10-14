"""F5 — Orchestrator for automated investigation.

Main entry: run_investigation_for_event(event_id, tenant_id).
Idempotent, crash-resilient, commit-after-each-step.
"""
import hashlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from ...application.cases import _add_timeline
from ...application.events import InvestigationCompleteEvent, RuleMatchEvent
from ...application.investigations.llm import generate_summary
from ...application.investigations.recommendations import generate_recommendations
from ...application.investigations.scoring import compute_risk_score
from ...application.investigations.steps import (
    step_asset,
    step_host_wazuh,
    step_mitre_context,
    step_related_alerts,
    step_threat_intel_dest,
    step_threat_intel_src,
)
from ...application.investigations.summaries import template_summary
from ...application.system_config import get_config_value
from ...db import SessionLocal
from ...domain.investigations import Investigation, InvestigationEvidence, InvestigationRecommendation
from ...domain.models import Alert, Case, CaseAlertLink, SuricataAlert

logger = logging.getLogger(__name__)

COLLECTION_STEPS = [
    step_threat_intel_src,
    step_threat_intel_dest,
    step_host_wazuh,
    step_asset,
    step_related_alerts,
    step_mitre_context,
]

PER_STEP_TIMEOUT = 30
DEDUP_WINDOW_HOURS_DEFAULT = 24
MAX_PER_DAY_DEFAULT = 20
MAX_CONCURRENT_DEFAULT = 3


def _now() -> datetime:
    return datetime.now(UTC)


def _make_dedup_fingerprint(tenant_id: str, event: RuleMatchEvent) -> str:
    src_ip = event.normalized_alert.get("src_ip") or "-"
    dest_ip = event.normalized_alert.get("dest_ip") or "-"
    signature = event.normalized_alert.get("signature") or event.normalized_alert.get("description") or ""
    raw = f"{tenant_id}|{src_ip}|{dest_ip}|{signature}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def _resolve_alert(db: Session, tenant_id: str, alert_type: str, alert_id: int):
    model = SuricataAlert if alert_type == "suricata" else (Alert if alert_type == "alert" else None)
    if model is None:
        return None
    return db.query(model).filter(model.id == alert_id, model.tenant_id == tenant_id).first()


def _create_case_for_investigation(
    db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent
) -> Case:
    src_ip = event.normalized_alert.get("src_ip") or ""
    dest_ip = event.normalized_alert.get("dest_ip") or ""
    signature = event.normalized_alert.get("signature") or event.normalized_alert.get("description") or ""
    max_sev = max(
        (int(r.get("rule_severity", 0)) for r in (event.matched_rules or []) if isinstance(r, dict)),
        default=5,
    )
    severity = max(0, min(15, max_sev))
    title = f"Investigation: {signature[:100]} ({src_ip} -> {dest_ip})"[:200]

    case = Case(
        tenant_id=tenant_id,
        title=title,
        description=f"Auto-created from investigation event {event.event_id}. Severity: {severity}",
        status="open",
        severity=severity,
        created_by="investigation",
    )
    db.add(case)
    db.flush()
    return case


def _add_evidence_row(
    db: Session, tenant_id: str, investigation_id: int,
    step_key: str, source: str, status: str = "success",
    payload: dict | None = None, error: str | None = None, summary: str = "",
) -> None:
    ev = InvestigationEvidence(
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        step_key=step_key,
        evidence_type=source,
        source=source,
        status=status,
        summary=summary,
        payload=json.dumps(payload or {}, ensure_ascii=False),
        error=error,
    )
    db.add(ev)


def _link_case_alert(db: Session, tenant_id: str, case_id: int, alert_type: str, alert_id: int) -> None:
    if not case_id:
        return
    dup = db.query(CaseAlertLink).filter(
        CaseAlertLink.case_id == case_id,
        CaseAlertLink.alert_type == alert_type,
        CaseAlertLink.alert_id == alert_id,
        CaseAlertLink.tenant_id == tenant_id,
    ).first()
    if dup is None:
        link = CaseAlertLink(
            tenant_id=tenant_id, case_id=case_id,
            alert_type=alert_type, alert_id=alert_id,
            status="open", created_by="investigation",
        )
        db.add(link)


def _link_trigger_alert(db: Session, tenant_id: str, investigation: Investigation, event: RuleMatchEvent) -> None:
    _link_case_alert(db, tenant_id, investigation.case_id or 0, investigation.trigger_alert_type, investigation.trigger_alert_id)


def _add_linked_evidence(db: Session, tenant_id: str, investigation_id: int, event: RuleMatchEvent) -> None:
    alert_type = event.normalized_alert.get("alert_type", "alert")
    alert_id = event.normalized_alert.get("alert_id", 0)
    step_key = f"linked:alert:{alert_id}"
    payload = {"alert_type": alert_type, "alert_id": alert_id}
    ev = InvestigationEvidence(
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        step_key=step_key,
        evidence_type="linked_alert",
        source="pipeline",
        status="success",
        summary=f"Linked alert {alert_type}#{alert_id} (dedup)",
        payload=json.dumps(payload),
    )
    db.add(ev)


def _run_step_with_timeout(
    step_func, db: Session, tenant_id: str,
    investigation: Investigation, event: RuleMatchEvent, timeout: int = PER_STEP_TIMEOUT
) -> tuple[str | None, dict | None, str | None]:
    start = time.monotonic()
    result = step_func(db, tenant_id, investigation, event)
    elapsed = time.monotonic() - start
    if elapsed > timeout:
        logger.warning("Step %s took %.1fs (timeout %ds)", step_func.__name__, elapsed, timeout)
    return result


def run_investigation_for_event(event_id: str, tenant_id: str) -> dict:
    """Main entry: run full investigation pipeline for a RuleMatchEvent."""
    db = SessionLocal()
    try:
        # ── Re-read event from payload ──
        from ...domain.rule_models import RuleMatchOutbox
        outbox = db.query(RuleMatchOutbox).filter(RuleMatchOutbox.event_id == event_id).first()
        if outbox is None:
            logger.warning("Event %s not found in outbox", event_id)
            return {"status": "error", "error": "event not found"}

        payload = json.loads(outbox.payload or "{}")
        event = RuleMatchEvent(**payload)
        tenant_id = event.tenant_id or tenant_id or "default"

        # ── Idempotency guard (first thing) ──
        dedup_fp = _make_dedup_fingerprint(tenant_id, event)
        dedup_window_hours = int(get_config_value(db, "investigation", "dedup_window_hours", str(DEDUP_WINDOW_HOURS_DEFAULT), tenant_id=tenant_id))
        cutoff = _now() - timedelta(hours=dedup_window_hours)

        existing = db.query(Investigation).filter(
            Investigation.tenant_id == tenant_id,
            Investigation.dedup_fingerprint == dedup_fp,
            Investigation.created_at >= cutoff,
        ).first()
        if existing:
            logger.info("Event %s already investigated (dedup) — linking", event_id)
            _link_trigger_alert(db, tenant_id, existing, event)
            _add_linked_evidence(db, tenant_id, existing.id, event)
            existing.updated_at = _now()
            db.commit()
            return {"status": "linked", "investigation_id": existing.id}

        # ── Quota check ──
        max_per_day = int(get_config_value(db, "investigation", "max_per_day", str(MAX_PER_DAY_DEFAULT), tenant_id=tenant_id))
        max_concurrent = int(get_config_value(db, "investigation", "max_concurrent", str(MAX_CONCURRENT_DEFAULT), tenant_id=tenant_id))

        start_of_day = _now().replace(hour=0, minute=0, second=0, microsecond=0)
        runs_today = db.query(Investigation.id).filter(
            Investigation.tenant_id == tenant_id,
            Investigation.created_at >= start_of_day,
        ).count()
        if runs_today >= max_per_day:
            logger.warning("Quota exceeded for %s (%d/day)", tenant_id, max_per_day)
            return {"status": "quota_exceeded", "investigation_id": None}

        running_count = db.query(Investigation.id).filter(
            Investigation.tenant_id == tenant_id,
            Investigation.status == "running",
        ).count()
        if running_count >= max_concurrent:
            logger.warning("Concurrent limit reached for %s (%d running)", tenant_id, running_count)
            return {"status": "queued", "investigation_id": None}

        # ── Create Investigation row ──
        investigation = Investigation(
            tenant_id=tenant_id,
            event_id=event_id,
            trigger_alert_type=event.normalized_alert.get("alert_type", "alert"),
            trigger_alert_id=int(event.normalized_alert.get("alert_id", 0)),
            dedup_fingerprint=dedup_fp,
            status="running",
            created_by="investigation",
        )
        db.add(investigation)
        db.flush()

        # ── Auto-create Case ──
        case = _create_case_for_investigation(db, tenant_id, investigation, event)
        investigation.case_id = case.id

        # Link trigger alert
        alert_type = investigation.trigger_alert_type
        alert_id = investigation.trigger_alert_id
        _link_case_alert(db, tenant_id, case.id, alert_type, alert_id)

        # Timeline: investigation_started
        _add_timeline(db, tenant_id, case.id, "investigation_started", "investigation",
                        f"Investigation started for event {event_id}")
        db.commit()

        # ── Run collection steps ──
        missing_steps: list = []
        for step_func in COLLECTION_STEPS:
            try:
                step_key, payload, error = _run_step_with_timeout(
                    step_func, db, tenant_id, investigation, event
                )
                if error:
                    missing_steps.append(step_func.__name__)
                    sk = step_key if step_key else step_func.__name__
                    _add_evidence_row(db, tenant_id, investigation.id, sk, step_func.__name__, "failed", error=error)
                elif payload is not None:
                    sk = step_key if step_key else step_func.__name__
                    _add_evidence_row(db, tenant_id, investigation.id, sk, step_func.__name__, "success", payload=payload)
                elif step_key is not None:
                    _add_evidence_row(db, tenant_id, investigation.id, step_key, step_func.__name__, "skipped")
            except Exception as e:
                logger.warning("Step %s failed: %s", step_func.__name__, e)
                missing_steps.append(step_func.__name__)
                db.rollback()
                try:
                    _add_evidence_row(db, tenant_id, investigation.id, step_func.__name__, step_func.__name__, "failed", error=str(e))
                    db.commit()
                except Exception:
                    db.rollback()

        # Timeline: evidence_added
        _add_timeline(db, tenant_id, case.id, "evidence_added", "investigation",
                        f"Collected evidence from {len(COLLECTION_STEPS) - len(missing_steps)}/{len(COLLECTION_STEPS)} steps")
        db.commit()

        # ── Scoring ──
        intel_verdict = "unknown"
        intel_score = None
        host_dept = None
        is_wazuh_agent = False
        has_asset = False
        related_count = 0
        mitre_tactics: list = []

        for ev_row in db.query(InvestigationEvidence).filter(
            InvestigationEvidence.investigation_id == investigation.id
        ).all():
            try:
                p = json.loads(ev_row.payload or "{}")
                sk = ev_row.step_key or ""
                if sk.startswith("ti:"):
                    intel_verdict = p.get("verdict", "unknown")
                    intel_score = p.get("risk_score")
                elif sk.startswith("host:"):
                    host_dept = p.get("department")
                    is_wazuh_agent = bool(p.get("agent_id") or p.get("ip"))
                elif sk.startswith("asset:"):
                    has_asset = True
                    host_dept = p.get("department")
                elif sk.startswith("corr:"):
                    related_count = p.get("count", 0)
                elif sk.startswith("mitre:"):
                    mitre_tactics = p.get("tactics", [])
            except (json.JSONDecodeError, TypeError):
                pass

        max_rule_sev = max(
            (int(r.get("rule_severity", 0)) for r in (event.matched_rules or []) if isinstance(r, dict)),
            default=5,
        )
        score, level, breakdown = compute_risk_score(
            db, tenant_id,
            severity=max_rule_sev,
            intel_verdict=intel_verdict,
            intel_score=intel_score,
            host_dept=host_dept,
            is_wazuh_agent=is_wazuh_agent,
            has_asset=has_asset,
            related_count=related_count,
            mitre_tactics=mitre_tactics,
            age_hours=0.0,
        )

        investigation.risk_score = score
        investigation.risk_level = level
        investigation.score_breakdown = json.dumps(breakdown, ensure_ascii=False)
        investigation.status = "scoring"
        case.severity = max(0, min(15, round(score * 15 / 100)))
        db.commit()

        _add_timeline(db, tenant_id, case.id, "scored", "investigation", f"Risk score: {score} ({level})")
        db.commit()

        # ── LLM Summary ──
        evidence_rows = db.query(InvestigationEvidence).filter(
            InvestigationEvidence.investigation_id == investigation.id
        ).all()

        summary = None
        try:
            llm_enabled = get_config_value(db, "investigation", "llm_enabled", "true", tenant_id=tenant_id) == "true"
            if llm_enabled:
                summary = generate_summary(db, tenant_id, investigation, evidence_rows)
        except Exception as e:
            logger.warning("LLM summary failed: %s", e)

        if summary is None:
            summary = template_summary(investigation, event, evidence_rows)
            investigation.completion = "partial"
            missing_steps.append("llm_summary")
        else:
            investigation.completion = "full"

        investigation.summary = summary
        investigation.status = "summarizing"
        db.commit()

        _add_timeline(db, tenant_id, case.id, "summary_generated", "investigation", "Summary generated")
        db.commit()

        # ── Recommendations ──
        recs = generate_recommendations(db, tenant_id, investigation, event, evidence_rows, score, level)
        for rec_data in recs:
            rec = InvestigationRecommendation(
                tenant_id=tenant_id,
                investigation_id=investigation.id,
                action_type=rec_data["action_type"],
                target=rec_data.get("target"),
                priority=rec_data.get("priority", 3),
                confidence=rec_data.get("confidence", 0.5),
                rationale=rec_data.get("rationale", ""),
                source=rec_data.get("source", "rule_based"),
                status="pending",
            )
            db.add(rec)
        db.commit()

        _add_timeline(db, tenant_id, case.id, "recommendations_ready", "investigation", f"{len(recs)} recommendations generated")
        db.commit()

        # ── Final status ──
        pending_recs = db.query(InvestigationRecommendation.id).filter(
            InvestigationRecommendation.investigation_id == investigation.id,
            InvestigationRecommendation.status == "pending",
        ).count()
        investigation.status = "awaiting_response" if pending_recs > 0 else "complete"
        investigation.completed_at = _now()
        investigation.missing_steps = json.dumps(missing_steps) if missing_steps else None
        db.commit()

        # Publish investigation complete event (lazy import to avoid cycle)
        if pending_recs > 0:
            try:
                from ...application.events import CHANNEL_INVESTIGATION_COMPLETE, event_bus
                evt = InvestigationCompleteEvent(
                    event_id=f"resp:{investigation.id}",
                    timestamp=_now().isoformat(),
                    tenant_id=investigation.tenant_id,
                    channel=CHANNEL_INVESTIGATION_COMPLETE,
                    version=1,
                    source="investigation",
                    investigation_id=investigation.id,
                    case_id=investigation.case_id,
                    risk_level=investigation.risk_level,
                )
                event_bus._dispatch(CHANNEL_INVESTIGATION_COMPLETE, evt)  # type: ignore[arg-type]
            except Exception:
                logger.exception("failed publishing investigation complete")

        return {"status": investigation.status, "investigation_id": investigation.id, "risk_score": score}

    except Exception as e:
        logger.exception("run_investigation_for_event failed for %s", event_id)
        try:
            db.rollback()
            inv = db.query(Investigation).filter(Investigation.event_id == event_id).first()
            if inv:
                inv.status = "failed"
                inv.missing_steps = json.dumps([str(e)])
                db.commit()
        except Exception:
            db.rollback()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()
