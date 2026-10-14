"""F5 — Response Agent executor.

Claim, execute, rollback, and process pending recommendations.
"""
import json
import logging
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ...application.action_logger import log_action
from ...application.response.actions import get_action
from ...application.system_config import get_config_value
from ...db import SessionLocal
from ...domain.investigations import Investigation, InvestigationRecommendation
from ...domain.models import TimelineEvent
from ...domain.response import ResponseActionResult, ResponseRollback, ResponseRun

logger = logging.getLogger(__name__)


def claim_recommendation(db: Session, recommendation_id: int, run_ref: str) -> bool:
    """Atomically claim a pending recommendation. Returns True if claimed."""
    result = db.query(InvestigationRecommendation).filter(
        InvestigationRecommendation.id == recommendation_id,
        InvestigationRecommendation.status == "pending",
    ).update({
        "status": "accepted",
        "response_ref": run_ref,
        "updated_at": datetime.now(UTC),
    }, synchronize_session=False)
    db.commit()
    return result == 1


def execute_response_run(run_id: int) -> dict:
    """Execute a ResponseRun: load → approve if auto → run action → write result."""
    db = SessionLocal()
    try:
        run = db.query(ResponseRun).filter(ResponseRun.id == run_id).first()
        if run is None:
            return {"status": "error", "error": "run not found"}

        # Auto-approve if not requires_approval
        if not run.requires_approval:
            run.status = "approved"
            run.approved_by = "response_agent"
            run.approved_at = datetime.now(UTC)
            db.commit()

        if run.status != "approved" and run.status != "running":
            return {"status": "error", "error": f"run status {run.status} not executable"}

        # Transition to running
        run.status = "running"
        run.started_at = datetime.now(UTC)
        db.commit()

        # Look up action handler
        action_def = get_action(run.action_type)
        if action_def is None:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            db.commit()
            return {"status": "error", "error": f"unknown action_type: {run.action_type}"}

        if not action_def["implemented"]:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)
            db.commit()
            return {"status": "error", "error": f"action {run.action_type} not implemented"}

        # Enforce timeout
        timeout = action_def["timeout_seconds"]
        try:
            params = json.loads(run.params or "{}")
        except (ValueError, TypeError):
            params = {}
        start = time.monotonic()
        try:
            handler = action_def["handler"]
            ok, output, error = handler(db, run, params)
        except Exception as e:
            ok = False
            error = str(e)
            output = None
        elapsed = int((time.monotonic() - start) * 1000)

        # Write ResponseActionResult
        result = ResponseActionResult(
            tenant_id=run.tenant_id,
            run_id=run.id,
            attempt=1,
            status="success" if ok else "failed",
            output=json.dumps(output or {}, ensure_ascii=False) if output else None,
            error=error,
            duration_ms=elapsed,
        )
        db.add(result)

        if ok:
            run.status = "success"
            run.finished_at = datetime.now(UTC)

            # Mark recommendation as executed
            rec = db.query(InvestigationRecommendation).filter(
                InvestigationRecommendation.id == run.recommendation_id
            ).first()
            if rec:
                rec.status = "executed"
                rec.resolved_at = datetime.now(UTC)

            # Write rollback_plan if inverse exists
            inverse = action_def.get("inverse")
            if inverse:
                run.rollback_plan = json.dumps({
                    "action_type": inverse,
                    "target": run.target,
                    "original_params": params,
                    "output": output or {},
                }, ensure_ascii=False)

            # Audit trail
            log_action(db, "response_agent", "response.execute",
                        details=f"run {run.id}: {run.action_type} success",
                        resource=f"run:{run.id}", tenant_id=run.tenant_id)

            # Timeline event on investigation's case
            _add_timeline_on_case(db, run, f"Action {run.action_type} executed successfully")
        else:
            run.status = "failed"
            run.finished_at = datetime.now(UTC)

            rec = db.query(InvestigationRecommendation).filter(
                InvestigationRecommendation.id == run.recommendation_id
            ).first()
            if rec:
                rec.status = "failed"
                rec.resolved_at = datetime.now(UTC)

            log_action(db, "response_agent", "response.execute",
                        details=f"run {run.id}: {run.action_type} failed: {error}",
                        resource=f"run:{run.id}", tenant_id=run.tenant_id)

        db.commit()
        return {"status": run.status, "run_id": run.id}

    except Exception as e:
        logger.exception("execute_response_run %s failed", run_id)
        try:
            db.rollback()
            run = db.query(ResponseRun).filter(ResponseRun.id == run_id).first()
            if run:
                run.status = "failed"
                db.commit()
        except Exception:
            db.rollback()
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


def execute_rollback(run_id: int, reason: str) -> dict:
    """Execute rollback for a ResponseRun with a rollback_plan."""
    db = SessionLocal()
    try:
        run = db.query(ResponseRun).filter(ResponseRun.id == run_id).first()
        if run is None:
            return {"status": "error", "error": "run not found"}
        if not run.rollback_plan:
            return {"status": "error", "error": "no rollback_plan defined"}

        plan = json.loads(run.rollback_plan or "{}")
        inverse_action = plan.get("action_type")
        action_def = get_action(inverse_action)
        if action_def is None or not action_def["implemented"]:
            return {"status": "error", "error": f"rollback action {inverse_action} not implemented"}

        # Create ResponseRollback row
        rollback = ResponseRollback(
            tenant_id=run.tenant_id,
            run_id=run.id,
            action_type=inverse_action,
            target=plan.get("target"),
            params=json.dumps(plan.get("original_params", {}), ensure_ascii=False),
            status="running",
            initiated_by="response_agent",
            reason=reason,
        )
        db.add(rollback)
        db.flush()
        db.commit()

        # Execute the inverse action
        start = time.monotonic()
        try:
            handler = action_def["handler"]
            # Merge original params + action output so inverse handlers can
            # resolve quarantine metadata (paths, sha256) embedded at execution.
            params = {
                **plan.get("original_params", {}),
                **plan.get("output", {}),
            }
            ok, output, error = handler(db, run, params)
        except Exception as e:
            ok = False
            error = str(e)
            output = None
        elapsed = int((time.monotonic() - start) * 1000)

        rollback.status = "success" if ok else "failed"
        rollback.output = json.dumps(output or {}, ensure_ascii=False) if output else None
        rollback.error = error
        rollback.executed_at = datetime.now(UTC)
        db.commit()

        log_action(db, "response_agent", "response.rollback",
                    details=f"rollback run {run_id}: {inverse_action}",
                    resource=f"run:{run_id}", tenant_id=run.tenant_id)

        return {"status": rollback.status, "rollback_id": rollback.id}

    except Exception as e:
        logger.exception("execute_rollback %s failed", run_id)
        try:
            db.rollback()
        except Exception:
            pass
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


def process_pending_recommendations(db: Session, tenant_id: str | None = None, limit: int = 50,
                                    investigation_id: int | None = None) -> int:
    """Scan pending recommendations on awaiting_response investigations and create ResponseRuns."""
    q = db.query(InvestigationRecommendation).filter(
        InvestigationRecommendation.status == "pending",
    )
    if investigation_id is not None:
        q = q.filter(InvestigationRecommendation.investigation_id == investigation_id)
    if tenant_id:
        q = q.join(Investigation).filter(
            Investigation.status == "awaiting_response",
            Investigation.tenant_id == tenant_id,
        ).limit(limit).all()
    else:
        q = q.join(Investigation).filter(
            Investigation.status == "awaiting_response",
        ).limit(limit).all()
    recs = q

    processed = 0
    for rec in recs:
        try:
            inv = db.query(Investigation).filter(Investigation.id == rec.investigation_id).first()
            if inv is None or inv.case_id is None:
                continue

            action_def = get_action(rec.action_type)
            if action_def is None:
                continue

            requires_approval = action_def["requires_approval"] and rec.action_type not in ("notify", "monitor", "escalate", "run_playbook")
            # Auto-approve for configured actions
            auto_approve_actions = get_config_value(db, "response", "auto_approve_actions", "notify,monitor,escalate,run_playbook", tenant_id=rec.tenant_id or "default")
            auto_approve_list = [a.strip() for a in auto_approve_actions.split(",")]
            if rec.action_type in auto_approve_list:
                requires_approval = False

            run = ResponseRun(
                tenant_id=rec.tenant_id or "default",
                investigation_id=rec.investigation_id,
                recommendation_id=rec.id,
                action_type=rec.action_type,
                target=rec.target,
                params=json.dumps({"rationale": rec.rationale or ""}, ensure_ascii=False),
                requires_approval=requires_approval,
                status="pending_approval" if requires_approval else "approved",
            )
            db.add(run)
            db.flush()

            # Claim the recommendation (atomic). If another path already claimed
            # it, drop this run — its recommendation_id is UNIQUE.
            claimed = claim_recommendation(db, rec.id, f"run:{run.id}")
            if not claimed:
                db.delete(run)
                db.commit()
                continue

            if not requires_approval:
                # Execute inline
                db.commit()
                execute_response_run(run.id)
            else:
                db.commit()

            processed += 1
        except Exception as e:
            logger.warning("process_pending rec %s failed: %s", rec.id, e)
            try:
                db.rollback()
            except Exception:
                pass

    return processed


def _add_timeline_on_case(db: Session, run: ResponseRun, message: str) -> None:
    """Write a TimelineEvent on the investigation's case (reuse cases.py pattern)."""
    inv = db.query(Investigation).filter(Investigation.id == run.investigation_id).first()
    if inv and inv.case_id:
        ev = TimelineEvent(
            tenant_id=run.tenant_id or "default",
            case_id=inv.case_id,
            event_type="response_executed",
            actor="response_agent",
            message=message,
        )
        db.add(ev)
