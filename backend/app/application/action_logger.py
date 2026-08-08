import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ..models import ActionLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    username: str,
    action: str,
    details: str = None,
    resource: str = None,
    ip_address: str = None,
    face_verified: bool = False,
    tenant_id: str = "default",
):
    try:
        log = ActionLog(
            username=username,
            action=action,
            details=details,
            resource=resource,
            ip_address=ip_address,
            face_verified=face_verified,
            tenant_id=tenant_id,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(log)
        db.commit()
    except Exception as e:
        logger.warning("Failed to log action: %s", e)
