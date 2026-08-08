import base64
import os
import json
import hashlib
import logging
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from ..models import AccessLog
from ..schemas import AccessLogCreate

logger = logging.getLogger(__name__)

SURVEILLANCE_FACE_DIR = Path(__file__).resolve().parent.parent / "face_data" / "surveillance"
MAPPING_FILE = SURVEILLANCE_FACE_DIR / "surveillance_mapping.json"


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_mapping() -> dict:
    if MAPPING_FILE.exists():
        try:
            with open(MAPPING_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            return {}
    return {}


def _write_mapping(mapping: dict):
    SURVEILLANCE_FACE_DIR.mkdir(parents=True, exist_ok=True)
    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=2)


class SurveillanceService:
    def __init__(self):
        SURVEILLANCE_FACE_DIR.mkdir(parents=True, exist_ok=True)

    def record_login(self, db: Session, data: AccessLogCreate, tenant_id: str = "default") -> AccessLog:
        face_hash = None
        if data.face_image:
            face_hash = self._save_face_image(data.face_image, tenant_id)

        mapping_entry = None
        if face_hash:
            mapping = _read_mapping()
            mapping[face_hash] = {
                "username": data.username,
                "tenant_id": tenant_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            _write_mapping(mapping)
            mapping_entry = face_hash

        log_entry = AccessLog(
            username=data.username,
            login_time=datetime.now(timezone.utc),
            is_online=True,
            face_image=mapping_entry,
            face_verified=data.face_verified,
            ip_address=data.ip_address,
            login_method=data.login_method,
            tenant_id=tenant_id,
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        logger.info("Login recorded: %s at %s (tenant: %s)", data.username, log_entry.login_time, tenant_id)
        return log_entry

    def record_logout(self, db: Session, username: str, tenant_id: str = "default"):
        log_entry = (
            db.query(AccessLog)
            .filter(
                AccessLog.username == username,
                AccessLog.is_online == True,
                AccessLog.tenant_id == tenant_id,
            )
            .order_by(desc(AccessLog.login_time))
            .first()
        )
        if log_entry:
            now = datetime.now(timezone.utc)
            log_entry.logout_time = now
            log_entry.is_online = False
            duration = (now - log_entry.login_time).total_seconds()
            log_entry.session_duration = int(duration)
            db.commit()
            db.refresh(log_entry)
            logger.info("Logout recorded: %s at %s (duration: %ds, tenant: %s)", username, now, int(duration), tenant_id)
        return log_entry

    def get_online_users(self, db: Session, tenant_id: str = "default"):
        return (
            db.query(AccessLog)
            .filter(AccessLog.is_online == True, AccessLog.tenant_id == tenant_id)
            .order_by(desc(AccessLog.login_time))
            .all()
        )

    def get_logs(self, db: Session, limit: int = 50, offset: int = 0, tenant_id: str = "default"):
        total = db.query(AccessLog).filter(AccessLog.tenant_id == tenant_id).count()
        logs = (
            db.query(AccessLog)
            .filter(AccessLog.tenant_id == tenant_id)
            .order_by(desc(AccessLog.login_time))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return logs, total

    def get_stats(self, db: Session, tenant_id: str = "default") -> dict:
        today = date.today()
        today_start = datetime(today.year, today.month, today.day)

        total_logins_today = (
            db.query(AccessLog)
            .filter(AccessLog.login_time >= today_start, AccessLog.tenant_id == tenant_id)
            .count()
        )

        users_online = (
            db.query(AccessLog)
            .filter(AccessLog.is_online == True, AccessLog.tenant_id == tenant_id)
            .count()
        )

        avg_seconds = (
            db.query(func.avg(AccessLog.session_duration))
            .filter(AccessLog.session_duration.isnot(None), AccessLog.tenant_id == tenant_id)
            .scalar()
        )
        avg_session_minutes = round(avg_seconds / 60, 1) if avg_seconds else None

        total_users = (
            db.query(AccessLog.username)
            .filter(AccessLog.tenant_id == tenant_id)
            .distinct()
            .count()
        )

        total_with_face = (
            db.query(AccessLog)
            .filter(AccessLog.face_verified == True, AccessLog.tenant_id == tenant_id)
            .count()
        )
        total_all = db.query(AccessLog).filter(AccessLog.tenant_id == tenant_id).count()
        face_pct = round((total_with_face / total_all * 100), 1) if total_all > 0 else 0

        hourly_logins = (
            db.query(
                func.extract("hour", AccessLog.login_time).label("hour"),
                func.count(AccessLog.id).label("count"),
            )
            .filter(AccessLog.login_time >= today_start, AccessLog.tenant_id == tenant_id)
            .group_by("hour")
            .order_by("hour")
            .all()
        )

        return {
            "total_logins_today": total_logins_today,
            "users_online": users_online,
            "avg_session_minutes": avg_session_minutes,
            "total_users_registered": total_users,
            "face_auth_percentage": face_pct,
            "hourly_logins": [{"hour": int(r.hour), "count": r.count} for r in hourly_logins],
        }

    def _save_face_image(self, image_data: str, tenant_id: str = "default") -> Optional[str]:
        try:
            if "," in image_data:
                image_data = image_data.split(",")[1]
            img_bytes = base64.b64decode(image_data)
            image_hash = _hash_bytes(img_bytes)
            tenant_dir = SURVEILLANCE_FACE_DIR / tenant_id
            tenant_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{image_hash}.jpg"
            filepath = tenant_dir / filename
            if not filepath.exists():
                with open(filepath, "wb") as f:
                    f.write(img_bytes)
            return image_hash
        except Exception as e:
            logger.error("Failed to save face image: %s", e)
            return None

    def get_face_image_base64(self, image_hash: str, tenant_id: str = "default") -> Optional[str]:
        try:
            tenant_dir = SURVEILLANCE_FACE_DIR / tenant_id
            filepath = tenant_dir / f"{image_hash}.jpg"
            if not filepath.exists():
                return None
            with open(filepath, "rb") as f:
                img_bytes = f.read()
            return base64.b64encode(img_bytes).decode("utf-8")
        except Exception as e:
            logger.error("Failed to read face image: %s", e)
            return None

surveillance_service = SurveillanceService()
