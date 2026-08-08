import json
import logging
from datetime import datetime, date, timezone
from typing import Optional

import redis as _redis
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, extract

from ...db import get_db, get_tenant_id, query_with_tenant
from ...models import ActionLog, AccessLog, TenantUser
from ...schemas import ActionLogCreate
from ...config import settings
from ...admin_auth import create_admin_token, get_current_admin, verify_admin_password
from ...core.rbac import ADMIN_ASSIGNABLE, ROLE_RANK, ROLE_WHITELIST, require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])

_redis_client = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


@router.post("/token")
async def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    # Rate limit: 5 admin login attempts per minute per IP
    client_ip = request.client.host if request else "unknown"
    key = f"ratelimit:admin:{client_ip}"
    try:
        count = _redis_client.incr(key)
        if count == 1:
            _redis_client.expire(key, 60)
        if count > 5:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Trop de tentatives admin. Réessayez dans une minute.",
            )
    except _redis.ConnectionError:
        pass  # Fail open if Redis is down

    # Only "admin" username is allowed
    if form_data.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants admin incorrects",
        )

    if not verify_admin_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants admin incorrects",
        )
    token = create_admin_token()
    return {"access_token": token, "token_type": "bearer", "role": "admin"}


@router.post("/actions/log")
async def log_action(
    data: ActionLogCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    ip = data.ip_address or (request.client.host if request.client else None)
    log = ActionLog(
        username=data.username,
        action=data.action,
        details=data.details,
        resource=data.resource,
        ip_address=ip,
        face_verified=data.face_verified,
        tenant_id=get_tenant_id(request),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(log)
    db.commit()
    return {"status": "logged", "id": log.id}


@router.get("/actions")
async def get_actions(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    username: Optional[str] = None,
    action: Optional[str] = None,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    query = query_with_tenant(ActionLog, request, db)
    if username:
        query = query.filter(ActionLog.username == username)
    if action:
        query = query.filter(ActionLog.action == action)
    total = query.count()
    logs = (
        query.order_by(desc(ActionLog.timestamp))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "items": [
            {
                "id": l.id,
                "username": l.username,
                "action": l.action,
                "details": l.details,
                "resource": l.resource,
                "ip_address": l.ip_address,
                "face_verified": l.face_verified,
                "timestamp": l.timestamp.isoformat(),
            }
            for l in logs
        ],
        "total": total,
    }


@router.get("/analysts")
async def get_analysts(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    online_users = (
        query_with_tenant(AccessLog, request, db)
        .filter(AccessLog.is_online == True)
        .order_by(desc(AccessLog.login_time))
        .all()
    )
    analysts = []
    for u in online_users:
        face_b64 = None
        if u.face_image:
            from ...services.surveillance_service import surveillance_service
            face_b64 = surveillance_service.get_face_image_base64(u.face_image)
        analysts.append({
            "id": u.id,
            "username": u.username,
            "login_time": u.login_time.isoformat(),
            "face_verified": u.face_verified,
            "face_image": face_b64,
            "ip_address": u.ip_address,
            "login_method": u.login_method,
        })
    return analysts


@router.get("/analysts/{username}/actions")
async def get_analyst_actions(
    request: Request,
    username: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    logs = (
        query_with_tenant(ActionLog, request, db)
        .filter(ActionLog.username == username)
        .order_by(desc(ActionLog.timestamp))
        .limit(limit)
        .all()
    )
    return [
        {
            "id": l.id,
            "action": l.action,
            "details": l.details,
            "resource": l.resource,
            "timestamp": l.timestamp.isoformat(),
        }
        for l in logs
    ]


@router.get("/analysts/{username}/sessions")
async def get_analyst_sessions(
    request: Request,
    username: str,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    logs = (
        query_with_tenant(AccessLog, request, db)
        .filter(AccessLog.username == username)
        .order_by(desc(AccessLog.login_time))
        .limit(limit)
        .all()
    )
    return [
        {
            "id": l.id,
            "login_time": l.login_time.isoformat(),
            "logout_time": l.logout_time.isoformat() if l.logout_time else None,
            "is_online": l.is_online,
            "session_duration": l.session_duration,
            "face_verified": l.face_verified,
            "login_method": l.login_method,
        }
        for l in logs
    ]


@router.get("/stats")
async def get_admin_stats(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    today = date.today()
    today_start = datetime(today.year, today.month, today.day)

    total_analysts = query_with_tenant(ActionLog, request, db).with_entities(ActionLog.username).distinct().count()
    active_sessions = query_with_tenant(AccessLog, request, db).filter(AccessLog.is_online == True).count()

    total_actions_today = (
        query_with_tenant(ActionLog, request, db)
        .filter(ActionLog.timestamp >= today_start)
        .count()
    )

    actions_by_type_rows = (
        query_with_tenant(ActionLog, request, db)
        .with_entities(ActionLog.action, func.count(ActionLog.id))
        .filter(ActionLog.timestamp >= today_start)
        .group_by(ActionLog.action)
        .all()
    )
    actions_by_type = {row[0]: row[1] for row in actions_by_type_rows}

    hourly_rows = (
        query_with_tenant(ActionLog, request, db)
        .with_entities(
            extract("hour", ActionLog.timestamp).label("hour"),
            func.count(ActionLog.id).label("count"),
        )
        .filter(ActionLog.timestamp >= today_start)
        .group_by("hour")
        .order_by("hour")
        .all()
    )
    hourly_activity = [{"hour": int(r.hour), "count": r.count} for r in hourly_rows]

    return {
        "total_analysts": total_analysts,
        "active_sessions": active_sessions,
        "total_actions_today": total_actions_today,
        "actions_by_type": actions_by_type,
        "hourly_activity": hourly_activity,
    }


@router.post("/analysts/{username}/force-logout")
async def force_logout(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    from ...services.surveillance_service import surveillance_service
    tenant_id = get_tenant_id(request)
    log_entry = surveillance_service.record_logout(db, username, tenant_id=tenant_id)
    if not log_entry:
        raise HTTPException(status_code=404, detail="No active session found")
    return {"status": "force_logged_out", "username": username}


@router.get("/face/status")
async def admin_face_status(
    request: Request,
    admin=Depends(get_current_admin),
):
    """Check if admin face is registered."""
    from ...services.face_service import face_service
    tenant_id = get_tenant_id(request)
    registered = face_service.has_registered_face("admin", tenant_id=tenant_id)
    return {"username": "admin", "registered": registered}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
async def change_admin_password(
    data: ChangePasswordRequest,
    admin=Depends(get_current_admin),
):
    """Change the admin password (persisted to password hash store)."""
    from ...services.password_manager import store_password_hash, check_password
    from ...config import settings

    admin_key = settings.ADMIN_API_KEY.get_secret_value()

    if data.current_password != admin_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mot de passe actuel incorrect",
        )

    if len(data.new_password) < 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le nouveau mot de passe doit contenir au moins 4 caractères",
        )

    store_password_hash("admin_api_key", data.new_password)
    logger.info("Admin password changed successfully")
    return {"status": "success", "message": "Mot de passe modifié avec succès"}


class RoleUpdateRequest(BaseModel):
    role: str


@router.get("/users")
async def list_users(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role("admin")),
):
    """List tenant users (excluding super_admin accounts)."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    users = (
        db.query(TenantUser)
        .filter(TenantUser.tenant_id == tenant_id, TenantUser.role != "super_admin")
        .all()
    )
    return [
        {
            "username": u.username,
            "role": u.role,
            "tenant_id": u.tenant_id,
            "email": u.email,
            "is_active": u.is_active,
        }
        for u in users
    ]


@router.patch("/users/{username}/role")
async def update_user_role(
    username: str,
    data: RoleUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_role("admin")),
):
    """Change a user's role within the current tenant (admin)."""
    new_role = data.role
    if new_role not in ROLE_WHITELIST:
        raise HTTPException(
            status_code=400,
            detail="Role must be one of: viewer, analyst, admin, super_admin",
        )
    tenant_id = getattr(request.state, "tenant_id", "default")
    target = (
        db.query(TenantUser)
        .filter(TenantUser.username == username, TenantUser.tenant_id == tenant_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.role == "super_admin":
        raise HTTPException(status_code=403, detail="Cannot modify a super_admin account")
    if new_role not in ADMIN_ASSIGNABLE:
        raise HTTPException(status_code=400, detail="Only a super admin can assign super_admin")
    if target.role == "admin" and ROLE_RANK[new_role] < 2:
        admin_count = (
            db.query(TenantUser)
            .filter(TenantUser.tenant_id == tenant_id, TenantUser.role == "admin")
            .count()
        )
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot demote the last admin of the tenant")
    target.role = new_role
    db.commit()
    from ...services.password_manager import _read_store, _write_store
    s = _read_store()
    s[f"role:{username}"] = new_role
    _write_store(s)
    return {"username": username, "role": new_role, "tenant_id": tenant_id}
