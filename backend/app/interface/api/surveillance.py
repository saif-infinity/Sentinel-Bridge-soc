
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ...auth import has_scopes_or_api_key
from ...db import get_db, get_tenant_id
from ...schemas import AccessLogCreate
from ...services.surveillance_service import surveillance_service

router = APIRouter(prefix="/api/surveillance", tags=["surveillance"])


@router.post("/login", dependencies=[Depends(has_scopes_or_api_key(["surveillance:write"]))])
async def record_login(
    request: Request,
    data: AccessLogCreate,
    db: Session = Depends(get_db),
):
    ip = request.client.host if request.client else None
    data.ip_address = data.ip_address or ip
    tenant_id = get_tenant_id(request)
    log_entry = surveillance_service.record_login(db, data, tenant_id=tenant_id)
    return {
        "status": "success",
        "id": log_entry.id,
        "login_time": log_entry.login_time.isoformat(),
    }


@router.post("/logout", dependencies=[Depends(has_scopes_or_api_key(["surveillance:write"]))])
async def record_logout(
    request: Request,
    username: str,
    db: Session = Depends(get_db),
):
    tenant_id = get_tenant_id(request)
    log_entry = surveillance_service.record_logout(db, username, tenant_id=tenant_id)
    if not log_entry:
        raise HTTPException(status_code=404, detail="No active session found for this user")
    return {"status": "success", "logout_time": log_entry.logout_time.isoformat()}


@router.get("/online", dependencies=[Depends(has_scopes_or_api_key(["surveillance:read"]))])
async def get_online_users(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    users = surveillance_service.get_online_users(db, tenant_id=tenant_id)
    results = []
    for u in users:
        face_base64 = None
        if u.face_image:
            face_base64 = surveillance_service.get_face_image_base64(u.face_image, tenant_id=tenant_id)
        results.append({
            "id": u.id,
            "username": u.username,
            "login_time": u.login_time.isoformat(),
            "face_verified": u.face_verified,
            "face_image": face_base64,
        })
    return results


@router.get("/logs", dependencies=[Depends(has_scopes_or_api_key(["surveillance:read"]))])
async def get_logs(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    tenant_id = get_tenant_id(request)
    logs, total = surveillance_service.get_logs(db, limit, offset, tenant_id=tenant_id)
    results = []
    for log in logs:
        face_base64 = None
        if log.face_image:
            face_base64 = surveillance_service.get_face_image_base64(log.face_image, tenant_id=tenant_id)
        results.append({
            "id": log.id,
            "username": log.username,
            "login_time": log.login_time.isoformat(),
            "logout_time": log.logout_time.isoformat() if log.logout_time else None,
            "is_online": log.is_online,
            "face_verified": log.face_verified,
            "face_image": face_base64,
            "ip_address": log.ip_address,
            "login_method": log.login_method,
            "session_duration": log.session_duration,
        })
    return {"items": results, "total": total}


@router.get("/stats", dependencies=[Depends(has_scopes_or_api_key(["surveillance:read"]))])
async def get_stats(request: Request, db: Session = Depends(get_db)):
    tenant_id = get_tenant_id(request)
    return surveillance_service.get_stats(db, tenant_id=tenant_id)
