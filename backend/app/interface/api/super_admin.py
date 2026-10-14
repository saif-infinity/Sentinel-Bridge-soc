from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...config import settings
from ...core.rbac import ROLE_RANK, ROLE_WHITELIST, require_role
from ...db import get_db
from ...models import Alert, Device, Tenant, TenantUser

router = APIRouter(prefix="/api/super-admin", tags=["super-admin"])


async def verify_super_admin(x_api_key: str = Header(None, alias="X-API-Key")):
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing super admin API key",
        )
    expected = settings.SUPER_ADMIN_API_KEY.get_secret_value()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Super admin API key not configured",
        )
    if x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid super admin API key",
        )
    return x_api_key


@router.get("/tenants", dependencies=[Depends(verify_super_admin)])
def list_all_tenants(db: Session = Depends(get_db)):
    """List all tenants (super admin only)."""
    tenants = db.query(Tenant).all()
    return [
        {
            "id": t.id,
            "company_name": t.company_name,
            "email": t.email,
            "plan": t.plan,
            "status": t.status,
            "created_at": t.created_at.isoformat(),
            "subscription_end": t.subscription_end.isoformat() if t.subscription_end else None,
        }
        for t in tenants
    ]


@router.post("/tenants/{tenant_id}/suspend", dependencies=[Depends(verify_super_admin)])
def suspend_tenant(tenant_id: str, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.status = "suspended"
    db.commit()
    return {"status": "suspended", "tenant_id": tenant_id}


@router.post("/tenants/{tenant_id}/activate", dependencies=[Depends(verify_super_admin)])
def activate_tenant(tenant_id: str, db: Session = Depends(get_db)):
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.status = "active"
    db.commit()
    return {"status": "active", "tenant_id": tenant_id}


@router.get("/stats", dependencies=[Depends(verify_super_admin)])
def get_global_stats(db: Session = Depends(get_db)):
    """Global statistics for super admin."""
    total_tenants = db.query(func.count(Tenant.id)).scalar()
    active_tenants = db.query(func.count(Tenant.id)).filter(Tenant.status == "active").scalar()
    total_users = db.query(func.count(TenantUser.id)).scalar()
    total_devices = db.query(func.count(Device.id)).scalar()
    total_alerts = db.query(func.count(Alert.id)).scalar()

    return {
        "total_tenants": total_tenants,
        "active_tenants": active_tenants,
        "total_users": total_users,
        "total_devices": total_devices,
        "total_alerts": total_alerts,
    }


class RoleUpdateRequest(BaseModel):
    role: str


@router.get("/users")
async def list_all_users(
    db: Session = Depends(get_db),
    _=Depends(require_role("super_admin")),
):
    """List all users across all tenants (super admin only)."""
    users = db.query(TenantUser).all()
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
async def update_user_role_global(
    username: str,
    data: RoleUpdateRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role("super_admin")),
):
    """Change a user's role globally (super admin only)."""
    new_role = data.role
    if new_role not in ROLE_WHITELIST:
        raise HTTPException(
            status_code=400,
            detail="Role must be one of: viewer, analyst, admin, super_admin",
        )
    targets = db.query(TenantUser).filter(TenantUser.username == username).all()
    if not targets:
        raise HTTPException(status_code=404, detail="User not found")
    if len(targets) > 1:
        raise HTTPException(status_code=409, detail="Username exists in multiple tenants — ambiguous")
    target = targets[0]

    if target.role == "super_admin" and new_role != "super_admin":
        sa_count = db.query(TenantUser).filter(TenantUser.role == "super_admin").count()
        if sa_count == 1:
            raise HTTPException(status_code=400, detail="Cannot demote the last super admin")

    if target.role == "admin" and ROLE_RANK[new_role] < 2:
        admin_count = (
            db.query(TenantUser)
            .filter(TenantUser.tenant_id == target.tenant_id, TenantUser.role == "admin")
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
    return {"username": username, "role": new_role, "tenant_id": target.tenant_id}
