from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timedelta, timezone
import uuid
import redis as _redis

from ...db import get_db, get_tenant_id
from ...models import Tenant, TenantUser
from ...auth import has_scopes_or_api_key
from ...services.password_manager import hash_password
from ...jwt_utils import create_access_token
from ...config import settings

_redis_client = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

router = APIRouter(prefix="/api/tenants", tags=["tenants"])

PLAN_LIMITS = {
    "trial":    {"max_agents": 5,   "max_endpoints": 10,  "retention_days": 7,   "price": 0},
    "basic":    {"max_agents": 5,   "max_endpoints": 10,  "retention_days": 7,   "price": 99},
    "pro":      {"max_agents": 25,  "max_endpoints": 50,  "retention_days": 30,  "price": 299},
    "enterprise": {"max_agents": 999, "max_endpoints": 999, "retention_days": 90, "price": 999},
}


class TenantRegisterRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=200)
    email: str = Field(..., min_length=5, max_length=200)
    admin_username: str = Field(..., min_length=3, max_length=64)
    admin_password: str = Field(..., min_length=8, max_length=128)


class TenantSubscribeRequest(BaseModel):
    plan: str = Field(..., pattern="^(basic|pro|enterprise)$")


class TenantUpdateRequest(BaseModel):
    company_name: Optional[str] = None
    email: Optional[str] = None


@router.post("/register")
async def register_tenant(data: TenantRegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Register a new tenant with a 14-day trial."""
    # Rate limit: 3 registrations per 5 minutes per IP
    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:tenant_register:{client_ip}"
    try:
        count = _redis_client.incr(key)
        if count == 1:
            _redis_client.expire(key, 300)
        if count > 3:
            raise HTTPException(status_code=429, detail="Trop de tentatives. Réessayez dans 5 minutes.")
    except _redis.ConnectionError:
        pass

    # Check if email already exists
    existing = db.query(Tenant).filter(Tenant.email == data.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    # Create tenant with trial
    tenant_id = str(uuid.uuid4())
    tenant = Tenant(
        id=tenant_id,
        company_name=data.company_name,
        email=data.email,
        plan="trial",
        status="active",
        subscription_end=datetime.now(timezone.utc) + timedelta(days=14),
        max_agents=PLAN_LIMITS["trial"]["max_agents"],
        max_endpoints=PLAN_LIMITS["trial"]["max_endpoints"],
        retention_days=PLAN_LIMITS["trial"]["retention_days"],
    )
    db.add(tenant)

    # Create admin user for this tenant
    admin_user = TenantUser(
        tenant_id=tenant_id,
        username=data.admin_username,
        password_hash=hash_password(data.admin_password),
        role="admin",
        email=data.email,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(tenant)

    # Generate JWT with tenant_id
    access_token = create_access_token(
        data={
            "sub": data.admin_username,
            "role": "admin",
            "scopes": ["devices:read", "devices:write", "alerts:read", "ws:alerts",
                       "terminal:exec", "scan:execute", "ai:generate", "admin:manage",
                       "surveillance:read", "surveillance:write"],
            "tenant_id": tenant_id,
        }
    )

    return {
        "tenant_id": tenant_id,
        "company_name": tenant.company_name,
        "plan": tenant.plan,
        "subscription_end": tenant.subscription_end.isoformat(),
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.post("/subscribe")
def subscribe_tenant(
    data: TenantSubscribeRequest,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """Subscribe to a paid plan."""
    tenant_id = get_tenant_id(request)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    limits = PLAN_LIMITS.get(data.plan)
    if not limits:
        raise HTTPException(status_code=400, detail="Invalid plan")

    tenant.plan = data.plan
    tenant.max_agents = limits["max_agents"]
    tenant.max_endpoints = limits["max_endpoints"]
    tenant.retention_days = limits["retention_days"]
    # For now, set subscription to 30 days from now. Stripe webhook will update this.
    tenant.subscription_end = datetime.now(timezone.utc) + timedelta(days=30)
    db.commit()

    return {"plan": tenant.plan, "subscription_end": tenant.subscription_end.isoformat()}


@router.get("/current")
def get_current_tenant(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(has_scopes_or_api_key(["devices:read"])),
):
    """Get current tenant info."""
    tenant_id = get_tenant_id(request)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        # Return default tenant info for backward compatibility
        return {
            "id": "default",
            "company_name": "Default",
            "plan": "default",
            "status": "active",
            "max_agents": 999,
            "max_endpoints": 999,
            "retention_days": 365,
        }

    return {
        "id": tenant.id,
        "company_name": tenant.company_name,
        "email": tenant.email,
        "plan": tenant.plan,
        "status": tenant.status,
        "created_at": tenant.created_at.isoformat(),
        "subscription_end": tenant.subscription_end.isoformat() if tenant.subscription_end else None,
        "max_agents": tenant.max_agents,
        "max_endpoints": tenant.max_endpoints,
        "retention_days": tenant.retention_days,
    }


@router.put("/current")
def update_current_tenant(
    data: TenantUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """Update current tenant profile."""
    tenant_id = get_tenant_id(request)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    if data.company_name is not None:
        tenant.company_name = data.company_name
    if data.email is not None:
        # Check uniqueness
        existing = db.query(Tenant).filter(Tenant.email == data.email, Tenant.id != tenant_id).first()
        if existing:
            raise HTTPException(status_code=409, detail="Email already in use")
        tenant.email = data.email

    db.commit()
    return {"status": "updated"}
