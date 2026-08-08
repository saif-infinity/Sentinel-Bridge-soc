import logging
import re
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
import redis as _redis
from sqlalchemy.orm import Session
from ...config import settings
from ...db import get_db
from ...jwt_utils import create_access_token, verify_token
from ...services.password_manager import store_password_hash, check_password, user_exists

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
me_router = APIRouter(prefix="/api/auth", tags=["auth"])

_redis_client = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

ADMIN_SCOPES = [
    "devices:read", "devices:write", "alerts:read", "ws:alerts",
    "terminal:exec", "scan:execute", "ai:generate", "admin:manage",
    "surveillance:read", "surveillance:write", "cases:write",
    "soar:manage", "soar:approve",
]

ANALYST_SCOPES = [
    "devices:read", "alerts:read", "ws:alerts",
    "terminal:exec", "scan:execute", "ai:generate",
    "surveillance:read", "cases:write",
    "soar:approve",
]

VIEWER_SCOPES = [
    "devices:read", "alerts:read", "ws:alerts",
]


async def check_rate_limit(request: Request, max_attempts: int = 5, window_seconds: int = 60):
    client_ip = request.client.host if request.client else "unknown"
    key = f"ratelimit:auth:{client_ip}"
    try:
        count = _redis_client.incr(key)
        if count == 1:
            _redis_client.expire(key, window_seconds)
        if count > max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Trop de tentatives. Réessayez dans une minute.",
            )
    except _redis.ConnectionError:
        pass  # Fail open if Redis is down


def _validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins 8 caractères")
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins une majuscule")
    if not re.search(r'[a-z]', password):
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins une minuscule")
    if not re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="Le mot de passe doit contenir au moins un chiffre")


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst")


@router.post("/register")
async def register_user(data: RegisterRequest, request: Request):
    await check_rate_limit(request, max_attempts=3, window_seconds=300)
    if not data.username.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nom d'utilisateur requis",
        )

    if data.role not in ("analyst", "viewer"):
        data.role = "analyst"

    _validate_password_strength(data.password)

    # Anonymous callers must always land in the "default" tenant — never
    # trust a client-supplied X-Tenant-ID header on an unauthenticated
    # registration.
    authenticated = False
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, token = authorization.split() if " " in authorization else (None, None)
        if scheme and scheme.lower() == "bearer" and token and verify_token(token):
            authenticated = True
    api_key = request.headers.get("X-API-Key")
    if api_key and api_key == settings.API_KEY.get_secret_value():
        authenticated = True

    tenant_id = getattr(request.state, "tenant_id", "default")
    if not authenticated:
        tenant_id = "default"

    if user_exists(f"user:{data.username}", tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cet utilisateur existe déjà",
        )

    scopes = ANALYST_SCOPES if data.role == "analyst" else VIEWER_SCOPES
    store_password_hash(f"user:{data.username}", data.password, tenant_id=tenant_id)

    # Store role
    from ...services.password_manager import _read_store, _write_store
    role_store = _read_store()
    role_store[f"role:{data.username}"] = data.role
    _write_store(role_store)

    logger.info("New user registered: %s (role: %s)", data.username, data.role)

    # Resolve tenant_id from TenantUser table
    from ...models import TenantUser
    from ...db import SessionLocal
    db = SessionLocal()
    try:
        tenant_user = db.query(TenantUser).filter(TenantUser.username == data.username).first()
        resolved_tenant_id = tenant_user.tenant_id if tenant_user else "default"
    finally:
        db.close()

    access_token = create_access_token(
        data={"sub": data.username, "role": data.role, "scopes": scopes, "tenant_id": resolved_tenant_id}
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": data.username,
        "role": data.role,
    }


@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    await check_rate_limit(request, max_attempts=5, window_seconds=60)

    user_key = f"user:{form_data.username}"
    if check_password(user_key, form_data.password, tenant_id=None):
        # Resolve role from TenantUser table (supersedes JSON store)
        from ...models import TenantUser
        from ...db import SessionLocal
        db = SessionLocal()
        try:
            tenant_user = db.query(TenantUser).filter(TenantUser.username == form_data.username).first()
            if tenant_user:
                role = tenant_user.role
                tenant_user.last_login = datetime.now(timezone.utc)
                db.commit()
            else:
                # Fallback to JSON store for legacy users
                from ...services.password_manager import _read_store
                role_store = _read_store()
                role = role_store.get(f"role:{form_data.username}", "analyst")
            resolved_tenant_id = tenant_user.tenant_id if tenant_user else "default"
        finally:
            db.close()

        if role == "admin":
            scopes = ADMIN_SCOPES
        elif role == "super_admin":
            scopes = ADMIN_SCOPES
        elif role == "viewer":
            scopes = VIEWER_SCOPES
        else:
            scopes = ANALYST_SCOPES

        access_token = create_access_token(
            data={"sub": form_data.username, "role": role, "scopes": scopes, "tenant_id": resolved_tenant_id}
        )
        return {"access_token": access_token, "token_type": "bearer", "role": role}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Identifiants incorrects",
        headers={"WWW-Authenticate": "Bearer"},
    )


@me_router.get("/me")
async def get_me(request: Request, db: Session = Depends(get_db)):
    """Return the current user's identity/role (DB is the source of truth)."""
    authorization = request.headers.get("Authorization")
    scheme, token = authorization.split() if authorization and " " in authorization else (None, None)
    if not scheme or scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    sub = payload["sub"]
    tenant_id = getattr(request.state, "tenant_id", "default")
    from ...core.rbac import resolve_user_role
    role, row = resolve_user_role(db, sub, tenant_id)
    if row and not row.is_active:
        raise HTTPException(status_code=401, detail="Account disabled")
    return {
        "username": sub,
        "role": role,
        "tenant_id": tenant_id,
        "email": row.email if row else None,
        "is_active": row.is_active if row else True,
    }
