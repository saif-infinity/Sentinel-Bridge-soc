import logging
import re
import secrets
from datetime import UTC, datetime

import redis as _redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...config import settings
from ...core.broadcaster import broadcaster
from ...db import get_db
from ...jwt_utils import create_access_token, verify_token
from ...models import RegistrationRequest
from ...services.password_manager import (
    _read_store,
    _write_store,
    check_password,
    hash_password,
    store_password_hash,
    user_exists,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
me_router = APIRouter(prefix="/api/auth", tags=["auth"])

_redis_client = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

# Si True → register crée une RegistrationRequest pending (approbation admin requise avant login)
REGISTRATION_REQUIRES_APPROVAL = settings.REGISTRATION_REQUIRES_APPROVAL

ADMIN_SCOPES = [
    "devices:read", "devices:write", "alerts:read", "ws:alerts",
    "terminal:exec", "scan:execute", "ai:generate", "admin:manage",
    "surveillance:read", "surveillance:write", "cases:write",
    "soar:manage", "soar:approve",
]

ANALYST_SCOPES = [
    "devices:read", "alerts:read", "ws:alerts",
    "terminal:exec", "scan:execute", "ai:generate",
    "surveillance:read", "surveillance:write", "cases:write",
    "soar:approve",
]

VIEWER_SCOPES = [
    "devices:read", "alerts:read", "ws:alerts",
]


def _client_ip(request: Request) -> str:
    """IP du pair, en tenant compte d'un reverse proxy de confiance.

    `request.client.host` est l'adresse TCP du pair direct. Derrière nginx/Traefik
    c'est toujours l'IP du proxy, donc tous les utilisateurs partageraient UN seul
    seau de rate-limit (déni de service mutuel). On ne lit X-Forwarded-For que si
    TRUST_PROXY_HEADERS=true : sinon n'importe qui peut forger l'en-tête et faire
    sauter la limite.
    """
    if request is None:
        return "unknown"
    if settings.TRUST_PROXY_HEADERS:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            first_hop = xff.split(",")[0].strip()
            if first_hop:
                return first_hop
    return request.client.host if request.client else "unknown"


async def check_rate_limit(
    request: Request,
    max_attempts: int = 5,
    window_seconds: int = 60,
    username: str | None = None,
):
    """Limite les tentatives par IP **et** par compte visé.

    Deux failles de la version précédente :

    1. Clé IP seule. Un attaquant distribué (botnet, VPN, plusieurs IPs)
       brute-force un compte sans jamais atteindre le seuil — et à l'inverse tout
       un bureau derrière un NAT partage un seul seau. On compte donc aussi par
       nom d'utilisateur ciblé, quel que soit l'IP d'origine.
    2. `except _redis.ConnectionError: pass` → le rate-limit disparaissait pile
       quand Redis tombait (fail-open). En production on échoue désormais
       **fermé** (503) : refuser les logins vaut mieux que les laisser illimités.
       `RedisError` couvre aussi TimeoutError, qui faisait auparavant tomber
       /auth/token en 500.
    """
    buckets = [f"ratelimit:auth:ip:{_client_ip(request)}"]
    if username:
        ident = username.strip().lower()
        if ident:
            buckets.append(f"ratelimit:auth:user:{ident}")

    try:
        for key in buckets:
            count = _redis_client.incr(key)
            if count == 1:
                _redis_client.expire(key, window_seconds)
            if count > max_attempts:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Trop de tentatives. Réessayez dans une minute.",
                )
    except _redis.RedisError as exc:
        if settings.ENVIRONMENT.strip().lower() == "production":
            logger.error("Rate-limit indisponible (Redis: %s) — échec fermé en production", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service d'authentification temporairement indisponible.",
            ) from exc
        logger.warning(
            "Rate-limit indisponible (Redis: %s) — fail-open en environnement %s",
            exc, settings.ENVIRONMENT,
        )


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
    face_image: str | None = None  # base64 face image (optional)


@router.post("/register")
async def register_user(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    await check_rate_limit(
        request, max_attempts=3, window_seconds=300, username=data.username
    )
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
    if api_key and secrets.compare_digest(api_key, settings.API_KEY.get_secret_value()):
        authenticated = True

    tenant_id = getattr(request.state, "tenant_id", "default")
    if not authenticated:
        tenant_id = "default"

    if user_exists(f"user:{data.username}", tenant_id=tenant_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cet utilisateur existe déjà",
        )

    # ── Mode pending : création d'une RegistrationRequest en attente ──
    pending_header = request.headers.get("X-Registration-Mode")
    if REGISTRATION_REQUIRES_APPROVAL or pending_header == "pending":
        pending = (
            db.query(RegistrationRequest)
            .filter(
                RegistrationRequest.username == data.username,
                RegistrationRequest.tenant_id == tenant_id,
                RegistrationRequest.status == "pending",
            )
            .first()
        )
        if pending:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Demande déjà en attente",
            )

        hashed = hash_password(data.password)
        req = RegistrationRequest(
            tenant_id=tenant_id,
            username=data.username,
            password_hash=hashed,
            role=data.role,
            face_image=data.face_image,
            status="pending",
        )
        db.add(req)
        db.commit()
        db.refresh(req)

        logger.info("Registration request created: %s (role: %s)", data.username, data.role)

        await broadcaster.broadcast({
            "type": "registration_request",
            "request_id": req.id,
            "username": req.username,
        })

        return {
            "request_id": req.id,
            "status": "pending",
            "message": "Inscription en attente d'approbation admin",
        }

    # ── Mode direct (défaut) : création immédiate du compte ──
    scopes = ANALYST_SCOPES if data.role == "analyst" else VIEWER_SCOPES
    store_password_hash(f"user:{data.username}", data.password, tenant_id=tenant_id)

    role_store = _read_store()
    role_store[f"role:{data.username}"] = data.role
    _write_store(role_store)

    logger.info("New user registered: %s (role: %s)", data.username, data.role)

    from ...db import SessionLocal
    from ...models import TenantUser
    db_local = SessionLocal()
    try:
        tenant_user = db_local.query(TenantUser).filter(TenantUser.username == data.username).first()
        resolved_tenant_id = tenant_user.tenant_id if tenant_user else "default"
    finally:
        db_local.close()

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
    await check_rate_limit(
        request,
        max_attempts=settings.AUTH_LOGIN_RATE_LIMIT_MAX,
        window_seconds=settings.AUTH_LOGIN_RATE_LIMIT_WINDOW,
        username=form_data.username,
    )

    # FIX: tenant_id=None made check_password() test the hash of EVERY tenant that has
    # this username ("Cross-tenant lookup" in password_store.py), and the role lookup
    # below took an arbitrary `.first()` row. Two tenants each having a user named
    # "admin" could therefore authenticate into each other's tenant. /auth/token is a
    # public route (no JWT to derive the tenant from), so the tenant is taken from an
    # explicit X-Tenant-ID header.
    login_tenant = (request.headers.get("X-Tenant-ID") or "default") if request else "default"

    user_key = f"user:{form_data.username}"
    if check_password(user_key, form_data.password, tenant_id=login_tenant):
        # Resolve role from TenantUser table (supersedes JSON store)
        from ...db import SessionLocal
        from ...models import TenantUser
        db = SessionLocal()
        try:
            tenant_user = db.query(TenantUser).filter(
                TenantUser.username == form_data.username,
                TenantUser.tenant_id == login_tenant,
            ).first()
            if tenant_user:
                role = tenant_user.role
                tenant_user.last_login = datetime.now(UTC)
                db.commit()
            else:
                # Fallback to JSON store for legacy users
                from ...services.password_manager import _read_store
                role_store = _read_store()
                role = role_store.get(f"role:{form_data.username}", "analyst")
            resolved_tenant_id = tenant_user.tenant_id if tenant_user else login_tenant
            if tenant_user and tenant_user.is_active is False:
                raise HTTPException(status_code=403, detail="Compte désactivé")
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


@router.get("/register-request/{request_id}")
async def get_register_request_status(request_id: int, db: Session = Depends(get_db)):
    """Analyst polls this to check if their registration was approved."""
    req = db.query(RegistrationRequest).filter(RegistrationRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Demande non trouvée")
    return {"request_id": req.id, "status": req.status, "resolved_at": req.resolved_at}


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
