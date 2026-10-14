"""F4 — Role-based access control (RBAC).

Role hierarchy: viewer(0) < analyst(1) < admin(2) < super_admin(3).
The DB (TenantUser) is the source of truth for roles; the JSON store is a
legacy fallback. `require_role` is a FastAPI dependency that short-circuits
the legacy per-route scope deps (it is inserted at index 0 of
route.dependencies).
"""
import secrets

from fastapi import Depends, Header, HTTPException, Request
from fastapi.routing import APIRoute
from sqlalchemy.orm import Session

from ..domain.models import TenantUser
from .config import settings
from .db import get_db
from .jwt_utils import verify_token

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2, "super_admin": 3}
ROLE_WHITELIST = set(ROLE_RANK)
ADMIN_ASSIGNABLE = {"viewer", "analyst", "admin"}
DEFAULT_POLICY = {"read": "viewer", "write": "analyst", "exempt": False, "exempt_paths": []}


def resolve_user_role(db, username, tenant_id):
    """Return (role, TenantUser row or None). DB is the source of truth;
    falls back to the legacy JSON store for users not in the DB."""
    row = db.query(TenantUser).filter_by(username=username, tenant_id=tenant_id).first()
    if row:
        return (row.role, row)
    from ..infrastructure.persistence.password_store import _read_store
    # FIX: unknown users used to default to "analyst" (a role that writes) when they
    # were absent from TenantUser. An authorisation default must fail closed.
    return (_read_store().get(f"role:{username}", "viewer"), None)


def require_role(min_role: str):
    async def role_guard(
        request: Request,
        api_key: str = Header(None, alias="X-API-Key"),
        authorization: str = Header(None, alias="Authorization"),
        db: Session = Depends(get_db),
    ) -> dict:
        # ── API-key lane ──────────────────────────────────────────────
        if api_key:
            if (
                secrets.compare_digest(api_key, settings.API_KEY.get_secret_value())
                and ROLE_RANK[min_role] <= ROLE_RANK["admin"]
            ):
                return {
                    "sub": "api_key",
                    "tenant_id": getattr(request.state, "tenant_id", "default"),
                    "role": "admin",
                    "source": "api_key",
                }
            if min_role == "super_admin":
                sa = settings.SUPER_ADMIN_API_KEY.get_secret_value()
                if sa and secrets.compare_digest(api_key, sa):
                    return {
                        "sub": "api_key",
                        "tenant_id": getattr(request.state, "tenant_id", "default"),
                        "role": "super_admin",
                        "source": "api_key",
                    }
        # Non-matching API key falls through to the JWT lane.

        # ── JWT lane ──────────────────────────────────────────────────
        scheme, token = authorization.split() if authorization and " " in authorization else (None, None)
        if not scheme or scheme.lower() != "bearer" or not token:
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        payload = verify_token(token)
        if payload is None:
            # Console-admin tokens (signed with ADMIN_JWT_SECRET) are accepted
            # as super_admin: the admin console is the platform operator UI.
            from ..admin_auth import verify_admin_token
            admin_payload = verify_admin_token(token)
            if admin_payload is None:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return {
                "sub": admin_payload.get("sub", "admin"),
                "tenant_id": getattr(request.state, "tenant_id", "default"),
                "role": "super_admin",
                "source": "admin_jwt",
            }

        tenant_id = getattr(request.state, "tenant_id", "default")
        role, row = resolve_user_role(db, payload["sub"], tenant_id)
        if row and row.is_active is False:
            raise HTTPException(status_code=401, detail="Account disabled")
        if ROLE_RANK[role] < ROLE_RANK[min_role]:
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return {"sub": payload["sub"], "tenant_id": tenant_id, "role": role, "source": "jwt"}

    return role_guard


def apply_role_guard(router, policy: dict):
    # Empty policies (e.g. {"devices": {}}) mean "use the defaults".
    policy = {**DEFAULT_POLICY, **policy}
    for route in router.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in policy.get("exempt_paths", []):
            continue
        methods = {m.upper() for m in (route.methods or [])}
        min_role = policy["read"] if methods & {"GET", "HEAD", "OPTIONS"} else policy["write"]
        if not min_role:
            continue
        route.dependencies.insert(0, Depends(require_role(min_role)))
