import logging
import secrets

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from ...jwt_utils import verify_token
from ...config import settings

logger = logging.getLogger(__name__)

# Routes that don't require tenant validation
PUBLIC_ROUTES = {
    "/auth/register",
    "/auth/token",
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/",
    "/api/tenants/register",  # New tenant registration
}

# Prefixes that are public
PUBLIC_PREFIXES = ("/docs", "/redoc", "/openapi")


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip public routes
        if path in PUBLIC_ROUTES or any(path.startswith(p) for p in PUBLIC_PREFIXES):
            return await call_next(request)

        # WebSocket connections: tenant validation must happen in the WS handler
        # (middleware cannot intercept WS upgrade paths)
        if path.startswith("/ws/") or path.startswith("/webhook"):
            return await call_next(request)

        # Extract tenant_id from JWT first (trusted source)
        tenant_id = None
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            payload = verify_token(token)
            if payload:
                tenant_id = payload.get("tenant_id")

        # Only fall back to X-Tenant-ID header if no JWT AND valid API key
        if not tenant_id:
            api_key = request.headers.get("x-api-key")
            if api_key and secrets.compare_digest(api_key, settings.API_KEY.get_secret_value()):
                tenant_id = request.headers.get("X-Tenant-ID")

        # Default tenant for backward compatibility
        if not tenant_id:
            tenant_id = "default"

        # Validate tenant exists and is active
        try:
            from ...db import SessionLocal
            from ...models import Tenant

            db = SessionLocal()
            try:
                tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
                if tenant is None and tenant_id != "default":
                    return JSONResponse(
                        status_code=404,
                        content={"detail": "Tenant not found"}
                    )
                if tenant and tenant.status == "suspended":
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Tenant suspended"}
                    )
                if tenant and tenant.subscription_end:
                    from datetime import datetime, timezone
                    if tenant.subscription_end < datetime.now(timezone.utc):
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "Subscription expired"}
                        )
            finally:
                db.close()
        except Exception as e:
            logger.error("Tenant validation error: %s", e)
            if settings.ENVIRONMENT == "production":
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Tenant validation unavailable"}
                )
            # Fail open only in development
            pass

        # Inject tenant_id into request state
        request.state.tenant_id = tenant_id

        return await call_next(request)
