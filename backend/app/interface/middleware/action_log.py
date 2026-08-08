import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from ...application.action_logger import log_action
from ...db import SessionLocal
from ...jwt_utils import verify_token

logger = logging.getLogger(__name__)


class ActionLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        try:
            path = request.url.path
            if self._should_skip(path):
                return response

            auth = request.headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                return response

            token = auth[7:]
            payload = verify_token(token)
            if not payload:
                return response

            username = payload.get("sub", "unknown")
            tenant_id = payload.get("tenant_id", getattr(request.state, "tenant_id", "default"))
            method = request.method
            action_map = {
                "GET": "view",
                "POST": "create",
                "PUT": "update",
                "DELETE": "delete",
            }
            action_type = action_map.get(method, method.lower())

            db = SessionLocal()
            try:
                log_action(
                    db=db,
                    username=username,
                    action=f"{action_type}:{path}",
                    resource=path,
                    ip_address=request.client.host if request.client else None,
                    tenant_id=tenant_id,
                )
            finally:
                db.close()
        except Exception:
            pass
        return response

    def _should_skip(self, path: str):
        skip_prefixes = [
            "/auth/", "/api/admin/", "/api/faces/", "/api/surveillance/",
            "/ws/", "/webhook", "/api/wazuh/webhook",
            "/", "/api/stats/", "/api/real-alerts",
        ]
        return any(path.startswith(p) for p in skip_prefixes)
