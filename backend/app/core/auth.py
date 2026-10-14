import secrets
from fastapi import Header, HTTPException, Request, status, Query, Depends
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from .jwt_utils import verify_token
from .config import settings

# We are going to use the OAuth2PasswordBearer to extract the token from the Authorization header.
# However, for WebSocket, we don't have headers, so we will also support token as a query parameter.
# We'll create a dependency that can get the token from either the header or the query parameter.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)

async def get_token_from_header(token: str = Depends(oauth2_scheme)):
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

async def get_token_from_query(token: str = Query(None)):
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

# Let's create a simple API key authentication for services that need it
def _key_matches(provided, expected) -> bool:
    """Constant-time comparison. `==` on a secret leaks length/prefix via timing."""
    if not provided or not expected:
        return False
    return secrets.compare_digest(provided, expected)


async def get_api_key(api_key: str = Header(None, alias="X-API-Key")):
    if not _key_matches(api_key, settings.API_KEY.get_secret_value()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate API key",
        )
    return api_key

# Combined auth: accepts either X-API-Key header OR JWT Bearer token
async def get_api_key_or_jwt(
    api_key: str = Header(None, alias="X-API-Key"),
    authorization: str = Header(None, alias="Authorization"),
):
    # Try API key first
    if _key_matches(api_key, settings.API_KEY.get_secret_value()):
        return api_key
    
    # Try JWT Bearer token
    if authorization:
        scheme, token = authorization.split() if " " in authorization else (None, None)
        if scheme and scheme.lower() == "bearer" and token:
            from .jwt_utils import verify_token
            payload = verify_token(token)
            if payload:
                return token
            # Console-admin token (ADMIN_JWT_SECRET): accepted as operator.
            from ..admin_auth import verify_admin_token
            if verify_admin_token(token) is not None:
                return token
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials. Provide X-API-Key header or Bearer token.",
    )

# Create the api_key_auth dependency that analyse.py expects
api_key_auth = Depends(get_api_key)

# FIX: removed the dead `get_token()` stub (its body was `pass`) together with the
# ~12 lines of draft reasoning comments left above it ("Let's do it differently:",
# "Actually, we want to try header first."). get_token_from_request below is the real one.

async def get_token_from_request(request: Request):
    # Try to get token from Authorization header
    authorization: str = request.headers.get("Authorization")
    if authorization:
        scheme, token = authorization.split()
        if scheme.lower() == "bearer":
            return token
    # Try to get token from query parameter
    token = request.query_params.get("token")
    if token:
        return token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Now we create a dependency that uses the get_token_from_request and then verifies the token and checks scopes.
from typing import List, Set, Optional

def has_scopes(required_scopes: List[str]):
    async def scope_verifier(token: str = Depends(get_token_from_request)):
        payload = verify_token(token)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_scopes: Set[str] = set(payload.get("scopes", []))
        required_scopes_set: Set[str] = set(required_scopes)
        if not required_scopes_set.issubset(token_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    return scope_verifier

# Combined scope checker: accepts either JWT with required scopes OR API key
def has_scopes_or_api_key(required_scopes: List[str]):
    async def scope_verifier(
        api_key: str = Header(None, alias="X-API-Key"),
        authorization: str = Header(None, alias="Authorization"),
        x_tenant_id: str = Header(None, alias="X-Tenant-ID"),
    ):
        # Try API key first (has all permissions)
        if _key_matches(api_key, settings.API_KEY.get_secret_value()):
            tenant_id = x_tenant_id or "default"
            return {"scopes": required_scopes, "sub": "api_key", "tenant_id": tenant_id}
        
        # Try JWT Bearer token
        if authorization:
            scheme, token = authorization.split() if " " in authorization else (None, None)
            if scheme and scheme.lower() == "bearer" and token:
                payload = verify_token(token)
                if payload:
                    token_scopes: Set[str] = set(payload.get("scopes", []))
                    required_scopes_set: Set[str] = set(required_scopes)
                    if required_scopes_set.issubset(token_scopes):
                        return payload
                else:
                    # Console-admin token (ADMIN_JWT_SECRET): operator, all scopes.
                    from ..admin_auth import verify_admin_token
                    admin_payload = verify_admin_token(token)
                    if admin_payload is not None:
                        return admin_payload
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide X-API-Key header or Bearer token with required scopes.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return scope_verifier


def webhook_token_auth(source: str):
    """Factory returning a FastAPI dependency for webhook endpoint auth.

    X-SOC-Token header (if present) is matched against stored tokens across
    all tenants (constant-time compare). On match, request.state.tenant_id
    is set. If no match but X-SOC-Token present → 401 immediately.
    If X-SOC-Token absent → fall back to get_api_key_or_jwt.
    Never logs the token value.
    """
    from app.application.system_config import get_config_value
    from app.db import SessionLocal
    from app.domain.models import Tenant

    async def _auth(
        x_soc_token: str = Header(None, alias="X-SOC-Token"),
        api_key: str = Header(None, alias="X-API-Key"),
        authorization: str = Header(None, alias="Authorization"),
        request: Request = None,
    ):
        if request is not None:
            if x_soc_token:
                db = SessionLocal()
                try:
                    webhook_section = f"{source}_webhook"
                    tenants = db.query(Tenant).all()
                    for tenant in tenants:
                        stored_token = get_config_value(
                            db, webhook_section, "token", tenant_id=tenant.id
                        )
                        if stored_token and secrets.compare_digest(
                            str(x_soc_token), str(stored_token)
                        ):
                            request.state.tenant_id = tenant.id
                            return
                    # Token present but matched no tenant → 401
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid webhook token",
                    )
                finally:
                    db.close()

        # No X-SOC-Token → fall back to existing auth
        await get_api_key_or_jwt(api_key=api_key, authorization=authorization)

    return _auth


def webhook_slug_auth(source: str):
    """Factory returning a FastAPI dependency for SLUGGED per-tenant webhook URLs.

    POST /api/{source}/webhook/{slug} — l'URL elle-même est un secret partagé
    (revocable via rotation du slug). Résout le tenant par match du slug
    (constante de temps) et fixe request.state.tenant_id. Slug inconnu → 404
    (ne pas fuir l'existence). Si X-SOC-Token est fourni, il doit matcher le
    token du tenant résolu (constante de temps) → sinon 401.
    Ne journalise jamais ni slug ni token.
    """
    from app.application.system_config import get_config_value
    from app.db import SessionLocal
    from app.domain.models import Tenant

    async def _auth(
        slug: str,
        x_soc_token: str | None = Header(None, alias="X-SOC-Token"),
        request: Request = None,
    ):
        if request is not None:
            db = SessionLocal()
            try:
                webhook_section = f"{source}_webhook"
                tenants = db.query(Tenant).all()
                matched_tenant_id = None
                for tenant in tenants:
                    stored_slug = get_config_value(db, webhook_section, "slug", tenant_id=tenant.id)
                    if stored_slug and secrets.compare_digest(str(slug), str(stored_slug)):
                        matched_tenant_id = tenant.id
                        break
                if matched_tenant_id is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Unknown webhook URL",
                    )
                if x_soc_token:
                    stored_token = get_config_value(db, webhook_section, "token", tenant_id=matched_tenant_id)
                    if not stored_token or not secrets.compare_digest(
                        str(x_soc_token), str(stored_token)
                    ):
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid webhook token",
                        )
                request.state.tenant_id = matched_tenant_id
                return
            finally:
                db.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown webhook URL",
        )

    return _auth