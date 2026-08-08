from fastapi import Header, HTTPException, status, Query, Depends
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
async def get_api_key(api_key: str = Header(None, alias="X-API-Key")):
    if api_key is None or api_key != settings.API_KEY.get_secret_value():
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
    if api_key and api_key == settings.API_KEY.get_secret_value():
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

# We'll create a dependency that tries to get the token from the header first, then from the query.
async def get_token(
    header_token: str = Depends(get_token_from_header, use_cache=False),
    query_token: str = Depends(get_token_from_query, use_cache=False),
):
    # If header token is provided, use it; otherwise, use query token.
    # Note: the Depends with use_cache=False is to allow both to be called? Actually, we want to try header first.
    # We can do: if header_token is not None, return header_token, else return query_token.
    # But note: the dependency system will call both functions. We want to avoid calling the query token function if header token is present?
    # We can't easily do that with Depends. We'll create a new function that takes both as optional and then choose.
    pass

# Let's do it differently: we'll create a single function that tries to get the token from the header, and if not present, from the query.
# We can't do that with two separate dependencies because we don't know which one will be called first.
# We'll create a custom dependency that gets the token from the request.

from fastapi import Request

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
from typing import List, Set

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
        if api_key and api_key == settings.API_KEY.get_secret_value():
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