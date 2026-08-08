from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ...services.face_service import face_service
from ...jwt_utils import verify_token
from ...admin_auth import verify_admin_token
from ...auth import has_scopes_or_api_key

router = APIRouter(prefix="/api/faces", tags=["faces"])


class FaceRegisterRequest(BaseModel):
    image: str
    username: str


class FaceVerifyRequest(BaseModel):
    image: str
    username: str


def _require_jwt_user(authorization: str = Header(None, alias="Authorization")):
    """Exiger un JWT valide et retourner le nom d'utilisateur + tenant_id.
    Accepte les tokens utilisateur classiques ET les tokens admin."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer requis",
        )
    scheme, token = authorization.split() if " " in authorization else (None, None)
    if not scheme or scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Format: Authorization: Bearer <token>",
        )

    # Try regular user token first
    payload = verify_token(token)
    if payload:
        return payload.get("username") or payload.get("sub"), payload.get("tenant_id", "default")

    # Fallback: try admin token
    admin_payload = verify_admin_token(token)
    if admin_payload:
        return admin_payload.get("sub", "admin"), "default"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expire",
    )


@router.post("/register")
async def register_face(
    request: FaceRegisterRequest,
    auth_data: tuple = Depends(_require_jwt_user),
):
    username, tenant_id = auth_data
    if not request.username.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username requis")
    if request.username.strip().lower() != username.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous ne pouvez enregistrer que votre propre visage",
        )
    success, message = face_service.register_face(request.username, request.image, tenant_id=tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return {"status": "success", "message": message}


@router.post("/verify")
async def verify_face(
    request: FaceVerifyRequest,
    auth_data: tuple = Depends(_require_jwt_user),
):
    username, tenant_id = auth_data
    if request.username.strip().lower() != username.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous ne pouvez pas verifier le visage d'un autre utilisateur",
        )
    success, message = face_service.verify_face(request.username, request.image, tenant_id=tenant_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=message
        )
    return {"status": "success", "message": message, "verified": True}


@router.get("/status/{username}", dependencies=[Depends(has_scopes_or_api_key(["devices:read"]))])
async def face_status(username: str, request: Request):
    from ...db import get_tenant_id
    tenant_id = get_tenant_id(request)
    registered = face_service.has_registered_face(username, tenant_id=tenant_id)
    return {"username": username, "registered": registered}


@router.get("/image/{username}", dependencies=[Depends(has_scopes_or_api_key(["devices:read"]))])
async def face_image(username: str, request: Request):
    """Return the stored face image for a user (404 if none registered)."""
    from ...db import get_tenant_id
    tenant_id = get_tenant_id(request)
    path = face_service.get_face_path(username, tenant_id=tenant_id)
    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Face image not found")
    return FileResponse(path, media_type="image/jpeg")
