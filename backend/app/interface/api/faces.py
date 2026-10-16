from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...admin_auth import verify_admin_token
from ...auth import has_scopes_or_api_key
from ...core.broadcaster import broadcaster
from ...db import get_db, get_tenant_id
from ...jwt_utils import verify_token
from ...models import FaceLoginRequest, UnverifiedFaceAttempt
from ...services.face_service import face_service

router = APIRouter(prefix="/api/faces", tags=["faces"])


class FaceRegisterRequest(BaseModel):
    image: str
    username: str


class FaceVerifyRequest(BaseModel):
    image: str
    username: str


class FaceIdentifyRequest(BaseModel):
    image: str


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


@router.post("/identify", dependencies=[Depends(has_scopes_or_api_key(["surveillance:read"]))])
async def identify_face(
    request: FaceIdentifyRequest,
    req: Request,
):
    """Identifie un visage parmi les utilisateurs enregistrés du tenant.
    FIX: cet endpoint était PUBLIC ("pré-auth") et renvoyait le username reconnu —
    un oracle d'identification biométrique 1:N sans authentification ni rate-limit,
    permettant d'énumérer les identités du tenant (donnée biométrique => art. 9 RGPD).
    Il exige désormais le scope `surveillance:read` (viewer+) ou la clé d'API."""
    tenant_id = get_tenant_id(req)
    username, similarity, message = face_service.identify_face(request.image, tenant_id=tenant_id)
    if username is None:
        return {
            "status": "unknown",
            "username": None,
            "similarity": round(float(similarity), 3),
            "message": message,
            "authorized": False,
        }
    return {
        "status": "recognized",
        "username": username,
        "similarity": round(float(similarity), 3),
        "message": message,
        "authorized": True,
    }


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


class FaceLoginRequestBody(BaseModel):
    username: str
    image: str


class UnverifiedFaceCaptureRequest(BaseModel):
    username: str | None = None
    face_image: str


@router.post("/capture-unknown")
async def capture_unknown_face(
    body: UnverifiedFaceCaptureRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Capture silencieux d'un visage inconnu (pas d'authentification)."""
    tenant_id = get_tenant_id(request)
    attempt = UnverifiedFaceAttempt(
        tenant_id=tenant_id,
        username=body.username,
        face_image=body.face_image,
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)

    await broadcaster.broadcast({
        "type": "unknown_face_attempt",
        "attempt_id": attempt.id,
        "tenant_id": attempt.tenant_id,
        "username": attempt.username,
        "capture_time": attempt.capture_time.isoformat() if attempt.capture_time else None,
    })
    return {"status": "success"}


@router.post("/request-login")
async def request_login(
    body: FaceLoginRequestBody,
    db: Session = Depends(get_db),
    auth_data: tuple = Depends(_require_jwt_user),
):
    """Analyste : vérifie le visage puis crée une demande d'approbation admin (pending)."""
    username, tenant_id = auth_data
    if not body.username.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username requis")
    if body.username.strip().lower() != username.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous ne pouvez demander une connexion que pour votre propre compte",
        )
    success, message = face_service.verify_face(body.username, body.image, tenant_id=tenant_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)

    login_request = FaceLoginRequest(
        tenant_id=tenant_id,
        username=body.username,
        status="pending",
    )
    db.add(login_request)
    db.commit()
    db.refresh(login_request)

    await broadcaster.broadcast({
        "type": "face_login_request",
        "request_id": login_request.id,
        "username": login_request.username,
        "created_at": login_request.created_at.isoformat() if login_request.created_at else None,
    })
    return {"request_id": login_request.id, "status": login_request.status}


@router.get("/login-request/{request_id}")
async def login_request_status(
    request_id: int,
    db: Session = Depends(get_db),
    auth_data: tuple = Depends(_require_jwt_user),
):
    """Analyste : interroge le statut de sa demande d'approbation de connexion."""
    login_request = db.query(FaceLoginRequest).filter(FaceLoginRequest.id == request_id).first()
    if not login_request:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Requête de connexion introuvable")
    return {
        "request_id": login_request.id,
        "status": login_request.status,
        "resolved_at": login_request.resolved_at.isoformat() if login_request.resolved_at else None,
    }
