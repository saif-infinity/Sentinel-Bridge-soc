import logging
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from .config import settings
from .services.password_manager import store_password_hash, check_password

logger = logging.getLogger(__name__)

admin_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/admin/token")


def create_admin_token():
    expire = datetime.now(timezone.utc) + timedelta(hours=8)
    payload = {
        "sub": "admin",
        "role": "admin",
        "exp": expire,
    }
    return jwt.encode(payload, settings.ADMIN_JWT_SECRET.get_secret_value(), algorithm="HS256")


def verify_admin_token(token: str):
    try:
        payload = jwt.decode(
            token,
            settings.ADMIN_JWT_SECRET.get_secret_value(),
            algorithms=["HS256"],
        )
        if payload.get("role") != "admin":
            return None
        return payload
    except JWTError:
        return None


async def get_current_admin(token: str = Depends(admin_oauth2_scheme)):
    payload = verify_admin_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token",
        )
    return payload


def verify_admin_password(password: str) -> bool:
    admin_key = settings.ADMIN_API_KEY.get_secret_value()

    if not check_password("admin_api_key", admin_key):
        store_password_hash("admin_api_key", admin_key)
        logger.info("Admin password hash created")

    return check_password("admin_api_key", password)
