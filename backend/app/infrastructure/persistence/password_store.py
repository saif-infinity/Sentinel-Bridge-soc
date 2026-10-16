import hashlib
import json
from pathlib import Path

import bcrypt

HASH_STORE_PATH = Path(__file__).resolve().parents[2] / "face_data" / "password_hashes.json"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def store_password_hash(identifier: str, password: str, tenant_id: str = "default") -> str:
    """Store password hash in TenantUser table. Falls back to JSON for backward compat."""
    hashed = hash_password(password)

    # Try DB first
    from ...db import SessionLocal
    from ...models import TenantUser
    db = SessionLocal()
    try:
        # Parse identifier to extract username
        # Format: "user:{username}" or just "{username}"
        username = identifier.replace("user:", "", 1) if identifier.startswith("user:") else identifier

        # Find user within the specified tenant
        user = db.query(TenantUser).filter(
            TenantUser.username == username,
            TenantUser.tenant_id == tenant_id,
        ).first()
        if user:
            user.password_hash = hashed
            db.commit()
            return hashed
    except Exception:
        pass
    finally:
        db.close()

    # Fallback to JSON for legacy code
    _ensure_store()
    store = _read_store()
    store[identifier] = hashed
    _write_store(store)
    return hashed


def check_password(identifier: str, password: str, tenant_id: str | None = None) -> bool:
    """Check password against TenantUser table. Falls back to JSON for backward compat.

    When tenant_id is provided, only check the user within that tenant.
    When tenant_id is None, check across all tenants (cross-tenant lookup).
    """
    from ...db import SessionLocal
    from ...models import TenantUser
    db = SessionLocal()
    try:
        username = identifier.replace("user:", "", 1) if identifier.startswith("user:") else identifier

        if tenant_id:
            user = db.query(TenantUser).filter(
                TenantUser.username == username,
                TenantUser.tenant_id == tenant_id,
            ).first()
            if user and user.password_hash and verify_password(password, user.password_hash):
                return True
        else:
            # Cross-tenant lookup: check all users with this username
            users = db.query(TenantUser).filter(TenantUser.username == username).all()
            for user in users:
                if user.password_hash and verify_password(password, user.password_hash):
                    return True
    except Exception:
        pass
    finally:
        db.close()

    # Fallback to JSON
    store = _read_store()
    hashed = store.get(identifier)
    if not hashed:
        return False
    return verify_password(password, hashed)


def user_exists(identifier: str, tenant_id: str = "default") -> bool:
    """Check if user exists in TenantUser table. Falls back to JSON."""
    from ...db import SessionLocal
    from ...models import TenantUser
    db = SessionLocal()
    try:
        username = identifier.replace("user:", "", 1) if identifier.startswith("user:") else identifier
        user = db.query(TenantUser).filter(
            TenantUser.username == username,
            TenantUser.tenant_id == tenant_id,
        ).first()
        if user:
            return True
    except Exception:
        pass
    finally:
        db.close()

    # Fallback to JSON
    store = _read_store()
    return identifier in store


# Keep the old JSON helpers for backward compatibility during migration
def _ensure_store():
    HASH_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not HASH_STORE_PATH.exists():
        with open(HASH_STORE_PATH, "w") as f:
            json.dump({}, f)


def _read_store():
    _ensure_store()
    try:
        with open(HASH_STORE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _write_store(data: dict):
    _ensure_store()
    with open(HASH_STORE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def hash_file_content(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_image_data(image_data: str) -> str:
    if "," in image_data:
        image_data = image_data.split(",")[1]
    return hashlib.sha256(image_data.encode()).hexdigest()
