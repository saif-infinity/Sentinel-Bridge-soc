"""Agent tokens — hash + verify utilities (server-side only)."""
import hashlib
import secrets
import string


def generate_token(length: int = 48) -> str:
    """Génère un token URL-safe (ex: sb_ + base62)."""
    alphabet = string.ascii_letters + string.digits
    return "sb_" + "".join(secrets.choice(alphabet) for _ in range(length))


def hash_token(token: str) -> str:
    """SHA-256 hex du token (stocké, jamais le clair)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(provided: str, stored_hash: str) -> bool:
    """Comparaison constant-time sur hash."""
    computed = hashlib.sha256(provided.encode("utf-8")).hexdigest()
    return secrets.compare_digest(computed, stored_hash)
