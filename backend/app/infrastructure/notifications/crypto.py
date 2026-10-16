"""R3 — Chiffrement Fernet des configs de canaux de notification.

Convention : les clés secrètes d'une config JSON se terminent par "_secret"
(ex. "password_secret", "token_secret"). mask_config() masque ces valeurs
pour les logs / réponses API.
"""
import base64
import hashlib
import json
import logging

from cryptography.fernet import Fernet, InvalidToken

from ...config import settings

logger = logging.getLogger(__name__)


def _fernet() -> Fernet:
    """Clé Fernet : NOTIFICATION_ENCRYPTION_KEY si fournie, sinon fallback
    déterministe dérivé de JWT_SECRET_KEY (dev/tests)."""
    key = (settings.NOTIFICATION_ENCRYPTION_KEY or "").strip()
    if not key:
        digest = hashlib.sha256(
            settings.JWT_SECRET_KEY.get_secret_value().encode("utf-8")
        ).digest()
        key = base64.urlsafe_b64encode(digest).decode("ascii")
    return Fernet(key.encode("utf-8") if isinstance(key, str) else key)


def encrypt_config(config: dict) -> str:
    """Chiffre un dict de config en JSON Fernet (str)."""
    return _fernet().encrypt(
        json.dumps(config, ensure_ascii=False).encode("utf-8")
    ).decode("utf-8")


def decrypt_config(blob: str) -> dict:
    """Déchiffre un blob Fernet en dict.

    Fallback : JSON en clair (config non chiffrée, ex. défaut "{}").
    Retourne {} si le blob est invalide.
    """
    if not blob:
        return {}
    try:
        raw = _fernet().decrypt(blob.encode("utf-8"))
        return json.loads(raw)
    except (InvalidToken, ValueError, TypeError):
        pass
    try:
        value = json.loads(blob)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        logger.warning("decrypt_config: blob invalide (ni Fernet ni JSON)")
        return {}


def mask_config(config: dict) -> dict:
    """Masque les valeurs des clés finissant par '_secret' (convention R3)."""
    out = {}
    for key, value in config.items():
        if key.endswith("_secret") and value:
            out[key] = "***"
        else:
            out[key] = value
    return out
