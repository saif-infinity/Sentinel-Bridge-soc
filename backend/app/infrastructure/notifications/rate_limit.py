"""R3 — Rate limiting Redis par canal de notification (bucket par minute).

Clé : notif:rl:{channel_id}:{epoch_minute} — INCR + EXPIRE (TTL 120s).
Fail-open : si Redis est down, la notification n'est PAS bloquée.
"""
import logging
import time

import redis

from ...config import settings

logger = logging.getLogger(__name__)

_redis_client = None


def get_redis_client() -> redis.Redis:
    """Client Redis partagé (decode_responses=True, comme le reste du code)."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def is_rate_limited(r, channel_id: int, limit_per_minute: int) -> bool:
    """True si le canal a dépassé sa limite de notifications pour la minute courante.

    - limit_per_minute <= 0 => jamais limité.
    - Fail-open sur erreur Redis (ConnectionError, ResponseError, ...).
    """
    if limit_per_minute <= 0:
        return False
    bucket = int(time.time() // 60)
    key = f"notif:rl:{channel_id}:{bucket}"
    try:
        count = r.incr(key)
        if count == 1:
            r.expire(key, 120)
        return count > limit_per_minute
    except redis.RedisError as e:
        logger.warning("Rate limit Redis échoué (fail-open): %s", e)
        return False
