"""Redis Streams helpers for syslog buffering."""
import json
import logging
from typing import Any

import redis

logger = logging.getLogger(__name__)

STREAM_KEY = "syslog:events"
DLQ_STREAM = "syslog:events:dlq"
GROUP_NAME = "syslog-workers"
MAX_STREAM_LEN = 100_000


def get_redis_client(redis_url: str) -> redis.Redis:
    """Create a Redis client for syslog streams."""
    return redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=None)


def ensure_group(r: redis.Redis) -> None:
    """Create consumer group if it doesn't exist (idempotent)."""
    try:
        r.xgroup_create(STREAM_KEY, GROUP_NAME, id="0", mkstream=True)
        logger.info("Syslog: created consumer group %s on stream %s", GROUP_NAME, STREAM_KEY)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def publish_event(r: redis.Redis, payload: dict[str, Any]) -> str:
    """Publish a parsed syslog event to the Redis Stream."""
    msg_id = r.xadd(
        STREAM_KEY,
        {"payload": json.dumps(payload, default=str)},
        maxlen=MAX_STREAM_LEN,
        approximate=True,
    )
    return msg_id


def send_to_dlq(r: redis.Redis, original_id: str, error: str, payload: str) -> str:
    """Send a failed event to the dead-letter queue."""
    msg_id = r.xadd(
        DLQ_STREAM,
        {
            "original_id": original_id,
            "error": error,
            "payload": payload,
        },
        maxlen=10_000,
        approximate=True,
    )
    logger.warning("Syslog: sent to DLQ (original=%s, error=%s)", original_id, error)
    return msg_id
