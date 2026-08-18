"""R10 — Syslog consumer: XREADGROUP from Redis Stream → ingest_alert."""
import json
import logging

import redis

from ...core.celery import celery_app
from ...core.config import settings
from ...db import SessionLocal
from ...application import pipeline as pipeline_module
from ..syslog.stream import (
    GROUP_NAME,
    STREAM_KEY,
    DLQ_STREAM,
    get_redis_client,
    ensure_group,
    send_to_dlq,
)

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
BATCH_SIZE = 50


def _get_redis() -> redis.Redis:
    return get_redis_client(settings.REDIS_URL)


@celery_app.task(
    name="jobs.syslog.process_batch",
    max_retries=3,
    default_retry_delay=10,
)
def process_syslog_batch():
    """Read a batch of syslog events from Redis Stream and ingest them."""
    r = _get_redis()
    ensure_group(r)

    messages = r.xreadgroup(
        groupname=GROUP_NAME,
        consumername="celery-worker",
        streams={STREAM_KEY: ">"},
        count=BATCH_SIZE,
        block=2000,
    )

    if not messages:
        return {"processed": 0}

    processed = 0
    errors = 0
    db = SessionLocal()

    try:
        for stream_name, entries in messages:
            for msg_id, fields in entries:
                try:
                    payload_str = fields.get("payload", "{}")
                    payload = json.loads(payload_str)

                    # Build ingest payload
                    ingest = {
                        "source": "syslog",
                        "timestamp": payload.get("@timestamp"),
                        "severity": payload.get("severity", 5),
                        "signature": payload.get("description", "")[:255],
                        "description": payload.get("description", ""),
                        "src_ip": payload.get("src_ip"),
                        "dest_ip": payload.get("dest_ip"),
                        "proto": payload.get("proto", "syslog"),
                        "agent_id": payload.get("agent_id"),
                        "category": payload.get("event", {}).get("category", "network"),
                        "raw": payload,
                        "tenant_id": payload.get("tenant_id", "default"),
                    }

                    pipeline_module.ingest_alert(ingest, db=db)
                    r.xack(STREAM_KEY, GROUP_NAME, msg_id)
                    processed += 1

                except Exception as e:
                    logger.warning("Syslog processing failed (msg=%s): %s", msg_id, e)
                    errors += 1
                    try:
                        send_to_dlq(r, str(msg_id), str(e), fields.get("payload", ""))
                    except Exception:
                        logger.exception("Failed to send to DLQ")
                    r.xack(STREAM_KEY, GROUP_NAME, msg_id)  # ACK to prevent infinite requeue

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return {"processed": processed, "errors": errors}