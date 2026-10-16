"""Syslog UDP/TCP receiver — standalone process.

Usage: python -m app.infrastructure.syslog.server

Receives syslog messages (RFC 5424/3164), resolves tenant by source IP,
and publishes to Redis Stream for Celery consumer processing.
"""
import asyncio
import json
import logging
import os
import signal

import redis

from .protocol import parse_syslog
from .stream import (
    GROUP_NAME,
    ensure_group,
    get_redis_client,
    publish_event,
)
from .tenant_resolver import configure as configure_tenants
from .tenant_resolver import resolve_tenant

logger = logging.getLogger("syslog_receiver")

# Config from env
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
SYSLOG_HOST = os.environ.get("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "1514"))
SYSLOG_TENANT_MAPPINGS = os.environ.get("SYSLOG_TENANT_MAPPINGS", "{}")
SYSLOG_DEFAULT_TENANT = os.environ.get("SYSLOG_DEFAULT_TENANT", "default")


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, r: redis.Redis):
        self.r = r
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        raw = data.decode("utf-8", errors="replace")
        parsed = parse_syslog(raw)
        source_ip = addr[0]
        tenant_id = resolve_tenant(source_ip)

        event = {
            **parsed,
            "source_ip": source_ip,
            "source_port": addr[1],
            "tenant_id": tenant_id,
        }

        try:
            publish_event(self.r, event)
        except redis.RedisError as e:
            logger.error("Redis XADD failed for %s: %s", source_ip, e)


class SyslogTCPServer:
    def __init__(self, r: redis.Redis):
        self.r = r

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        try:
            while True:
                # RFC 6587: octet-counting framing
                length_line = await reader.readline()
                if not length_line:
                    break
                try:
                    length = int(length_line.strip())
                except ValueError:
                    break

                data = await reader.readexactly(length)
                raw = data.decode("utf-8", errors="replace")
                parsed = parse_syslog(raw)
                source_ip = addr[0] if addr else "unknown"
                tenant_id = resolve_tenant(source_ip)

                event = {
                    **parsed,
                    "source_ip": source_ip,
                    "tenant_id": tenant_id,
                }

                try:
                    publish_event(self.r, event)
                except redis.RedisError as e:
                    logger.error("Redis XADD TCP failed for %s: %s", source_ip, e)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()


async def run_receiver():
    # Configure tenant mapping
    try:
        mappings = json.loads(SYSLOG_TENANT_MAPPINGS)
    except json.JSONDecodeError:
        mappings = {}
    configure_tenants(mappings, SYSLOG_DEFAULT_TENANT)

    # Connect to Redis
    r = get_redis_client(REDIS_URL)
    ensure_group(r)
    logger.info("Syslog receiver: Redis connected, group=%s", GROUP_NAME)

    loop = asyncio.get_running_loop()

    # UDP server
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(r),
        local_addr=(SYSLOG_HOST, SYSLOG_PORT),
    )
    logger.info("Syslog receiver: UDP listening on %s:%d", SYSLOG_HOST, SYSLOG_PORT)

    # TCP server
    tcp_server = await asyncio.start_server(
        lambda reader, writer: SyslogTCPServer(r).handle_client(reader, writer),
        SYSLOG_HOST,
        SYSLOG_PORT,
    )
    logger.info("Syslog receiver: TCP listening on %s:%d", SYSLOG_HOST, SYSLOG_PORT)

    # Graceful shutdown
    stop = asyncio.Event()

    def _signal_handler():
        logger.info("Syslog receiver: shutting down...")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _signal_handler)

    await stop.wait()

    udp_transport.close()
    tcp_server.close()
    await tcp_server.wait_closed()
    r.close()
    logger.info("Syslog receiver: stopped")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    asyncio.run(run_receiver())


if __name__ == "__main__":
    main()
