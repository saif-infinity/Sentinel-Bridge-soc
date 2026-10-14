import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from ...application.pipeline import ingest_alert
from ...core.config import settings
from ...db import SessionLocal
from ...models import HoneypotEvent

logger = logging.getLogger(__name__)


class HoneypotService:
    """Service honeypot minimal — écoute sur des ports TCP configurables."""

    def __init__(self):
        self._running: bool = False
        self._ports: List[int] = []
        self._servers: List[asyncio.Server] = []
        self._tasks: List[asyncio.Task] = []
        self._total_events: int = 0
        # Rate limit: (src_ip, port) -> last_alert_timestamp
        self._rate_limit: Dict[tuple, float] = {}
        self._rate_limit_window: float = 30.0  # secondes
        # FIX: db_factory was a bare name inside _handle_connection while only being
        # a parameter of start() -> NameError on every connection, swallowed by the
        # surrounding `except Exception`, so the honeypot accepted traffic on
        # 0.0.0.0:2323/3389/8443/5555 and persisted neither alert nor event.
        self._db_factory: Callable[[], Session] = SessionLocal

    @property
    def running(self) -> bool:
        return self._running

    def status(self) -> dict:
        return {
            "running": self._running,
            "ports": list(self._ports),
            "total_events": self._total_events,
        }

    async def start(
        self,
        db_factory,
        broadcast_fn: Optional[Callable] = None,
        ports: Optional[List[int]] = None,
    ):
        """Lance un asyncio.Server sur chaque port configurable."""
        if db_factory is not None:
            self._db_factory = db_factory
        if ports is None:
            ports = [2323, 3389, 8443, 5555]
        self._ports = ports
        self._running = True

        for port in ports:
            try:
                server = await asyncio.start_server(
                    self._handle_connection,
                    host="0.0.0.0",
                    port=port,
                )
                self._servers.append(server)
                addr = server.sockets[0].getsockname() if server.sockets else port
                logger.info("Honeypot listening on port %s", addr)
            except OSError as e:
                logger.warning("Honeypot: port %d already in use, skipping: %s", port, e)
                continue

        logger.info("HoneypotService started on %d ports", len(self._servers))

    async def stop(self):
        """Arrête tous les serveurs."""
        self._running = False
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self._servers.clear()
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        logger.info("HoneypotService stopped")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Gère une connexion entrante : log, rate-limit, alerte, persistance."""
        peer = writer.get_extra_info("peername")
        if not peer:
            writer.close()
            return
        src_ip = peer[0]
        src_port = peer[1]
        port = writer.get_extra_info("sockname")[1] if writer.get_extra_info("sockname") else 0

        # Rate limit par (src_ip, port)
        now = datetime.now(timezone.utc).timestamp()
        key = (src_ip, port)
        last = self._rate_limit.get(key, 0)
        if now - last < self._rate_limit_window:
            writer.close()
            return
        self._rate_limit[key] = now

        # Lire les premiers octets du payload
        payload_preview: Optional[str] = None
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=2)
            if data:
                payload_preview = data.decode("utf-8", errors="replace")[:500]
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        self._total_events += 1
        logger.info("Honeypot event: port=%d src_ip=%s src_port=%d", port, src_ip, src_port)

        # Créer l'alerte via le pipeline
        alert_id: Optional[int] = None
        try:
            db = self._db_factory()
            try:
                result = ingest_alert({
                    "description": f"Honeypot connection on port {port} from {src_ip}",
                    "severity": 3,
                    "src_ip": src_ip,
                    "tenant_id": "default",
                    "agent_id": "honeypot",
                }, db=db)
                if result and result.get("status") == "accepted":
                    # Chercher l'alert_id créé
                    from ...models import Alert
                    alert = (
                        db.query(Alert)
                        .filter(
                            Alert.src_ip == src_ip,
                            Alert.agent_id == "honeypot",
                            Alert.tenant_id == "default",
                        )
                        .order_by(Alert.timestamp.desc())
                        .first()
                    )
                    if alert:
                        alert_id = alert.id
            finally:
                db.close()
        except Exception as e:
            logger.warning("Honeypot: ingest_alert failed: %s", e)

        # Persister l'événement
        try:
            db = self._db_factory()
            try:
                event = HoneypotEvent(
                    tenant_id="default",
                    port=port,
                    src_ip=src_ip,
                    src_port=src_port,
                    payload_preview=payload_preview,
                    alert_id=alert_id,
                )
                db.add(event)
                db.commit()
                db.refresh(event)
            finally:
                db.close()
        except Exception as e:
            logger.warning("Honeypot: persist event failed: %s", e)

        writer.close()
        await writer.wait_closed()
