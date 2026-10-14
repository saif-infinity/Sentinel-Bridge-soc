import asyncio
import logging

from ..config import settings
from ..core.broadcaster import broadcaster
from ..db import Base, SessionLocal, engine
from ..domain.investigations import Investigation, InvestigationEvidence, InvestigationRecommendation  # noqa: F401
from ..domain.models import TenantUser
from ..infrastructure.honeypot.service import HoneypotService
from ..scanner import background_scanner
from ..services.password_manager import hash_password
from .system_config import _init_defaults
from .wazuh.service import wazuh_service

honeypot_service = HoneypotService()

logger = logging.getLogger(__name__)

# Tâches d'arrière-plan créées au démarrage. Sans référence conservée, le
# ramasse-miettes peut détruire une tâche en cours d'exécution (« Task was
# destroyed but it is pending! ») et rien ne peut l'annuler à l'arrêt.
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro, *, name: str) -> asyncio.Task:
    """Crée une tâche référencée et nommée, avec nettoyage + log à la fin."""
    task = asyncio.create_task(coro, name=name)
    _background_tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _background_tasks.discard(t)
        if t.cancelled():
            return
        exc = t.exception()
        if exc is not None:
            logger.error("Tâche d'arrière-plan %r terminée en erreur: %s", name, exc)

    task.add_done_callback(_done)
    logger.info("Tâche d'arrière-plan démarrée: %s", name)
    return task


async def run_shutdown():
    """Arrêt propre : honeypot, collecteurs, puis annulation des tâches.

    Appelée par le handler `lifespan` de `interface/main.py`. Sans elle, un
    `SIGTERM` laissait les sockets du honeypot ouverts et les tâches en vol.
    """
    logger.info("=== AEGIS Sentinel Backend Shutting Down ===")
    if settings.ENABLE_HONEYPOT and honeypot_service.running:
        try:
            await honeypot_service.stop()
            logger.info("Honeypot arrêté.")
        except Exception as e:  # noqa: BLE001 — l'arrêt ne doit jamais échouer
            logger.warning("Arrêt du honeypot en erreur (ignoré): %s", e)

    pending = [t for t in _background_tasks if not t.done()]
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
        logger.info("%d tâche(s) d'arrière-plan annulée(s).", len(pending))


async def run_startup():
    # `create_all()` ne sait ni ALTER ni DROP : il crée les tables manquantes et
    # ignore toute évolution de colonne. C'est pratique en dev, dangereux en
    # production où le schéma doit venir des migrations Alembic (`alembic upgrade
    # head`), seules reproductibles et réversibles. AUTO_CREATE_SCHEMA=false
    # désactive le raccourci ; la révision 0001 sert de baseline.
    if settings.AUTO_CREATE_SCHEMA:
        Base.metadata.create_all(bind=engine)
    else:
        logger.info(
            "AUTO_CREATE_SCHEMA=false : le schéma n'est pas créé au démarrage. "
            "Exécutez `alembic upgrade head`."
        )

    # F4 — Seed the super admin account (idempotent).
    sa_pw = settings.SUPER_ADMIN_PASSWORD.get_secret_value()
    db = SessionLocal()
    try:
        sa_exists = db.query(TenantUser).filter(TenantUser.role == "super_admin").first() is not None
        if sa_pw and not sa_exists:
            db.add(TenantUser(
                username="super_admin",
                tenant_id="default",
                password_hash=hash_password(sa_pw),
                role="super_admin",
                is_active=True,
            ))
            db.commit()
        elif not sa_pw and not sa_exists:
            logger.warning("No super admin seeded: SUPER_ADMIN_PASSWORD unset")
    finally:
        db.close()

    from ..infrastructure.jobs import retention as retention_module
    from . import pipeline as pipeline_module
    pipeline_module.ensure_columns(engine)

    # R4 — TimescaleDB hypertables (PostgreSQL only, idempotent)
    from ..infrastructure.timescale import ensure_timescaledb
    ensure_timescaledb(engine)

    from ..domain.rule_models import ensure_mitre_columns

    db = SessionLocal()
    try:
        pipeline_module.ensure_defaults(db)
        retention_module.ensure_retention_defaults(db)
        ensure_mitre_columns(db)
    finally:
        db.close()

    # F3-SOAR-WIRE-IN: lane mini-SOAR (F3) — abonnement au bus d'événements F1
    from .ai_auto.handler import on_alert_ingested
    from .events import CHANNEL_ALERT_INGESTED, CHANNEL_RULE_MATCH, event_bus
    from .investigations.handler import on_rule_match_investigate
    from .soar.executor import on_rule_match

    event_bus.subscribe(CHANNEL_RULE_MATCH, on_rule_match)
    event_bus.subscribe(CHANNEL_RULE_MATCH, on_rule_match_investigate)
    # F5 — Auto-analyse IA : écoute les ingestions acceptées par le pipeline.
    event_bus.subscribe(CHANNEL_ALERT_INGESTED, on_alert_ingested)

    try:
        db = SessionLocal()
        try:
            _init_defaults(db)
        finally:
            db.close()
    except Exception as e:
        logger.warning("Config init: %s", e)

    async def init_wazuh():
        try:
            wazuh_service.reload_config()
            await wazuh_service.refresh_agent_cache()
        except Exception as e:
            logger.warning("Wazuh cache init: %s (will retry in background)", e)
    _spawn(init_wazuh(), name="wazuh-init")

    async def safe_scanner():
        try:
            await background_scanner(SessionLocal, broadcaster.broadcast, settings.SCAN_INTERVAL_SECONDS)
        except Exception as e:
            logger.error("Background scanner crashed: %s", e)
    _spawn(safe_scanner(), name="scanner")

    # Quatre ports en écoute sur toutes les interfaces : activable explicitement.
    if settings.ENABLE_HONEYPOT:
        hp_ports = settings.HONEYPOT_PORTS or [2323, 3389, 8443, 5555]
        logger.warning("Honeypot ACTIVÉ — ports en écoute sur 0.0.0.0: %s", hp_ports)

        async def safe_honeypot():
            try:
                await honeypot_service.start(SessionLocal, broadcaster.broadcast, ports=hp_ports)
                from ..interface.api.honeypot import set_honeypot_service
                set_honeypot_service(honeypot_service)
            except Exception as e:
                logger.error("Honeypot crashed: %s", e)
        _spawn(safe_honeypot(), name="honeypot")
    else:
        logger.info(
            "Honeypot désactivé (ENABLE_HONEYPOT=false, défaut). "
            "Activez-le explicitement si votre déploiement en a besoin."
        )

    async def safe_bandwidth_sampler():
        try:
            from ..interface.api.sensors import sample_server_bandwidth
            await sample_server_bandwidth(SessionLocal)
        except Exception as e:
            logger.error("Bandwidth sampler crashed: %s", e)
    _spawn(safe_bandwidth_sampler(), name="bandwidth-sampler")

    async def wazuh_sync_task():
        from ..db import SessionLocal
        from .source_control import is_source_enabled
        refresh_counter = 0
        while True:
            db = SessionLocal()
            try:
                if not is_source_enabled(db, "wazuh"):
                    await asyncio.sleep(60)
                    continue
                if wazuh_service._wazuh_available or wazuh_service._indexer_available:
                    try:
                        await wazuh_service.sync_alerts(db)
                    except Exception as e:
                        logger.warning("Alert sync error: %s", e)

                    refresh_counter += 1
                    if refresh_counter >= 10:
                        refresh_counter = 0
                        try:
                            await wazuh_service.refresh_agent_cache()
                        except Exception as e:
                            logger.warning("Cache refresh error: %s", e)
                else:
                    await asyncio.sleep(120)
                    continue
            finally:
                db.close()
            await asyncio.sleep(60)
    if settings.ENABLE_WAZUH_SOURCE:
        _spawn(wazuh_sync_task(), name="wazuh-sync")
    else:
        logger.info("Source Wazuh désactivée — sync ignoré")
