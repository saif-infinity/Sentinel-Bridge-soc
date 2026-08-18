import asyncio
import logging

from ..config import settings
from ..core.broadcaster import broadcaster
from ..db import Base, SessionLocal, engine
from ..domain.models import TenantUser
from ..scanner import background_scanner
from ..services.password_manager import hash_password
from .system_config import _init_defaults
from .wazuh.service import wazuh_service

logger = logging.getLogger(__name__)


async def run_startup():
    Base.metadata.create_all(bind=engine)

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

    from . import pipeline as pipeline_module
    from ..infrastructure.jobs import retention as retention_module
    pipeline_module.ensure_columns(engine)

    # R4 — TimescaleDB hypertables (PostgreSQL only, idempotent)
    from ..infrastructure.timescale import ensure_timescaledb
    ensure_timescaledb(engine)

    db = SessionLocal()
    try:
        pipeline_module.ensure_defaults(db)
        retention_module.ensure_retention_defaults(db)
    finally:
        db.close()

    # F3-SOAR-WIRE-IN: lane mini-SOAR (F3) — abonnement au bus d'événements F1
    from .events import CHANNEL_RULE_MATCH, event_bus
    from .soar.executor import on_rule_match

    event_bus.subscribe(CHANNEL_RULE_MATCH, on_rule_match)

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
    asyncio.create_task(init_wazuh())

    async def safe_scanner():
        try:
            await background_scanner(SessionLocal, broadcaster.broadcast, settings.SCAN_INTERVAL_SECONDS)
        except Exception as e:
            logger.error("Background scanner crashed: %s", e)
    asyncio.create_task(safe_scanner())

    async def safe_bandwidth_sampler():
        try:
            from ..interface.api.sensors import sample_bandwidth_for_online_analysts
            await sample_bandwidth_for_online_analysts(SessionLocal)
        except Exception as e:
            logger.error("Bandwidth sampler crashed: %s", e)
    asyncio.create_task(safe_bandwidth_sampler())

    async def wazuh_sync_task():
        refresh_counter = 0
        while True:
            if wazuh_service._wazuh_available or wazuh_service._indexer_available:
                try:
                    await wazuh_service.sync_alerts(SessionLocal)
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

            await asyncio.sleep(60)
    asyncio.create_task(wazuh_sync_task())
