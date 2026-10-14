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
    asyncio.create_task(init_wazuh())

    async def safe_scanner():
        try:
            await background_scanner(SessionLocal, broadcaster.broadcast, settings.SCAN_INTERVAL_SECONDS)
        except Exception as e:
            logger.error("Background scanner crashed: %s", e)
    asyncio.create_task(safe_scanner())

    async def safe_honeypot():
        try:
            await honeypot_service.start(SessionLocal, broadcaster.broadcast, ports=[2323, 3389, 8443, 5555])
            from ..interface.api.honeypot import set_honeypot_service
            set_honeypot_service(honeypot_service)
        except Exception as e:
            logger.error("Honeypot crashed: %s", e)
    asyncio.create_task(safe_honeypot())

    async def safe_bandwidth_sampler():
        try:
            from ..interface.api.sensors import sample_bandwidth_for_online_analysts
            await sample_bandwidth_for_online_analysts(SessionLocal)
        except Exception as e:
            logger.error("Bandwidth sampler crashed: %s", e)
    asyncio.create_task(safe_bandwidth_sampler())

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
        asyncio.create_task(wazuh_sync_task())
    else:
        logger.info("Source Wazuh désactivée — sync ignoré")
