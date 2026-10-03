"""TimescaleDB: hypertable conversion, compression, retention policies.
Called from bootstrap.py after create_all + ensure_columns."""
import logging
from sqlalchemy import text, inspect

logger = logging.getLogger(__name__)

# Tables to convert to hypertables
HYPERTABLES = {
    "alerts": {"time_col": "timestamp", "chunk": "INTERVAL '1 day'"},
    "suricata_alerts": {"time_col": "timestamp", "chunk": "INTERVAL '1 day'"},
}

COMPRESSION_AGE = "INTERVAL '7 days'"
GLOBAL_RETENTION = "INTERVAL '90 days'"


def _is_postgresql(engine) -> bool:
    return engine.dialect.name == "postgresql"


def ensure_timescaledb(engine) -> None:
    """Create extension, convert hypertables, enable compression + retention policies."""
    if not _is_postgresql(engine):
        logger.info("TimescaleDB: skipped (not PostgreSQL, dialect=%s)", engine.dialect.name)
        return

    # 1. Create extension — non-fatal si TimescaleDB n'est pas installé sur ce serveur.
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb"))
    except Exception as e:
        logger.warning(
            "TimescaleDB: extension indisponible (%s) — hypertables/compression/retention désactivés, "
            "le backend continue sur PostgreSQL standard.",
            e,
        )
        return
    logger.info("TimescaleDB: extension ensured")

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    for table, cfg in HYPERTABLES.items():
        if table not in existing_tables:
            logger.warning("TimescaleDB: table %s not found, skipping", table)
            continue
        _convert_hypertable(engine, table, cfg)
        _enable_compression(engine, table)

    # Global retention policy (safety net)
    _add_global_retention(engine)


def _convert_hypertable(engine, table: str, cfg: dict) -> None:
    """Drop old PK, add composite PK (id, time_col), create hypertable."""
    time_col = cfg["time_col"]
    chunk = cfg["chunk"]

    with engine.begin() as conn:
        # Check if already a hypertable
        result = conn.execute(text(
            "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = :t"
        ), {"t": table})
        if result.fetchone():
            logger.info("TimescaleDB: %s is already a hypertable, skipping", table)
            return

        # Drop old PK, add composite PK
        pk_name = f"{table}_pkey"
        conn.execute(text(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {pk_name}"))
        conn.execute(text(f"ALTER TABLE {table} ADD PRIMARY KEY (id, {time_col})"))

        # Convert to hypertable (idempotent via if_not_exists)
        conn.execute(text(
            f"SELECT create_hypertable('{table}', '{time_col}', "
            f"chunk_time_interval => {chunk}, migrate_data => TRUE, if_not_exists => TRUE)"
        ))
        logger.info("TimescaleDB: %s converted to hypertable (time_col=%s)", table, time_col)


def _enable_compression(engine, table: str) -> None:
    """Enable compression with segmentby=timestamp, compress after 7 days."""
    with engine.begin() as conn:
        # Check if compression already enabled
        result = conn.execute(text(
            "SELECT 1 FROM timescaledb_information.jobs WHERE hypertable_name = :t "
            "AND proc_name = 'policy_compression'"
        ), {"t": table})
        if result.fetchone():
            logger.info("TimescaleDB: compression policy already exists for %s", table)
            return

        conn.execute(text(
            f"ALTER TABLE {table} SET ("
            f"timescaledb.compress, "
            f"timescaledb.compress_segmentby = 'timestamp', "
            f"timescaledb.compress_orderby = 'id DESC'"
            f")"
        ))
        conn.execute(text(
            f"SELECT add_compression_policy('{table}', compress_after => {COMPRESSION_AGE}, "
            f"if_not_exists => TRUE)"
        ))
        logger.info("TimescaleDB: compression enabled for %s (after %s)", table, COMPRESSION_AGE)


def _add_global_retention(engine) -> None:
    """Add global retention policy (90 days) as safety net."""
    with engine.begin() as conn:
        for table in HYPERTABLES:
            result = conn.execute(text(
                "SELECT 1 FROM timescaledb_information.jobs WHERE hypertable_name = :t "
                "AND proc_name = 'policy_retention'"
            ), {"t": table})
            if result.fetchone():
                logger.info("TimescaleDB: retention policy already exists for %s", table)
                continue
            conn.execute(text(
                f"SELECT add_retention_policy('{table}', drop_after => {GLOBAL_RETENTION}, "
                f"if_not_exists => TRUE)"
            ))
            logger.info("TimescaleDB: global retention set for %s (%s)", table, GLOBAL_RETENTION)