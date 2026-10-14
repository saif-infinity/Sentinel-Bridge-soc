"""Environnement Alembic.

Deux points importants :

* la chaîne de connexion vient de `settings.DATABASE_URL` (donc de
  l'environnement), jamais d'une valeur codée en dur ;
* `target_metadata` est `Base.metadata`, ce qui rend
  `alembic revision --autogenerate` réellement utilisable : Alembic compare
  alors les modèles SQLAlchemy au schéma vivant.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.db import Base

# Importer les modules de modèles pour que leurs tables s'enregistrent sur
# Base.metadata avant la comparaison autogenerate.
from app.domain import (
    investigations,  # noqa: F401
    models,  # noqa: F401
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Le driver asynchrone/psycopg éventuel dans DATABASE_URL n'est pas compris par
# Alembic : on force un DSN sync pg8000/psycopg2 sur la même base.
_url = settings.DATABASE_URL.replace("+asyncpg", "").replace("+psycopg", "+pg8000")
config.set_main_option("sqlalchemy.url", _url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Mode hors-ligne : génère le SQL sans se connecter (`--sql`)."""
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
