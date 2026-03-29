# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import os
import urllib.parse
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Build URL from env vars (same as main app)
PG_USER = os.getenv("POSTGRES_USER", "asn_admin")
PG_PASS = urllib.parse.quote_plus(os.getenv("POSTGRES_PASSWORD", ""))
PG_HOST = os.getenv("DB_META_HOST", "db-metadata")
PG_DB = os.getenv("POSTGRES_DB", "asn_registry")

config.set_main_option("sqlalchemy.url", f"postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}/{PG_DB}")

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
