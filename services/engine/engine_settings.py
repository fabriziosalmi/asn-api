# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

from pydantic import Field
from pydantic_settings import BaseSettings


class EngineSettings(BaseSettings):
    """Validated configuration for the ASN Scoring Engine."""

    # PostgreSQL
    # min_length is what makes the README's "required credentials fail-fast"
    # claim true: docker compose substitutes an unset variable with an EMPTY
    # string, which satisfies a bare required str and defers the failure to the
    # first query. A length floor turns that back into a startup error.
    postgres_user: str = Field(..., min_length=1, description="PostgreSQL username")
    postgres_password: str = Field(..., min_length=1, description="PostgreSQL password")
    postgres_db: str = Field(default="asn_registry", description="PostgreSQL database")
    db_meta_host: str = Field(default="db-metadata", description="PostgreSQL host")

    # ClickHouse
    db_ts_host: str = Field(default="db-timeseries", description="ClickHouse host")
    clickhouse_user: str = Field(default="default", description="ClickHouse user")
    clickhouse_password: str = Field(default="", description="ClickHouse password")

    # Redis / Celery
    broker_url: str = Field(
        default="redis://broker-cache:6379/0", description="Celery broker URL"
    )

    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format: json or text")

    # Pool
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=5, ge=0, le=50)

    # Enrichment
    enrichment_timeout: int = Field(
        default=3, ge=1, le=30, description="External API timeout"
    )
    circuit_breaker_threshold: int = Field(default=5, ge=1, le=50)
    circuit_breaker_cooldown: int = Field(default=300, ge=30, le=3600)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
