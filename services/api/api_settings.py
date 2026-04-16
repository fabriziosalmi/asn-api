# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Validated configuration for the ASN Risk API service."""

    # PostgreSQL
    postgres_user: str = Field(..., description="PostgreSQL username")
    postgres_password: str = Field(..., description="PostgreSQL password")
    postgres_db: str = Field(default="asn_registry", description="PostgreSQL database")
    db_meta_host: str = Field(default="db-metadata", description="PostgreSQL host")

    # ClickHouse
    db_ts_host: str = Field(default="db-timeseries", description="ClickHouse host")
    clickhouse_user: str = Field(default="default", description="ClickHouse user")
    clickhouse_password: str = Field(default="", description="ClickHouse password")

    # Redis
    redis_host: str = Field(default="broker-cache", description="Redis host")

    # API
    api_secret_key: str = Field(
        ...,
        min_length=32,
        description="API authentication key (minimum 32 characters)",
    )
    cache_ttl: int = Field(
        default=60, ge=0, le=3600, description="Cache TTL in seconds"
    )
    api_rate_limit: int = Field(
        default=100, ge=1, le=10000, description="Requests per minute per IP"
    )
    cors_origins: str = Field(
        default="http://localhost:3000",
        description="Comma-separated CORS origins",
    )

    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format: json or text")

    # Pool
    db_pool_size: int = Field(default=20, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=50)

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
