# Configuration

## Overview

All services use **Pydantic Settings** for validated configuration. Invalid or missing required values cause a startup error with a clear message.

## Environment Variables

Create a `.env` file from the template:

```bash
cp .env.example .env
```

### Required Variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_USER` | PostgreSQL username |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `API_SECRET_KEY` | API authentication key (`openssl rand -hex 32`) |

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | asn_registry | PostgreSQL database name |
| `DB_META_HOST` | db-metadata | PostgreSQL host |
| `DB_TS_HOST` | db-timeseries | ClickHouse host |
| `CLICKHOUSE_USER` | default | ClickHouse username |
| `CLICKHOUSE_PASSWORD` | (empty) | ClickHouse password |
| `REDIS_HOST` | broker-cache | Redis host |
| `BROKER_URL` | redis://broker-cache:6379/0 | Celery broker URL |

### API Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_TTL` | 60 | API cache duration in seconds (0-3600) |
| `API_RATE_LIMIT` | 100 | Requests per minute per IP (1-10000) |
| `CORS_ORIGINS` | * | Comma-separated allowed origins |

### Logging Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_FORMAT` | json | Log format: `json` or `text` |
| `LOG_LEVEL` | INFO | Log level: DEBUG, INFO, WARNING, ERROR |

### Pool Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_POOL_SIZE` | 20 | PostgreSQL connection pool size (1-100) |
| `DB_MAX_OVERFLOW` | 10 | Max overflow connections (0-50) |

### Engine Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ENRICHMENT_TIMEOUT` | 3 | External API timeout in seconds (1-30) |
| `CIRCUIT_BREAKER_THRESHOLD` | 5 | Failures before circuit opens (1-50) |
| `CIRCUIT_BREAKER_COOLDOWN` | 300 | Cooldown period in seconds (30-3600) |

### Grafana

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAFANA_ADMIN_PASSWORD` | admin | Grafana admin password |

## Docker Compose Overrides

For production, create a `docker-compose.override.yml`:

```yaml
services:
  asn-api:
    deploy:
      replicas: 3

  db-metadata:
    volumes:
      - /data/postgres:/var/lib/postgresql/data

  db-timeseries:
    volumes:
      - /data/clickhouse:/var/lib/clickhouse
```

## Database Migrations

Schema changes are managed with Alembic:

```bash
# For existing databases (mark current schema as baseline)
cd services/api
alembic stamp 001_baseline

# For new databases
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "description"
```

## Resource Allocation

Recommended resources for production:

| Service | CPU | Memory |
|---------|-----|--------|
| API | 0.5 core | 512MB |
| Engine | 1 core | 1GB |
| Ingestor | 0.5 core | 512MB |
| PostgreSQL | 0.5 core | 512MB |
| ClickHouse | 1 core | 2GB |
| Redis | - | 256MB (capped) |
