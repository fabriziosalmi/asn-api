# Configuration

## Environment Variables

The platform is configured through environment variables. Create a `.env` file in the project root:

```bash
cp .env.example .env
```

### Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | asn_admin | PostgreSQL username |
| `POSTGRES_PASSWORD` | secure_password | PostgreSQL password |
| `POSTGRES_DB` | asn_registry | Database name |
| `CLICKHOUSE_USER` | default | ClickHouse username |
| `CLICKHOUSE_PASSWORD` | (empty) | ClickHouse password |

### API Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `API_SECRET_KEY` | dev-secret | API authentication key |
| `API_RATE_LIMIT` | 100 | Requests per minute per key |

### Ingestor Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `BGP_STREAM_URL` | wss://ris-live.ripe.net/v1/ws/ | RIPE RIS WebSocket endpoint |
| `THREAT_FEED_INTERVAL` | 3600 | Seconds between threat feed updates |

## Docker Compose Overrides

For production deployments, create a `docker-compose.override.yml`:

```yaml
services:
  asn-api:
    environment:
      - API_SECRET_KEY=${PRODUCTION_API_KEY}
    deploy:
      replicas: 3
      
  db-metadata:
    volumes:
      - /data/postgres:/var/lib/postgresql/data
      
  db-timeseries:
    volumes:
      - /data/clickhouse:/var/lib/clickhouse
```

## Resource Allocation

Recommended resources for production:

| Service | CPU | Memory |
|---------|-----|--------|
| API | 1 core | 512MB |
| Engine | 2 cores | 1GB |
| Ingestor | 1 core | 512MB |
| PostgreSQL | 2 cores | 2GB |
| ClickHouse | 4 cores | 8GB |
| Redis | 1 core | 256MB |
