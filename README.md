# ASN Risk Intelligence Platform

> **Real-time trust scoring for Internet Autonomous Systems using BGP telemetry, threat intelligence, and network topology analysis**

[![License](https://img.shields.io/badge/license-Non--Commercial-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)
[![CI](https://github.com/fabriziosalmi/asn-api/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/asn-api/actions)

## Overview

The ASN Risk Intelligence Platform is a production-grade system for assessing the security and stability risk of Autonomous Systems (ASNs) on the Internet. By combining real-time BGP routing data, threat intelligence feeds, and sophisticated network topology analysis, it generates comprehensive risk scores (0-100) that help organizations make informed decisions about network trust.

**Key Capabilities:**
- **Real-time BGP Analysis** - Process hundreds of BGP updates per second from RIPE RIS live streams
- **Multi-source Threat Intelligence** - Integrate Spamhaus, URLhaus, and other feeds
- **Advanced Scoring Engine** - 30+ signals across hygiene, threats, stability, and forensics
- **Historical Tracking** - 365-day score history with trend analysis and pagination
- **Topology Analysis** - Upstream/downstream risk assessment and peer pressure analysis
- **Production-Ready** - Async API with caching, rate limiting, structured logging, and monitoring

## Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose v2+
- 8GB RAM minimum (16GB recommended)
- 50GB disk space for time-series data

### Launch the Platform

```bash
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api

# Configure environment
cp .env.example .env
# Edit .env with your credentials (POSTGRES_PASSWORD, API_SECRET_KEY, etc.)

# Start all services
docker-compose up --build
```

Wait 2-3 minutes for initial data ingestion and database initialization. Then access:

| Service | URL | Credentials |
|---------|-----|-------------|
| API Documentation | http://localhost/api/docs | API Key from `.env` |
| Grafana Dashboards | http://localhost/dashboard/ | admin / `$GRAFANA_ADMIN_PASSWORD` |
| VitePress Docs | http://localhost:5173 | (from docs/ dir) |

## Architecture

### System Design

```
Internet ─────────────────────────────────────────────────────────────
  │                                                                  │
  ▼ HTTP                                                             ▼ WebSocket
Nginx (80) ──► api (8000) ──► PostgreSQL (State)         ws://host/api/v1/stream
  │                │                                                  │
  └──► Grafana    └──► Redis L2 Cache ◄────── engine (Worker)        │
        (3000)         Redis Pub/Sub ─────────────────────────────────┘
                             │
BGP Stream ──► ingestor ──► ClickHouse (History) ◄── engine
               + Threat feeds
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **API Gateway** | FastAPI + async Redis | REST API with validated config (Pydantic Settings) |
| **Task Queue** | Celery + Redis | Asynchronous scoring with correlation ID tracing |
| **State Database** | PostgreSQL 15 | Current scores, metadata, signals (with Alembic migrations) |
| **Time-Series DB** | ClickHouse | High-volume BGP events with TTL retention policies |
| **Caching Layer** | Redis 7 | API response caching, atomic rate limiting (Lua) |
| **Visualization** | Grafana | Real-time dashboards and monitoring |
| **Documentation** | VitePress | Interactive API documentation |

## API Reference

### Authentication

All API endpoints require an API key passed via the `X-API-Key` header.

### Endpoints (v1)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/v1/asn/{asn}` | Detailed risk score card |
| `GET` | `/v1/asn/{asn}/history?days=30&offset=0&limit=200` | Paginated score history |
| `GET` | `/v1/asn/{asn}/upstreams` | Upstream risk analysis |
| `GET` | `/v1/asn/{asn}/peeringdb` | PeeringDB metadata (cached 24h) |
| `GET` | `/v1/tools/compare?asn_a=X&asn_b=Y` | Side-by-side ASN comparison |
| `GET` | `/v1/tools/domain-risk?domain=X` | Resolve domain → ASN → risk score |
| `POST` | `/v1/tools/bulk-risk-check` | Bulk analysis (max 1000 ASNs) |
| `POST` | `/v1/whitelist` | Add ASN to whitelist |
| `GET` | `/feeds/edl` | Firewall EDL feed (plain text, no auth) |
| `WebSocket` | `/v1/stream?api_key=X` | Real-time score update firehose |
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/api/docs` | Swagger UI |
| `GET` | `/api/redoc` | ReDoc |

Legacy routes without `/v1/` prefix are supported for backward compatibility but hidden from docs.

### Example

```bash
# Get ASN risk score
curl -H "X-API-Key: $API_KEY" http://localhost/api/v1/asn/15169

# Paginated history (last 7 days, 50 records)
curl -H "X-API-Key: $API_KEY" "http://localhost/api/v1/asn/15169/history?days=7&limit=50"

# Bulk analysis
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 3356]}' http://localhost/api/v1/tools/bulk-risk-check

# Compare two ASNs side-by-side
curl -H "X-API-Key: $API_KEY" "http://localhost/api/v1/tools/compare?asn_a=15169&asn_b=3356"

# Resolve domain → ASN → infrastructure risk
curl -H "X-API-Key: $API_KEY" "http://localhost/api/v1/tools/domain-risk?domain=suspicious.example.com"

# PeeringDB metadata for an ASN
curl -H "X-API-Key: $API_KEY" http://localhost/api/v1/asn/15169/peeringdb

# Firewall EDL feed (no auth required, plain-text ASN list)
curl http://localhost/api/feeds/edl
curl "http://localhost/api/feeds/edl?max_score=49"  # CRITICAL only

# Real-time score stream (WebSocket)
wscat -c "ws://localhost/api/v1/stream?api_key=$API_KEY"
```

### Response Headers

Every response includes:

| Header | Description |
|--------|-------------|
| `X-Trace-ID` | Distributed tracing correlation ID |
| `X-RateLimit-Limit` | Rate limit ceiling |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Window reset timestamp |
| `X-Response-Time` | Server processing time |
| `ETag` | Stable SHA256-based cache validation |

### Error Responses

All errors use a structured envelope:

```json
{
  "error": "ASN not found or not yet scored",
  "code": "HTTP_404",
  "request_id": "1711700400-a1b2c3d4"
}
```

### Input Validation

- ASN range: 1 - 4,294,967,295 (32-bit)
- History days: 1 - 365
- Bulk check: max 1000 ASNs per request
- Whitelist reason: 1 - 500 characters

## Scoring Methodology

The platform uses a multi-factor scoring model analyzing 30+ signals across four categories. Final score ranges from 0 (critical risk) to 100 (trusted).

### Scoring Categories

| Category | Weight | Description |
|----------|--------|-------------|
| **Routing Hygiene** | 40% | BGP routing health and RPKI compliance |
| **Threat Intelligence** | 35% | Malicious activity and threat feed correlations |
| **Network Stability** | 25% | BGP churn, predictive stability, upstream quality |
| **Forensic Signals** | Bonus/Penalty | Advanced BGP analysis and topology risk |

### Signal Breakdown

**Routing Hygiene (40%)**
- RPKI Invalid ROA status (-20 points)
- Valley-free violation / route leaks (-20 points)
- Bogon/reserved prefix advertisements (-10 points)
- Prefix de-aggregation / fragmentation (-10 points)
- Zombie ASN: active registration, zero routes (-15 points)

**Threat Intelligence (35%)**
- Spamhaus DROP/EDROP listing (-30 points)
- High spam emission rate (-15 points)
- Botnet C2 hosting (-20 per C2, cap -40)
- Threat recidivism over 30 days (-10 points)
- WHOIS entropy (generated names) (-10 points)

**Network Stability (25%)**
- Upstream churn >2 providers/90d (-25 points)
- Route flapping >100 withdrawals/week (-5 points)
- Predictive instability (statistical analysis) (-15 points)
- PeeringDB profile present (+5 bonus)
- Multiple Tier-1 upstreams (+5 bonus)
- Bad neighborhood (low-scoring upstreams) (-5 to -15 points)

**Forensic Signals (Bonus/Penalty)**
- Toxic downstream clientele (-20 points if avg <70)
- DDoS sponge / blackhole community tagging (-15 points)
- Traffic engineering chaos / excessive prepending (-10 points)

### Risk Levels

| Score Range | Risk Level | Interpretation |
|-------------|-----------|----------------|
| **90-100** | LOW | Highly trusted, minimal security concerns |
| **75-89** | MEDIUM | Generally reliable with minor issues |
| **50-74** | HIGH | Significant concerns, use with caution |
| **0-49** | CRITICAL | High-risk network, avoid if possible |

## Configuration

All services use validated configuration via Pydantic Settings. Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

### Required Variables

| Variable | Description |
|----------|-------------|
| `POSTGRES_USER` | PostgreSQL username |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `API_SECRET_KEY` | API authentication key (use `openssl rand -hex 32`) |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_TTL` | 60 | API cache duration (seconds) |
| `API_RATE_LIMIT` | 100 | Requests per minute per IP |
| `CORS_ORIGINS` | * | Comma-separated allowed origins |
| `LOG_FORMAT` | json | Log format: `json` or `text` |
| `LOG_LEVEL` | INFO | Log level |
| `DB_POOL_SIZE` | 20 | PostgreSQL connection pool size |
| `DB_MAX_OVERFLOW` | 10 | Max pool overflow connections |

See `.env.example` for the complete list.

## Data Architecture

### PostgreSQL (State Database)

Tables: `asn_registry`, `asn_signals`, `asn_whitelist`

Indexes on: `total_score`, `risk_level`, `last_scored_at`, `asn_signals.asn`, `asn_whitelist.asn`

Schema managed via **Alembic** migrations (`services/api/migrations/`). For existing databases: `alembic stamp 001_baseline`. For new databases: `alembic upgrade head`.

### ClickHouse (Time-Series Database)

Tables: `bgp_events`, `threat_events`, `asn_score_history`, `daily_metrics`, `forensic_metrics`, `api_requests`

Materialized views for real-time aggregation: `bgp_daily_mv`, `threat_daily_mv`, `forensic_prepending_mv`

### Data Retention (TTL)

| Data Type | Retention | Storage |
|-----------|-----------|---------|
| BGP Events | 90 days | ClickHouse (partitioned) |
| Threat Events | 180 days | ClickHouse |
| API Request Logs | 30 days | ClickHouse |
| Score History | Indefinite | ClickHouse (no TTL, retained for trending) |
| Daily Metrics | Indefinite | ClickHouse (aggregated) |
| Current Scores | Persistent | PostgreSQL |

## Docker

### Multi-stage Builds

All service Dockerfiles use multi-stage builds for smaller images and run as non-root `appuser`.

### Health Checks

Every container has a health check:

| Service | Health Check |
|---------|-------------|
| PostgreSQL | `pg_isready` |
| ClickHouse | `wget /ping` |
| Redis | `redis-cli ping` |
| API | `GET /health` |
| Engine | `celery inspect ping` |
| Ingestor | ClickHouse connectivity |

### Redis Configuration

Redis runs with `maxmemory 256mb` and `allkeys-lru` eviction policy to prevent OOM.

### Scaling

```bash
docker-compose up -d --scale asn-api=3
docker-compose up -d --scale asn-engine=5
```

For Kubernetes deployment, see [KUBERNETES.md](./KUBERNETES.md).

## Development

### Setup

```bash
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Start services
docker-compose up --build
```

### Testing

```bash
pip install -r services/api/requirements.txt
pip install -r services/engine/requirements.txt
pip install pytest pytest-asyncio anyio httpx starlette

pytest tests/ -v
```

### Load Testing

```bash
pip install locust
locust -f tests/load/locustfile.py --host http://localhost:80/api
```

See `tests/load/README.md` for performance targets and headless CI mode.

### Code Quality

```bash
# Pre-commit runs ruff + black + security checks automatically
pre-commit run --all-files

# Manual
ruff check .
black --check .
```

### CI/CD

**GitHub Actions** (`.github/workflows/ci.yml`):
1. **Lint** - ruff + black
2. **Test** - Python 3.11 + 3.12 matrix
3. **Security** - pip-audit on all requirements
4. **Load Test** - Locust syntax validation (main branch)

**GitLab CI** (`.gitlab-ci.yml`):
1. **Lint** - ruff + black
2. **Test** - pytest with service dependencies
3. **Security** - pip-audit
4. **Build** - Docker image build and registry push

### Project Structure

```
asn-api/
  services/
    api/
      main.py              # FastAPI routes and middleware
      api_settings.py       # Pydantic Settings (validated config)
      alembic.ini           # Alembic configuration
      migrations/           # Database migrations
      Dockerfile            # Multi-stage, non-root
    engine/
      scorer.py             # Risk scoring algorithm (30+ signals)
      tasks.py              # Celery tasks with correlation IDs
      engine_settings.py    # Pydantic Settings
      Dockerfile
    ingestor/
      start_ingestion_stream.py  # RIPE RIS + threat intel
      Dockerfile
    dashboard/              # Grafana dashboards
    db-metadata/init.sql    # PostgreSQL schema + indexes
    db-timeseries/init.sql  # ClickHouse schema + TTL policies
  tests/
    test_api.py             # 67 API tests
    test_scorer.py          # 2 scorer tests (exercise real _apply_scoring_rules)
    load/locustfile.py      # Load tests
  docs/                     # VitePress documentation
  docker-compose.yml        # 9-service orchestration
  .env.example              # All configuration variables
  .pre-commit-config.yaml   # ruff, black, security hooks
  .github/workflows/ci.yml  # GitHub Actions (matrix)
  .gitlab-ci.yml            # GitLab CI
```

## Observability

### Structured JSON Logging

All services emit structured JSON logs (configurable via `LOG_FORMAT`):

```json
{"timestamp": "2026-03-29T10:15:00", "name": "asn_api", "level": "INFO", "message": "scoring_complete", "asn": 15169, "score": 95, "level": "LOW"}
```

### Distributed Tracing

Every request gets a `X-Trace-ID` that propagates from the API through Celery tasks to the scoring engine, enabling end-to-end request tracing across services.

### Grafana Dashboards

5 pre-built dashboards at http://localhost/dashboard/:
1. **Mission Control** - Real-time BGP activity and threat detection
2. **System Health** - Ingestion rates and database metrics
3. **Network Topology** - AS connections and top active ASNs
4. **API Performance** - Request rate, latency percentiles, cache hit rate
5. **Forensics** - BGP event rates, threat signal trends, prepending/blackhole analysis

### Cache Invalidation

The scoring engine automatically invalidates Redis cache entries after score updates. The API cache key (`score:v3:{asn}`) is deleted when the engine recalculates a score, ensuring clients always see fresh data within one scoring cycle.

## Security

### Production Hardening

1. **Generate strong credentials** - `openssl rand -hex 32` for API key and passwords
2. **Enable HTTPS** - Use reverse proxy with TLS certificates (see [DEPLOYMENT.md](./DEPLOYMENT.md))
3. **Restrict network access** - Databases on internal Docker network only
4. **Audit dependencies** - `pip-audit` runs in CI on every push
5. **Pre-commit hooks** - Detect private keys and secrets before commit
6. **Non-root containers** - All services run as unprivileged `appuser`
7. **No hardcoded defaults** - Required credentials fail-fast if missing from environment

### CORS

Configurable via `CORS_ORIGINS` environment variable. Default: `*` (all origins). Set to specific domains in production.

### Rate Limiting

Atomic rate limiting via Redis Lua script. Configurable per-IP limit with RFC-compliant headers (`X-RateLimit-*`, `Retry-After`).

## Documentation

- **GitHub Pages**: https://fabriziosalmi.github.io/asn-api/
- **Swagger UI**: http://localhost:80/api/docs
- **ReDoc**: http://localhost:80/api/redoc
- **Local VitePress**: `cd docs && npm install && npm run dev`

### VitePress Sections

| Section | Topics |
|---------|--------|
| Guide → Quick Start | Docker launch, first requests |
| Guide → Configuration | All environment variables |
| Guide → Scoring Model | Weights, penalties, risk levels |
| Guide → Signals | Every signal field explained |
| Guide → Integrations | Palo Alto EDL, FortiGate, WebSocket consumers, SIEM |
| API → Endpoints | All 12 routes with request/response examples |
| API → Field Reference | Every field with penalty code table |
| API → Response Schema | TypeScript interfaces for all response types |
| Architecture → Overview | Two-tier cache, event bus, rate limiting, tracing |
| Architecture → Database | Full PostgreSQL + ClickHouse schema |

### Additional Files

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment checklist
- [KUBERNETES.md](./KUBERNETES.md) - Kubernetes deployment guide
- [RATELIMIT.md](./RATELIMIT.md) - Rate limiting strategy
- [CHANGELOG.md](./CHANGELOG.md) - Version history

## License

**Non-Commercial Use License**

This software is licensed under a custom non-commercial license. See the [LICENSE](LICENSE) file for complete terms and conditions. For commercial licensing inquiries, contact the repository owner through GitHub.

## Acknowledgments

- **RIPE NCC** - BGP data via RIPE RIS live stream
- **Spamhaus** - Threat intelligence feeds
- **PeeringDB** - Network metadata enrichment
- **ClickHouse** - High-performance time-series database
- **FastAPI** - Modern Python web framework

---

**Last Updated**: March 2026
**Version**: 7.3.0
**Platform Status**: Production Ready
