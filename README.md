# ASN Risk Intelligence Platform

Production-ready risk scoring for Autonomous Systems using BGP telemetry and threat intelligence.

## Status

- **1,519 ASNs** scored and monitored
- **2.3M+ BGP events** processed
- **43K+ historical scores** tracked
- **183 threat events** detected

## Quick Start

```bash
docker-compose up --build
```

Wait 2-3 minutes for initial data ingestion, then access:

| Service | URL | Credentials |
|---------|-----|-------------|
| API Documentation | http://localhost:8080/docs | API Key: `dev-secret` |
| Grafana Dashboards | http://localhost:3000 | admin / admin |
| VitePress Docs | http://localhost:5173 | (from docs/ dir) |

## Architecture

```
RIPE RIS Stream --> Ingestor --> ClickHouse --> Engine --> PostgreSQL --> API
                                     |              |          |
                                 (events)      (scoring)   (state)
```

**Stack**: FastAPI, Celery, PostgreSQL, ClickHouse, Redis, Grafana

## API Examples

```bash
# Get ASN risk score
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169

# Score history (last 30 days)
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169/history

# Bulk analysis
curl -X POST -H "X-API-Key: dev-secret" -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 3356]}' http://localhost:8080/tools/bulk-risk-check
```

## Scoring Model

| Component | Weight | Signals |
|-----------|--------|---------|
| **Hygiene** (40%) | RPKI validation, route leaks, bogon advertisements, **Zombie ASNs** (0 prefixes) |
| **Threats** (35%) | Spamhaus listings, botnet C2, phishing, malware, **WHOIS Entropy** (SOTA) |
| **Stability** (25%) | BGP churn rate, announcement volatility, **Downstream Risk** (Cone of Silence) |

**Score Range**: 0-100 (higher is better)
- 90-100: LOW risk
- 75-89: MEDIUM risk
- 50-74: HIGH risk
- 0-49: CRITICAL risk

## Features Implemented

### Phase 1: Production Readiness ✅
- [x] Real threat feeds (Spamhaus DROP/EDROP, URLhaus, PhishTank)
- [x] API authentication with API keys
- [x] Historical score timeline
- [x] PeeringDB enrichment
- [x] Whitelist management
- [x] System health monitoring
- [x] Bulk analysis endpoint

### Phase 2: Intelligence Features ✅
- [x] BGP topology visualization
- [x] Route leak detection (valley-free violations)
- [x] Predictive BGP stability analysis

### Phase 3: Production Readiness ✅
- [x] Automated Test Suite (`pytest`)
- [x] GitLab CI/CD Pipeline
- [x] Rate Limiting Strategy (`RATELIMIT.md`)

### Phase 4: Advanced Intelligence (SOTA) ✅
- [x] **Downstream Risk Analysis** ("Cone of Silence")
- [x] **Zombie ASN Detection** (Parked Networks)
- [x] **WHOIS Entropy Scoring** (Anti-shell company)
- [x] **Peer Pressure Dashboard**

## Dashboards

Access Grafana at http://localhost:3000 (admin/admin):

- **Mission Control**: Real-time BGP activity, threat detection, risk distribution
- **System Health**: Ingestion rates, scoring throughput, database metrics
- **Network Topology**: AS connections, top active ASNs
- **API Performance**: Request rate, latency percentiles, cache hit rate, error tracking

### API Performance Dashboard Features
- **Request Rate**: Real-time req/s monitoring
- **P95 Latency**: 95th percentile response time tracking
- **Error Count**: 4xx/5xx error monitoring (5min window)
- **Cache Hit Rate**: Redis cache effectiveness percentage
- **Response Time Percentiles**: P50, P95, P99 over time
- **Status Code Distribution**: Visual breakdown of HTTP responses
- **Top Endpoints**: Most requested endpoints with avg latency
- **Cache Hit vs Miss**: Stacked area chart of cache performance

## Documentation

Comprehensive documentation available in [docs/](./docs/):

```bash
cd docs && npm install && npm run dev
```

Then visit http://localhost:5173 for:
- API reference with examples
- Architecture deep-dive
- Field reference
- Integration guides

## Database Schema

### PostgreSQL (State)
- `asn_registry`: Current scores and metadata (1,519 ASNs)
- `asn_signals`: 15 detailed signal metrics per ASN
- `asn_whitelist`: User-managed ignore list

### ClickHouse (Time-Series)
- `bgp_events`: Raw BGP updates (2.3M+ events)
- `threat_events`: Threat intelligence hits
- `asn_score_history`: Score evolution (43K+ records)
- `daily_metrics`: Pre-aggregated statistics

## Configuration

Key environment variables in `docker-compose.yml`:

```yaml
API_SECRET_KEY: dev-secret          # Change in production
CLICKHOUSE_HOST: db-timeseries
POSTGRES_HOST: db-metadata
```

For production deployment, override with `.env` file or docker-compose.override.yml

## Performance

- **Ingestion Rate**: ~100-200 BGP updates/second
- **Scoring Latency**: <500ms per ASN
- **API Response**: <100ms (cached in PostgreSQL)
- **Data Retention**: 
  - BGP events: 30 days
  - Score history: 365 days
  - Aggregated metrics: Indefinite

## Development

```bash
# View logs
docker-compose logs -f asn-ingestor
docker-compose logs -f asn-engine

# Access databases
docker-compose exec db-metadata psql -U asn_admin -d asn_registry
docker-compose exec db-timeseries clickhouse-client

# Restart specific service
docker-compose restart asn-api

# Run Tests
pytest
```

## Project Structure

```
asn-api/
├── services/
│   ├── api/              # FastAPI REST API
│   ├── engine/           # Celery scoring worker
│   ├── ingestor/         # BGP stream consumer
│   ├── dashboard/        # Grafana dashboards
│   ├── db-metadata/      # PostgreSQL init
│   └── db-timeseries/    # ClickHouse init
├── docs/                 # VitePress documentation
├── docker-compose.yml    # Orchestration
└── README.md            # This file
```

## License

Proprietary - All rights reserved

---

**Last Updated**: January 2026
