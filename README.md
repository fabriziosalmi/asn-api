# ASN Risk Intelligence Platform

> **Real-time trust scoring for Internet Autonomous Systems using BGP telemetry, threat intelligence, and network topology analysis**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-required-blue.svg)](https://www.docker.com/)

## Overview

The ASN Risk Intelligence Platform is a production-grade system for assessing the security and stability risk of Autonomous Systems (ASNs) on the Internet. By combining real-time BGP routing data, threat intelligence feeds, and sophisticated network topology analysis, it generates comprehensive risk scores (0-100) that help organizations make informed decisions about network trust.

**Key Capabilities:**
- 🔍 **Real-time BGP Analysis** - Process hundreds of BGP updates per second from RIPE RIS live streams
- 🛡️ **Multi-source Threat Intelligence** - Integrate Spamhaus, URLhaus, PhishTank, and other feeds
- 📊 **Advanced Scoring Engine** - 30+ signals across hygiene, threats, stability, and forensics
- 🔄 **Historical Tracking** - 365-day score history with trend analysis
- 🌐 **Topology Analysis** - Upstream/downstream risk assessment and peer pressure analysis
- 📈 **Production-Ready** - Enterprise-grade REST API with caching, rate limiting, and monitoring

### Current Statistics

- **1,519 ASNs** actively scored and monitored
- **2.3M+ BGP events** processed in time-series database
- **43K+ historical scores** tracked for trend analysis
- **183 threat events** detected and correlated

## Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose 1.29+
- 8GB RAM minimum (16GB recommended)
- 50GB disk space for time-series data

### Launch the Platform

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api

# Start all services
docker-compose up --build
```

Wait 2-3 minutes for initial data ingestion and database initialization. Then access:

| Service | URL | Credentials |
|---------|-----|-------------|
| **API Documentation** | http://localhost:8080/docs | API Key: `dev-secret` |
| **Grafana Dashboards** | http://localhost:3000 | admin / admin |
| **Online Documentation** | https://fabriziosalmi.github.io/asn-api/ | Public access |
| **Local Docs (Dev)** | http://localhost:5173 | Run `cd docs && npm install && npm run dev` |

## Architecture

### System Design

```
┌─────────────────┐
│  RIPE RIS Live  │ BGP Stream (WebSocket)
│  Threat Feeds   │ Spamhaus, URLhaus, PhishTank
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Ingestor      │ BGP Parser & Threat Aggregator
│   (Python)      │ Normalizes and stores raw events
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ClickHouse     │ Time-Series Database
│  (Events Log)   │ 2.3M+ BGP events, threat history
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Scoring       │ Risk Analysis Engine
│   Engine        │ 30+ signals, ML-based stability
│   (Celery)      │ Downstream/upstream analysis
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   PostgreSQL    │ Current State Database
│   (Registry)    │ Scores, metadata, signals
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌─────────────┐
│   FastAPI       │◄─────┤   Redis     │
│   REST API      │      │   (Cache)   │
└─────────────────┘      └─────────────┘
         │
         ▼
┌─────────────────┐
│    Grafana      │ Real-time Dashboards
│    Dashboards   │ Mission Control, API Performance
└─────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **API Gateway** | FastAPI | High-performance REST API with OpenAPI docs |
| **Task Queue** | Celery + Redis | Asynchronous scoring and batch processing |
| **State Database** | PostgreSQL 15 | Current scores, metadata, and signals |
| **Time-Series DB** | ClickHouse | High-volume BGP events and historical data |
| **Caching Layer** | Redis 7 | API response caching and rate limiting |
| **Visualization** | Grafana | Real-time dashboards and monitoring |
| **Documentation** | VitePress | Interactive API documentation |

## Features

### Core Capabilities

#### 🎯 Risk Scoring
- **Comprehensive Analysis** - 30+ signals across 4 categories (Hygiene, Threats, Stability, Forensics)
- **Real-time Scoring** - Sub-500ms scoring latency per ASN
- **Percentile Ranking** - Global comparative analysis across 1,519+ monitored ASNs
- **Historical Tracking** - 365-day score history with trend visualization

#### 🔍 Intelligence Sources
- **BGP Telemetry** - Live RIPE RIS stream processing (100-200 updates/sec)
- **RPKI Validation** - ROA validation for route origin authentication
- **Threat Feeds** - Spamhaus DROP/EDROP, URLhaus, PhishTank integration
- **Network Metadata** - PeeringDB enrichment, WHOIS analysis

#### 🧠 Advanced Analytics
- **Downstream Risk** - "Cone of Silence" algorithm for customer risk assessment
- **Upstream Analysis** - "Peer Pressure" evaluation of transit providers
- **Zombie Detection** - Identification of inactive/parked ASNs
- **BGP Forensics** - DDoS sponge detection, AS path prepending analysis
- **Predictive Stability** - ML-based instability prediction using statistical analysis

#### 🔐 Security Features
- **API Key Authentication** - Secure access control with configurable keys
- **Rate Limiting** - RFC-compliant rate limit headers (`X-RateLimit-*`)
- **HTTPS Ready** - Production deployment with TLS/SSL support
- **Whitelist Management** - User-managed ASN exclusion lists

#### 📊 Monitoring & Observability
- **Grafana Dashboards** - 4 pre-built dashboards for monitoring
  - Mission Control: Real-time BGP activity and threat detection
  - System Health: Ingestion rates and database metrics
  - Network Topology: AS connections and top active ASNs
  - API Performance: Request rate, latency, cache hit rate
- **Request Logging** - ClickHouse-based API analytics
- **Cache Metrics** - Redis cache effectiveness tracking

## API Reference

### Authentication

All API endpoints require an API key passed via the `X-API-Key` header:

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169
```

### Core Endpoints

#### Get ASN Risk Score

Retrieve detailed risk assessment for a specific ASN:

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169
```

**Response:**
```json
{
  "asn": 15169,
  "name": "Google LLC",
  "country_code": "US",
  "registry": "ARIN",
  "risk_score": 95,
  "risk_level": "LOW",
  "rank_percentile": 98.5,
  "downstream_score": 92,
  "last_updated": "2026-01-15T05:30:00",
  "breakdown": {
    "hygiene": 100,
    "threat": 100,
    "stability": 95
  },
  "signals": {
    "hygiene": {
      "rpki_invalid_percent": 0.0,
      "has_route_leaks": false,
      "has_bogon_ads": false
    },
    "threats": {
      "spamhaus_listed": false,
      "botnet_c2_count": 0
    }
  },
  "details": []
}
```

#### Get Score History

Retrieve historical score trend for charting:

```bash
curl -H "X-API-Key: dev-secret" "http://localhost:8080/asn/15169/history?days=30"
```

#### Upstream Risk Analysis

Evaluate the risk of an ASN's upstream providers:

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169/upstreams
```

#### Bulk Risk Check

Analyze multiple ASNs in a single request (useful for supply chain analysis):

```bash
curl -X POST -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 3356]}' \
  http://localhost:8080/tools/bulk-risk-check
```

#### Whitelist Management

Add an ASN to the whitelist (score set to 100):

```bash
curl -X POST -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asn": 15169, "reason": "Corporate network"}' \
  http://localhost:8080/whitelist
```

### API Documentation

Interactive API documentation with examples is available at:
- **Swagger UI**: http://localhost:8080/docs
- **ReDoc**: http://localhost:8080/redoc

## Scoring Methodology

The platform uses a sophisticated multi-factor scoring model that analyzes 30+ signals across four main categories. The final score ranges from 0 (critical risk) to 100 (trusted).

### Scoring Categories

| Category | Weight | Description |
|----------|--------|-------------|
| **Routing Hygiene** | 40% | BGP routing health and RPKI compliance |
| **Threat Intelligence** | 35% | Malicious activity and threat feed correlations |
| **Network Stability** | 25% | BGP churn, predictive stability, upstream quality |
| **Forensic Signals** | Bonus/Penalty | Advanced BGP analysis and topology risk |

### Signal Breakdown

#### 🔧 Routing Hygiene (40%)
- **RPKI Validation** - Invalid ROA status detection (-20 points)
- **Route Leaks** - Valley-free violation detection (-20 points)
- **Bogon Advertisement** - Reserved/private prefix announcements (-10 points)
- **Prefix Granularity** - De-aggregation and fragmentation analysis (-10 points)
- **Zombie ASNs** - Active registration with zero routes (-15 points)

#### 🛡️ Threat Intelligence (35%)
- **Spamhaus Listings** - DROP/EDROP list membership (-30 points)
- **Spam Emission** - High spam bot activity rate (-15 points)
- **Botnet C2 Hosting** - Command & control server presence (-20 per C2, cap at -40)
- **Phishing Infrastructure** - Hosting phishing domains (-15 points)
- **Malware Distribution** - Active malware hosting (-20 points)
- **Threat Recidivism** - Persistent malicious activity over 30 days (-10 points)
- **WHOIS Entropy** - Algorithmically generated organization names (-10 points)

#### ⚖️ Network Stability (25%)
- **Upstream Churn** - Frequent provider changes (>2 in 90 days: -25 points)
- **Route Flapping** - High withdrawal rates (>100/week: -5 points)
- **Predictive Instability** - ML-based stability forecast (-15 points)
- **PeeringDB Profile** - Presence in PeeringDB (+5 bonus)
- **Tier-1 Connectivity** - Multiple Tier-1 upstreams (+5 bonus)
- **Bad Neighborhood** - Low-scoring upstreams (-5 to -15 points)

#### 🔬 Forensic Signals (Bonus/Penalty)
- **Downstream Risk** - "Cone of Silence" customer analysis (-20 points if avg <70)
- **DDoS Sponge** - Blackhole community tagging frequency (-15 points)
- **Traffic Engineering Chaos** - Excessive AS path prepending (-10 points)
- **Space Squatting** - RIR allocation validation

### Risk Levels

| Score Range | Risk Level | Interpretation |
|-------------|-----------|----------------|
| **90-100** | LOW | Highly trusted, minimal security concerns |
| **75-89** | MEDIUM | Generally reliable with minor issues |
| **50-74** | HIGH | Significant concerns, use with caution |
| **0-49** | CRITICAL | High-risk network, avoid if possible |

### Scoring Algorithm

The scoring engine follows this workflow:

1. **Signal Collection** - Fetch static signals from PostgreSQL and temporal metrics from ClickHouse
2. **Whitelist Check** - Bypass scoring for whitelisted ASNs (score = 100)
3. **Penalty Application** - Apply point deductions based on detected issues
4. **Bonus Application** - Add points for positive indicators
5. **Topology Analysis** - Evaluate upstream/downstream risk
6. **Score Normalization** - Clamp final score to 0-100 range
7. **Persistence** - Store in PostgreSQL and append to ClickHouse history

## Dashboards & Visualization

Access Grafana at http://localhost:3000 (default: admin/admin) for real-time monitoring:

### Available Dashboards

#### 1. Mission Control
**Purpose**: High-level operational overview
- Real-time BGP activity monitoring
- Threat detection alerts
- Risk distribution across monitored ASNs
- Top offenders and most improved ASNs

#### 2. System Health
**Purpose**: Platform performance and reliability
- Data ingestion rates (BGP updates/sec)
- Scoring throughput and latency
- Database query performance
- Memory and CPU utilization

#### 3. Network Topology
**Purpose**: Internet topology analysis
- AS relationship graph
- Top active ASNs by announcement volume
- Upstream/downstream connectivity patterns
- Geographic distribution

#### 4. API Performance
**Purpose**: API metrics and usage patterns
- **Request Rate** - Real-time req/s monitoring
- **Latency Percentiles** - P50, P95, P99 response times
- **Cache Effectiveness** - Hit rate percentage and hit/miss breakdown
- **Error Tracking** - 4xx/5xx error counts (5-minute window)
- **Endpoint Analysis** - Most requested endpoints with average latency
- **Status Code Distribution** - Visual breakdown of HTTP responses

### Dashboard Data Sources

- **PostgreSQL** - Current scores and metadata
- **ClickHouse** - Historical data, BGP events, API logs
- **Redis** - Cache metrics (via API instrumentation)

### Custom Dashboards

To create custom dashboards, use the pre-provisioned datasources:
- `asn-postgres` - PostgreSQL connection
- `asn-clickhouse` - ClickHouse connection

Grafana automatically installs the ClickHouse plugin on startup.

## Documentation

Comprehensive documentation is available:

### Online Documentation
- **GitHub Pages**: https://fabriziosalmi.github.io/asn-api/

Automatically deployed from the `main` branch using GitHub Actions.

### Local Development
```bash
cd docs && npm install && npm run dev
```

Then visit http://localhost:5173 for:
- API reference with examples
- Architecture deep-dive
- Field reference
- Integration guides

## Data Architecture

### PostgreSQL (State Database)

**Purpose**: Current state, identity, and computed scores

#### Tables

**`asn_registry`** - Primary registry of monitored ASNs
- Current scores (total, hygiene, threat, stability)
- Metadata (name, country, registry)
- Downstream and WHOIS entropy scores
- Last update timestamp

**`asn_signals`** - Detailed signal metrics (30+ fields)
- RPKI validation percentages
- Threat intelligence flags
- Identity indicators (PeeringDB, WHOIS)
- Forensic signals (DDoS, prepending)

**`asn_whitelist`** - User-managed exclusion list
- Whitelisted ASNs with justification
- Auto-score of 100 for trusted networks

### ClickHouse (Time-Series Database)

**Purpose**: High-volume event storage and historical analysis

#### Tables

**`bgp_events`** - Raw BGP routing updates (2.3M+ records)
- Announcements and withdrawals
- AS paths and communities
- Upstream relationships
- Partitioned by month for efficient queries

**`threat_events`** - Threat intelligence correlations
- Multi-source threat data (Spamhaus, URLhaus, PhishTank)
- Categorized by type (spam, C2, malware, phishing)
- IP-level attribution to ASNs

**`asn_score_history`** - Historical score tracking (43K+ records)
- Daily score snapshots for 365-day retention
- Powers trend analysis and charting

**`daily_metrics`** - Pre-aggregated statistics
- Daily BGP event counts
- Announce/withdraw ratios
- Materialized views for real-time aggregation

**`api_requests`** - API usage analytics
- Request timestamps and endpoints
- Response times and status codes
- Cache hit/miss tracking
- Client IP logging

### Data Retention Policy

| Data Type | Retention Period | Storage |
|-----------|-----------------|---------|
| BGP Events | 30 days | ClickHouse (partitioned) |
| Threat Events | 90 days | ClickHouse |
| Score History | 365 days | ClickHouse |
| Daily Metrics | Indefinite | ClickHouse (aggregated) |
| Current Scores | Persistent | PostgreSQL |
| API Logs | 90 days | ClickHouse |

## Configuration

### Environment Variables

Key configuration options in `docker-compose.yml`:

#### Security
```yaml
API_SECRET_KEY: dev-secret          # Change in production! Use openssl rand -hex 32
POSTGRES_PASSWORD: secure_password  # Database authentication
CLICKHOUSE_PASSWORD: ""             # ClickHouse authentication
```

#### Database Connectivity
```yaml
DB_HOST: db-metadata                # PostgreSQL host
CLICKHOUSE_HOST: db-timeseries      # ClickHouse host
REDIS_HOST: broker-cache            # Redis host
```

#### Performance Tuning
```yaml
CACHE_TTL: 60                       # API cache duration (seconds)
API_RATE_LIMIT: 100                 # Requests per minute per IP
```

#### Data Ingestion
```yaml
RIPE_RIS_ENABLED: true              # Enable live BGP stream
THREAT_FEED_INTERVAL: 3600          # Threat intel refresh (seconds)
```

### Production Configuration

For production deployments, use environment-specific configuration:

**Method 1: .env file**
```bash
# Create .env file in project root
echo "API_SECRET_KEY=$(openssl rand -hex 32)" > .env
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
```

**Method 2: docker-compose.override.yml**
```yaml
version: '3.8'
services:
  asn-api:
    environment:
      - API_SECRET_KEY=${API_SECRET_KEY}
      - CACHE_TTL=300  # 5 minutes for production
```

See [DEPLOYMENT.md](./DEPLOYMENT.md) for comprehensive production deployment guidance.

## Performance Characteristics

### Throughput Metrics

| Metric | Specification | Notes |
|--------|--------------|-------|
| **BGP Ingestion Rate** | 100-200 updates/sec | From RIPE RIS live stream |
| **Scoring Latency** | <500ms per ASN | Including all 30+ signals |
| **API Response Time** | <100ms (cached) | PostgreSQL + Redis caching |
| **API Response Time** | <250ms (uncached) | Full database query |
| **Bulk Analysis** | <5s for 100 ASNs | Parallel query optimization |

### Resource Requirements

#### Minimum (Development)
- **CPU**: 4 cores
- **RAM**: 8GB
- **Disk**: 20GB SSD
- **Network**: 10 Mbps

#### Recommended (Production)
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Disk**: 100GB+ SSD (NVMe preferred)
- **Network**: 100 Mbps+

### Scalability

The platform is designed for horizontal scaling:

**API Layer**
```bash
docker-compose up -d --scale asn-api=3
```

**Scoring Workers**
```bash
docker-compose up -d --scale asn-engine=5
```

For Kubernetes deployment, see [KUBERNETES.md](./KUBERNETES.md).

## Development

### Local Development Setup

```bash
# Clone repository
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api

# Start services
docker-compose up --build

# View logs
docker-compose logs -f asn-ingestor
docker-compose logs -f asn-engine
docker-compose logs -f asn-api
```

### Service Management

```bash
# Restart specific service
docker-compose restart asn-api

# Rebuild and restart
docker-compose up -d --build asn-engine

# Stop all services
docker-compose down

# Remove volumes (clean slate)
docker-compose down -v
```

### Database Access

#### PostgreSQL
```bash
# Connect to PostgreSQL
docker-compose exec db-metadata psql -U asn_admin -d asn_registry

# Example queries
SELECT asn, name, total_score, risk_level FROM asn_registry ORDER BY total_score DESC LIMIT 10;
SELECT * FROM asn_signals WHERE asn = 15169;
```

#### ClickHouse
```bash
# Connect to ClickHouse
docker-compose exec db-timeseries clickhouse-client

# Example queries
SELECT count() FROM bgp_events WHERE timestamp > now() - INTERVAL 1 HOUR;
SELECT asn, count() as events FROM bgp_events GROUP BY asn ORDER BY events DESC LIMIT 10;
```

#### Redis
```bash
# Connect to Redis
docker-compose exec broker-cache redis-cli

# Check cached scores
KEYS score:v2:*
GET score:v2:15169
```

### Testing

#### Run Test Suite
```bash
# Install test dependencies
pip install -r services/api/requirements.txt
pip install pytest pytest-asyncio httpx

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_api.py -v

# Run with coverage
pytest --cov=services tests/
```

#### Manual API Testing
```bash
# Health check
curl http://localhost:8080/health

# Get ASN score
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169

# Check API documentation
open http://localhost:8080/docs
```

### Code Quality

#### Linting
```bash
# Install linters
pip install ruff black

# Run ruff
ruff check .

# Run black
black --check .

# Auto-fix with black
black .
```

#### CI/CD Pipeline

The project includes GitLab CI configuration (`.gitlab-ci.yml`) with three stages:
1. **Lint** - Code style and quality checks
2. **Test** - Unit and integration tests
3. **Build** - Docker image building and registry push

### Project Structure

```
asn-api/
├── services/
│   ├── api/              # FastAPI REST API
│   │   ├── main.py       # API routes and endpoints
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── engine/           # Celery scoring worker
│   │   ├── scorer.py     # Risk scoring algorithm
│   │   ├── tasks.py      # Celery task definitions
│   │   └── Dockerfile
│   ├── ingestor/         # BGP stream consumer
│   │   ├── start_ingestion_stream.py
│   │   └── Dockerfile
│   ├── dashboard/        # Grafana dashboards
│   │   ├── provisioning/
│   │   └── dashboards/
│   ├── db-metadata/      # PostgreSQL initialization
│   │   └── init.sql
│   └── db-timeseries/    # ClickHouse initialization
│       └── init.sql
├── docs/                 # VitePress documentation
│   ├── api/             # API reference
│   ├── architecture/    # System design docs
│   ├── guide/           # User guides
│   └── .vitepress/      # VitePress config
├── tests/               # Test suite
│   ├── test_api.py
│   └── test_scorer.py
├── scripts/             # Utility scripts
├── docker-compose.yml   # Service orchestration
├── .gitlab-ci.yml       # CI/CD pipeline
├── DEPLOYMENT.md        # Production deployment guide
├── KUBERNETES.md        # Kubernetes deployment guide
└── README.md           # This file
```

## Documentation

Comprehensive documentation is available in multiple formats:

### Online Documentation (GitHub Pages)

**Live Documentation**: https://fabriziosalmi.github.io/asn-api/

The documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch. It includes:
- **API Reference** - Detailed endpoint documentation with examples
- **Architecture** - Deep-dive into system design and data flow
- **Field Reference** - Complete signal and metric definitions
- **Configuration Guide** - Environment setup and tuning
- **Integration Guides** - How to integrate with external systems

### Local Documentation Development (VitePress)

```bash
cd docs
npm install
npm run dev
```

Then visit http://localhost:5173 for local development and testing of documentation changes.

### API Documentation (OpenAPI/Swagger)

- **Swagger UI**: http://localhost:8080/docs - Interactive API testing
- **ReDoc**: http://localhost:8080/redoc - Clean API reference

### Additional Documentation Files

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment checklist
- [KUBERNETES.md](./KUBERNETES.md) - Kubernetes deployment guide
- [RATELIMIT.md](./RATELIMIT.md) - Rate limiting strategy and implementation
- [CHANGELOG.md](./CHANGELOG.md) - Version history and feature releases

## Use Cases

### 1. Supply Chain Risk Assessment
Evaluate the security posture of third-party networks and service providers:
```bash
curl -X POST -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asns": [13335, 15169, 8075]}' \
  http://localhost:8080/tools/bulk-risk-check
```

### 2. Peering Decision Support
Assess potential peering partners before establishing BGP sessions:
```bash
# Get detailed risk profile
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/3356

# Check upstream dependencies
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/3356/upstreams
```

### 3. Network Monitoring
Track your own ASN's risk score over time:
```bash
# Current score
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/<your-asn>

# Historical trend
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/<your-asn>/history?days=90
```

### 4. Security Operations
Identify high-risk ASNs for enhanced monitoring or blocking:
```bash
# Query PostgreSQL for critical ASNs
docker-compose exec db-metadata psql -U asn_admin -d asn_registry \
  -c "SELECT asn, name, total_score FROM asn_registry WHERE risk_level = 'CRITICAL' ORDER BY total_score;"
```

### 5. Research & Analysis
Export data for academic research or security analysis:
```bash
# Export score history from ClickHouse
docker-compose exec db-timeseries clickhouse-client --query \
  "SELECT * FROM asn_score_history WHERE asn = 15169 FORMAT CSV" > asn_15169_history.csv
```

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service status
docker-compose ps

# View logs for failed service
docker-compose logs <service-name>

# Restart with fresh state
docker-compose down -v
docker-compose up --build
```

#### No BGP Data Ingesting
```bash
# Check ingestor logs
docker-compose logs -f asn-ingestor

# Verify ClickHouse connectivity
docker-compose exec asn-ingestor ping db-timeseries

# Check RIPE RIS stream status
curl https://ris-live.ripe.net/v1/stream/
```

#### High Memory Usage
```bash
# Check container resource usage
docker stats

# Adjust ClickHouse memory limit in docker-compose.yml
services:
  db-timeseries:
    environment:
      - CLICKHOUSE_MAX_MEMORY_USAGE=4000000000
```

#### Slow API Responses
```bash
# Check PostgreSQL query performance
docker-compose exec db-metadata psql -U asn_admin -d asn_registry \
  -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"

# Verify Redis cache is working
docker-compose exec broker-cache redis-cli INFO stats

# Check API logs for cache hit rate
docker-compose logs asn-api | grep "cache_hit"
```

#### Database Connection Errors
```bash
# Ensure databases are healthy
docker-compose ps

# Wait for health checks
docker-compose exec db-metadata pg_isready
docker-compose exec db-timeseries wget -q -O- localhost:8123/ping

# Restart dependent services
docker-compose restart asn-api asn-engine
```

### Getting Help

1. Check the [CHANGELOG.md](./CHANGELOG.md) for known issues
2. Review logs: `docker-compose logs <service>`
3. Verify configuration in `docker-compose.yml`
4. Consult documentation in [docs/](./docs/)

## Security Considerations

### Production Hardening

1. **Change Default Credentials**
   ```bash
   # Generate strong API key
   openssl rand -hex 32
   
   # Generate database passwords
   openssl rand -base64 32
   ```

2. **Enable HTTPS**
   - Use reverse proxy (Nginx/Traefik) with TLS certificates
   - See [DEPLOYMENT.md](./DEPLOYMENT.md) for Nginx configuration

3. **Restrict Network Access**
   - Use firewall rules to limit exposed ports
   - Deploy databases in private networks
   - Use VPN for administrative access

4. **Regular Updates**
   ```bash
   # Update Docker images
   docker-compose pull
   docker-compose up -d
   ```

5. **Backup Strategy**
   - Automated daily backups of PostgreSQL and ClickHouse
   - See [DEPLOYMENT.md](./DEPLOYMENT.md) for backup scripts

6. **Monitoring**
   - Set up alerts for API errors, high memory usage, and failed services
   - Use Grafana dashboards for proactive monitoring

## Roadmap

### Planned Features

- [ ] **Machine Learning Integration** - Anomaly detection for BGP events
- [ ] **Real-time Alerts** - Webhook notifications for score changes
- [ ] **Multi-tenant Support** - Organization-level access control
- [ ] **Custom Scoring Profiles** - User-defined weights and thresholds
- [ ] **Historical Comparison** - Score diff view for time periods
- [ ] **Geolocation Analysis** - Country/region risk aggregation
- [ ] **API v2** - GraphQL endpoint for flexible queries
- [ ] **Mobile Dashboard** - Responsive Grafana views

### Recently Completed

- [x] **Phase 5: BGP Forensics** - DDoS sponge and prepending detection
- [x] **Phase 4: Advanced Intelligence** - Downstream risk, zombie detection, WHOIS entropy
- [x] **Phase 3: Production Readiness** - Automated tests, CI/CD, rate limiting
- [x] **Phase 2: Intelligence Features** - Topology visualization, route leaks, predictive stability
- [x] **Phase 1: MVP** - Core scoring, API authentication, historical tracking

See [CHANGELOG.md](./CHANGELOG.md) for detailed version history.

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Follow existing code style** - Run `black` and `ruff` before committing
3. **Write tests** for new features
4. **Update documentation** as needed
5. **Submit a pull request** with a clear description

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
docker-compose up --build
pytest tests/ -v

# Format code
black .
ruff check --fix .

# Commit and push
git add .
git commit -m "Add amazing feature"
git push origin feature/amazing-feature
```

## License

**Proprietary License** - All rights reserved

This software is proprietary and confidential. Unauthorized copying, modification, distribution, or use of this software is strictly prohibited.

For licensing inquiries, please contact the repository owner.

---

## Acknowledgments

- **RIPE NCC** - BGP data via RIPE RIS live stream
- **Spamhaus** - Threat intelligence feeds
- **PeeringDB** - Network metadata enrichment
- **ClickHouse** - High-performance time-series database
- **FastAPI** - Modern Python web framework

---

**Last Updated**: January 2026  
**Version**: 1.0.0  
**Platform Status**: Production Ready
