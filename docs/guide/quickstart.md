# Quick Start

## Prerequisites

- Docker and Docker Compose v2+
- 8GB RAM minimum
- Ports 80 (API via Nginx) and 3000 (Dashboard) available

## Installation

```bash
git clone https://github.com/fabriziosalmi/asn-api.git
cd asn-api

# Configure environment (required)
cp .env.example .env
# Edit .env - set POSTGRES_PASSWORD, API_SECRET_KEY, etc.

docker-compose up --build
```

The first startup takes 2-3 minutes while containers initialize and BGP data begins streaming.

## Verify Installation

```bash
docker-compose ps
```

Expected output shows 8+ healthy containers:

| Container | Service | Status |
|-----------|---------|--------|
| asn_api_gateway | API | Healthy |
| asn_worker_ingest | Ingestor | Healthy |
| asn_worker_scoring | Engine | Healthy |
| asn_db_meta | PostgreSQL | Healthy |
| asn_db_history | ClickHouse | Healthy |
| asn_broker | Redis | Healthy |
| asn_viz | Grafana | Running |
| asn_proxy | Nginx | Running |

## First API Call

Query the risk score for an ASN:

```bash
curl -H "X-API-Key: YOUR_API_KEY" http://localhost/api/v1/asn/15169
```

Response:

```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "risk_score": 95,
  "risk_level": "LOW",
  "rank_percentile": 98.5,
  "breakdown": {
    "hygiene": 100,
    "threat": 100,
    "stability": 95
  },
  "signals": { "..." },
  "details": []
}
```

## Check History with Pagination

```bash
curl -H "X-API-Key: YOUR_API_KEY" "http://localhost/api/v1/asn/15169/history?days=7&limit=10"
```

Returns a paginated response with `total`, `offset`, `limit`, and `data` fields.

## Access Dashboard

Open Grafana at [http://localhost/dashboard/](http://localhost/dashboard/)

- Username: `admin`
- Password: value of `GRAFANA_ADMIN_PASSWORD` from your `.env`

Navigate to the Mission Control dashboard for a real-time overview.

## Health Check

```bash
curl http://localhost/api/health
```

Returns dependency status for PostgreSQL, ClickHouse, and Redis without requiring authentication.
