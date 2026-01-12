# Quick Start

## Prerequisites

- Docker and Docker Compose
- 4GB RAM minimum
- Ports 8080 (API) and 3000 (Dashboard) available

## Installation

Clone the repository and start the stack:

```bash
git clone https://github.com/your-org/asn-risk-platform.git
cd asn-risk-platform
docker-compose up --build
```

The first startup takes 2-3 minutes while containers initialize and BGP data begins streaming.

## Verify Installation

Check that all services are running:

```bash
docker-compose ps
```

Expected output shows 7 healthy containers:

| Container | Service | Status |
|-----------|---------|--------|
| asn_api_gateway | API | Running |
| asn_worker_ingest | Ingestor | Running |
| asn_worker_scoring | Engine | Running |
| asn_db_meta | PostgreSQL | Healthy |
| asn_db_history | ClickHouse | Healthy |
| asn_broker | Redis | Healthy |
| asn_viz | Grafana | Running |

## First API Call

Query the risk score for an ASN:

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169
```

Response (truncated for brevity):

```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "country_code": "XX",
  "registry": null,
  "risk_score": 55,
  "risk_level": "HIGH",
  "breakdown": {
    "hygiene": 100,
    "threat": 90,
    "stability": 70
  },
  "signals": {
    "hygiene": { ... },
    "threats": { ... },
    "metadata": { ... }
  },
  "details": [
    "METADATA: No PeeringDB profile (reduces transparency)"
  ]
}
```

## Access Dashboard

Open Grafana at [http://localhost:3000](http://localhost:3000)

- Username: `admin`
- Password: `admin`

Navigate to the Mission Control dashboard for a real-time overview.
