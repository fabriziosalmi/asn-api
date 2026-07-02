# Data Flow

## BGP Event Processing

### 1. Ingestion

```
RIPE RIS WebSocket
       │
       ▼
┌──────────────┐
│   Parse      │  Extract: timestamp, prefix, origin_asn, as_path, type
│   Message    │
└──────────────┘
       │
       ▼
┌──────────────┐
│   Validate   │  Check message structure, filter noise
└──────────────┘
       │
       ▼
┌──────────────┐
│   Batch      │  Accumulate 1000 events or 5 second timeout
└──────────────┘
       │
       ▼
┌──────────────┐
│   Write      │  Bulk insert to ClickHouse bgp_events
└──────────────┘
```

### 2. Aggregation

ClickHouse Materialized Views automatically compute:

- `bgp_daily_mv`: Daily announcement/withdrawal counts per ASN
- `threat_daily_mv`: Daily threat event counts per ASN

### 3. Scoring

Triggered by Celery beat scheduler or on-demand:

```
┌──────────────┐
│  Query       │  Read aggregates from ClickHouse
│  ClickHouse  │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Calculate   │  Apply scoring formula
│  Scores      │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Update      │  Write to asn_registry, asn_signals
│  PostgreSQL  │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Record      │  Append to asn_score_history
│  History     │
└──────────────┘
```

## Threat Feed Processing

### Sources

| Feed | Type | Update Interval |
|------|------|-----------------|
| Spamhaus DROP | IP blocklist | 1 hour |
| Spamhaus EDROP | ASN blocklist | 1 hour |
| URLhaus | Malware URLs | 1 hour |
| PhishTank | Phishing URLs | 1 hour |

### Processing Pipeline

```
┌──────────────┐
│  Fetch       │  HTTP GET from feed URLs
│  Feed        │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Parse       │  Extract IPs, domains, ASNs
└──────────────┘
       │
       ▼
┌──────────────┐
│  Resolve     │  Map IPs/domains to origin ASN
└──────────────┘
       │
       ▼
┌──────────────┐
│  Write       │  Insert to threat_events
└──────────────┘
```

## Query Flow

### Score Query

```
Client Request: GET /v1/asn/15169
       │
       ▼
┌──────────────┐
│  Validate    │  Check API key, rate limit
│  Request     │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Query       │  SELECT from asn_registry JOIN asn_signals
│  PostgreSQL  │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Generate    │  Build human-readable explanations
│  Details     │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Return      │  JSON response
│  Response    │
└──────────────┘
```

### History Query

```
Client Request: GET /v1/asn/15169/history
       │
       ▼
┌──────────────┐
│  Query       │  SELECT from asn_score_history
│  ClickHouse  │
└──────────────┘
       │
       ▼
┌──────────────┐
│  Return      │  JSON array of timestamp/score pairs
│  Response    │
└──────────────┘
```

## Data Retention

| Table | Retention | Purpose |
|-------|-----------|---------|
| bgp_events | 90 days | Raw event analysis |
| threat_events | 180 days | Threat investigation |
| api_requests | 30 days | Request/audit logging |
| asn_score_history | Indefinite (no TTL) | Trend analysis |
| daily_metrics | Indefinite | Aggregated historical metrics |
