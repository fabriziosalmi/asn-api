# Architecture Overview

The ASN Risk Platform follows a microservices architecture optimized for high-throughput data ingestion and low-latency queries.

## System Diagram

```
                    ┌─────────────────┐
                    │   RIPE RIS      │
                    │   BGP Stream    │
                    └────────┬────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                        INGESTOR                              │
│  • WebSocket client for BGP stream                          │
│  • Threat feed fetcher (Spamhaus, URLhaus)                  │
│  • Batch writer for ClickHouse                              │
└─────────────────────────────────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌─────────────────────────┐    ┌─────────────────────────┐
│       CLICKHOUSE        │    │         REDIS           │
│  • bgp_events           │    │  • Task queue           │
│  • threat_events        │    │  • Result cache         │
│  • asn_score_history    │    │                         │
│  • Materialized views   │    │                         │
└─────────────────────────┘    └─────────────────────────┘
              │                              │
              └──────────────┬───────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                         ENGINE                               │
│  • Celery worker                                            │
│  • Score calculation                                        │
│  • Signal aggregation                                       │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
              ┌─────────────────────────┐
              │       POSTGRESQL        │
              │  • asn_registry         │
              │  • asn_signals          │
              │  • asn_whitelist        │
              └─────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                           API                                │
│  • FastAPI                                                  │
│  • Read-only queries                                        │
│  • Authentication                                           │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     CLIENTS     │
                    └─────────────────┘
```

## Component Responsibilities

### Ingestor

Handles all external data ingestion:

- Maintains persistent WebSocket connection to RIPE RIS
- Parses BGP UPDATE messages
- Fetches threat intelligence feeds on schedule
- Batches writes to ClickHouse for throughput optimization

### Engine

Performs scoring calculations:

- Celery worker processing task queue
- Queries ClickHouse for time-series aggregations
- Calculates additive risk scores (penalties/bonuses from 100)
- Updates PostgreSQL with current state

### API

Serves client requests:

- FastAPI with async support
- Reads from PostgreSQL for current scores
- Reads from ClickHouse for historical data
- Implements authentication and rate limiting

## Design Principles

### Separation of Write and Read Paths

The write path (Ingestor to ClickHouse) is optimized for throughput. The read path (API from PostgreSQL) is optimized for latency.

### Event Sourcing

All BGP events are stored immutably in ClickHouse. The current state in PostgreSQL is derived from these events.

### Horizontal Scalability

- Ingestor: Single instance (WebSocket limitation)
- Engine: Multiple Celery workers
- API: Multiple instances behind load balancer
- Databases: Replication for read scaling

### Fault Tolerance

- Redis persistence for task durability
- PostgreSQL WAL for crash recovery
- ClickHouse replication for data durability

---

## Two-Tier Caching

Every ASN lookup passes through a two-level cache before hitting PostgreSQL.

```
Request
   │
   ▼
┌─────────────────────────────┐
│  L1: In-process TTLCache    │  maxsize=5000, TTL = CACHE_TTL (default 60s)
│  Key: score:v3:{asn}        │  (Python cachetools, per worker)
└─────────────────────────────┘
   │ MISS
   ▼
┌─────────────────────────────┐
│  L2: Redis                  │  TTL = CACHE_TTL (default 60s)
│  Key: score:v3:{asn}        │  Shared across all API workers
└─────────────────────────────┘
   │ MISS
   ▼
┌─────────────────────────────┐
│  PostgreSQL (source of truth)│
└─────────────────────────────┘
```

The `X-Cache-Tier` response header tells the client which layer served the request: `L1` or `L2` (absent on a database miss).

Special keys:
- `stats:asn_total_count` — total scored ASN count, cached 300 seconds
- PeeringDB data — cached under `peeringdb:asn:{asn}` for 86400 seconds (24 h)

Cache invalidation: `DELETE /v1/internal/cache/{asn}` (internal endpoint, not exposed at nginx level).

---

## Real-Time Event Bus

Score update events are published to a Redis Pub/Sub channel after each scoring cycle. The WebSocket endpoint subscribes to this channel and fans out to all connected clients.

```
Engine scores AS64496
   │
   ▼ PUBLISH events:asn_updates
┌─────────────────────────────┐
│         Redis Pub/Sub       │
│   channel: events:asn_updates│
└─────────────────────────────┘
   │ SUBSCRIBE
   ▼
┌─────────────────────────────┐
│  API WebSocket handler      │
│  asyncio.Queue(maxsize=100) │
│  HEARTBEAT_INTERVAL = 30s   │
│  SEND_TIMEOUT = 5s          │
└─────────────────────────────┘
   │
   ▼ JSON messages
┌─────────────────────────────┐
│  WebSocket clients          │
└─────────────────────────────┘
```

Backpressure: if a client's queue exceeds 100 messages the connection is closed with WebSocket code `1008` (Policy Violation) to prevent memory exhaustion.

---

## Rate Limiting

Rate limiting is enforced in the FastAPI middleware via a Redis Lua sliding-window log algorithm (nginx does no rate limiting).

- **Window**: 60 seconds
- **Default limit**: 100 requests/window
- **Key**: per client IP (`rl:{client_ip}`), where the IP is taken from `X-Real-IP`/`X-Forwarded-For` set by nginx
- **Storage**: Redis sorted set (entries older than 60s are pruned on each request)
- **Exempt paths**: `/health`, `/`, `/metrics`
- **Fail-open**: if Redis is unavailable the request is served (and logged), rather than returning 503

Headers returned on every request:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed per window |
| `X-RateLimit-Remaining` | Remaining requests for current window |
| `X-RateLimit-Reset` | Unix timestamp of when the window resets |
| `Retry-After` | Seconds to wait before retrying (HTTP 429 only) |

---

## Request Lifecycle

```
Client
  │
  ▼ HTTP/WebSocket
┌──────────────────────────────────────────┐
│  nginx (port 80)                          │
│  • /api/ → reverse proxy to asn-api:8000  │
│  • Sets X-Real-IP / X-Forwarded-For       │
│  • Security headers added                 │
│  • Blocks /api/metrics (403)              │
│  • WebSocket upgrade at /api/v1/stream    │
└──────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────┐
│  FastAPI (port 8000)                      │
│  1. X-Trace-ID generation                 │
│  2. Rate-limit check (Redis Lua, per IP)  │
│  3. API key validation (per-route dep)    │
│  4. L1 cache lookup                       │
│  5. L2 Redis lookup                       │
│  6. PostgreSQL/ClickHouse query (on miss) │
│  7. ORJSONResponse serialization          │
└──────────────────────────────────────────┘
```

---

## Observability

### Prometheus Metrics

The API container exposes metrics at `asn-api:8000/metrics` (Prometheus format). Scrape it on the internal Docker network — the public edge blocks `/api/metrics` with a 403. Prometheus scrape config:

```yaml
- job_name: asn-api
  static_configs:
    - targets: ['asn-api:8000']
  metrics_path: /metrics
```

### Grafana Dashboards

Five pre-built dashboards ship with the platform under `services/dashboard/dashboards/`:

| Dashboard | Purpose |
|-----------|---------|
| `mission_control.json` | High-level KPIs |
| `api_performance.json` | Latency, error rate, cache hit ratios |
| `system_health.json` | CPU, memory, DB connection pools |
| `forensics.json` | BGP event rates, threat signal trends |
| `topology.json` | ASN relationship graph |

### Distributed Tracing

The `X-Trace-ID` header (format: `{unix_ts}-{hex_suffix}`) is attached to every response and all internal log lines. Use it to correlate API access logs with Engine task logs.

