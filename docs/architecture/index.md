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
- Calculates weighted risk scores
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
