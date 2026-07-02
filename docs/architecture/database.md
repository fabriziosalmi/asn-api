# Database Schema

## PostgreSQL

PostgreSQL stores the current state and metadata.

### asn_registry

Primary table for ASN information and current scores.

```sql
CREATE TABLE asn_registry (
    asn                  BIGINT PRIMARY KEY,
    name                 VARCHAR(255),
    country_code         CHAR(2),
    registry             VARCHAR(50),
    total_score          INTEGER DEFAULT 100,
    hygiene_score        INTEGER DEFAULT 100,
    threat_score         INTEGER DEFAULT 100,
    stability_score      INTEGER DEFAULT 100,
    downstream_score     INTEGER DEFAULT 100,
    whois_entropy_score  DECIMAL(5,2) DEFAULT 0.0,
    risk_level           VARCHAR(20) DEFAULT 'UNKNOWN',
    created_at           TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scored_at       TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_asn_score ON asn_registry(total_score);
```

### asn_signals

Detailed signal data for each ASN.

```sql
CREATE TABLE asn_signals (
    asn                        BIGINT PRIMARY KEY REFERENCES asn_registry(asn),
    rpki_invalid_percent       NUMERIC(5,2),
    rpki_unknown_percent       NUMERIC(5,2),
    has_route_leaks            BOOLEAN DEFAULT FALSE,
    has_bogon_ads              BOOLEAN DEFAULT FALSE,
    prefix_granularity_score   INTEGER,
    is_stub_but_transit        BOOLEAN DEFAULT FALSE,
    spamhaus_listed            BOOLEAN DEFAULT FALSE,
    spam_emission_rate         NUMERIC(10,5),
    botnet_c2_count            INTEGER DEFAULT 0,
    phishing_hosting_count     INTEGER DEFAULT 0,
    malware_distribution_count INTEGER DEFAULT 0,
    has_peeringdb_profile      BOOLEAN DEFAULT FALSE,
    upstream_tier1_count       INTEGER DEFAULT 0,
    is_whois_private           BOOLEAN DEFAULT FALSE,
    is_zombie_asn              BOOLEAN DEFAULT FALSE,
    whois_entropy              DECIMAL(5,2) DEFAULT 0.0,
    ddos_blackhole_count       INTEGER DEFAULT 0,
    excessive_prepending_count INTEGER DEFAULT 0,
    updated_at                 TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### asn_whitelist

User-managed ignore list.

```sql
CREATE TABLE asn_whitelist (
    asn       BIGINT PRIMARY KEY,
    reason    TEXT,
    added_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## ClickHouse

ClickHouse stores time-series event data.

### bgp_events

Raw BGP update events. 90-day TTL.

```sql
CREATE TABLE bgp_events (
    timestamp   DateTime,
    asn         UInt32,
    prefix      String,
    event_type  Enum8('announce' = 1, 'withdraw' = 2),
    upstream_as UInt32,
    path        Array(UInt32),
    community   Array(UInt32)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn)
TTL timestamp + INTERVAL 90 DAY DELETE;
```

### threat_events

Threat intelligence detections. 180-day TTL.

```sql
CREATE TABLE threat_events (
    timestamp   DateTime,
    asn         UInt32,
    source      String,      -- e.g. 'Spamhaus (Exact)', 'Route Leak Guard'
    category    String,      -- 'spamhaus', 'malware', 'route_leak', ...
    target_ip   String,      -- offending prefix / IP
    description String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn)
TTL timestamp + INTERVAL 180 DAY DELETE;
```

### daily_metrics

Aggregation target for the materialized views below (SummingMergeTree).

```sql
CREATE TABLE daily_metrics (
    date           Date,
    asn            UInt32,
    total_events   UInt32,
    announce_count UInt32,
    withdraw_count UInt32,
    threat_count   UInt32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, asn);
```

### asn_score_history

Historical score records. **No TTL** — retained indefinitely for trend analysis.

```sql
CREATE TABLE asn_score_history (
    timestamp  DateTime,
    asn        UInt32,
    score      UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asn, timestamp);
-- No TTL: score history is retained indefinitely
```

### forensic_metrics

Aggregated BGP-prepending counts (SummingMergeTree), fed by `forensic_prepending_mv`.

```sql
CREATE TABLE forensic_metrics (
    date           Date,
    asn            UInt32,
    prepends_count UInt32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, asn);
```

### api_requests

API access log for audit and analytics. 30-day TTL.

```sql
CREATE TABLE api_requests (
    timestamp        DateTime,
    endpoint         String,
    method           String,
    status_code      UInt16,
    response_time_ms Float64,
    cache_hit        UInt8,
    client_ip        String,
    error_message    String
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, endpoint)
TTL timestamp + INTERVAL 30 DAY DELETE;
```

### Materialized views

`bgp_daily_mv` and `threat_daily_mv` both write into `daily_metrics`; `forensic_prepending_mv` writes into `forensic_metrics`.

```sql
CREATE MATERIALIZED VIEW bgp_daily_mv TO daily_metrics AS
SELECT toDate(timestamp) AS date, asn,
       count() AS total_events,
       countIf(event_type = 'announce') AS announce_count,
       countIf(event_type = 'withdraw') AS withdraw_count,
       0 AS threat_count
FROM bgp_events GROUP BY date, asn;

CREATE MATERIALIZED VIEW threat_daily_mv TO daily_metrics AS
SELECT toDate(timestamp) AS date, asn,
       0 AS total_events, 0 AS announce_count, 0 AS withdraw_count,
       count() AS threat_count
FROM threat_events GROUP BY date, asn;

CREATE MATERIALIZED VIEW forensic_prepending_mv TO forensic_metrics AS
SELECT toDate(timestamp) AS date, asn, count() AS prepends_count
FROM bgp_events
WHERE countEqual(path, asn) > 3
GROUP BY date, asn;
```

## Data Model Relationships

```
┌─────────────────┐
│  asn_registry   │
│  (PostgreSQL)   │
└────────┬────────┘
         │ 1:1
         ▼
┌─────────────────┐
│  asn_signals    │
│  (PostgreSQL)   │
└─────────────────┘

┌─────────────────┐
│  bgp_events     │──┐
│  (ClickHouse)   │  │
└─────────────────┘  │
                     │ aggregates to
┌─────────────────┐  │
│  bgp_daily_mv   │◄─┘
│  (ClickHouse)   │
└─────────────────┘

┌─────────────────┐
│ threat_events   │──┐
│  (ClickHouse)   │  │
└─────────────────┘  │
                     │ aggregates to
┌─────────────────┐  │
│ threat_daily_mv │◄─┘
│  (ClickHouse)   │
└─────────────────┘
```
