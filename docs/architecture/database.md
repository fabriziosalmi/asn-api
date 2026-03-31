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
    whois_entropy_score  INTEGER DEFAULT 100,
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
    whois_entropy              NUMERIC(10,5),
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

Raw BGP update events.

```sql
CREATE TABLE bgp_events (
    timestamp    DateTime,
    asn          UInt32,
    prefix       String,
    event_type   Enum8('A' = 1, 'W' = 2),
    as_path      Array(UInt32),
    origin_as    UInt32,
    upstream_as  UInt32
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asn, timestamp)
TTL timestamp + INTERVAL 90 DAY;
```

### threat_events

Threat intelligence events.

```sql
CREATE TABLE threat_events (
    timestamp    DateTime,
    asn          UInt32,
    threat_type  String,
    indicator    String,
    source       String,
    severity     UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asn, timestamp)
TTL timestamp + INTERVAL 180 DAY;
```

### asn_score_history

Historical score records. **No TTL** — retained indefinitely for trending analysis.

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

### api_requests

API access log for audit and analytics.

```sql
CREATE TABLE api_requests (
    timestamp    DateTime,
    asn          UInt32,
    api_key_hash String,
    response_ms  UInt32,
    cache_hit    UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn)
TTL timestamp + INTERVAL 30 DAY;
```

### forensic_metrics

Aggregated forensic signal data.

```sql
CREATE TABLE forensic_metrics (
    day                       Date,
    asn                       UInt32,
    ddos_blackhole_count      UInt32,
    excessive_prepending_count UInt32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (asn, day);
```

### bgp_daily_mv

Materialized view for daily BGP aggregates.

```sql
CREATE MATERIALIZED VIEW bgp_daily_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (asn, day)
AS SELECT
    toDate(timestamp) AS day,
    asn,
    countIf(event_type = 'A') AS announcements,
    countIf(event_type = 'W') AS withdrawals,
    uniqExact(prefix) AS unique_prefixes
FROM bgp_events
GROUP BY day, asn;
```

### threat_daily_mv

Materialized view for daily threat aggregates.

```sql
CREATE MATERIALIZED VIEW threat_daily_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (asn, day)
AS SELECT
    toDate(timestamp) AS day,
    asn,
    threat_type,
    count() AS event_count
FROM threat_events
GROUP BY day, asn, threat_type;
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
