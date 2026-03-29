-- BGP Routing Events (High Volume) - 90 day retention
CREATE TABLE IF NOT EXISTS bgp_events (
    timestamp DateTime,
    asn UInt32,
    prefix String,
    event_type Enum8('announce' = 1, 'withdraw' = 2),
    upstream_as UInt32,
    path Array(UInt32),
    community Array(UInt32)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS merge_with_ttl_timeout = 86400;

-- Threat Intelligence Feeds & Logs - 180 day retention
CREATE TABLE IF NOT EXISTS threat_events (
    timestamp DateTime,
    asn UInt32,
    source String, -- e.g., 'spamhaus', 'abuse_ch'
    category String, -- 'spam', 'c2', 'malware'
    target_ip String,
    description String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn)
TTL timestamp + INTERVAL 180 DAY DELETE;

-- Calculated Daily Metrics for History/Trending
CREATE TABLE IF NOT EXISTS daily_metrics (
    date Date,
    asn UInt32,
    total_events UInt32,
    announce_count UInt32,
    withdraw_count UInt32,
    threat_count UInt32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, asn);

-- Materialized View to auto-aggregate BGP events in real-time
-- This avoids heavy scans on the raw 'bgp_events' table later.
CREATE MATERIALIZED VIEW IF NOT EXISTS bgp_daily_mv TO daily_metrics AS
SELECT 
    toDate(timestamp) as date,
    asn,
    count() as total_events,
    countIf(event_type = 'announce') as announce_count,
    countIf(event_type = 'withdraw') as withdraw_count,
    0 as threat_count
FROM bgp_events
GROUP BY date, asn;

-- Materialized View for Threat events
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_daily_mv TO daily_metrics AS
SELECT 
    toDate(timestamp) as date,
    asn,
    0 as total_events,
    0 as announce_count,
    0 as withdraw_count,
    count() as threat_count
FROM threat_events
GROUP BY date, asn;

-- Historical ASN scores
CREATE TABLE IF NOT EXISTS asn_score_history (
    timestamp DateTime,
    asn UInt32,
    score UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (asn, timestamp);

-- [Phase 5] Forensic Metrics for BGP Prepending
CREATE TABLE IF NOT EXISTS forensic_metrics (
    date Date,
    asn UInt32,
    prepends_count UInt32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, asn);

CREATE MATERIALIZED VIEW IF NOT EXISTS forensic_prepending_mv TO forensic_metrics AS
SELECT 
    toDate(timestamp) as date,
    asn,
    count() as prepends_count
FROM bgp_events
WHERE countEqual(path, asn) > 3
GROUP BY date, asn;

-- API Request Logging - 30 day retention
CREATE TABLE IF NOT EXISTS api_requests (
    timestamp DateTime,
    endpoint String,
    method String,
    status_code UInt16,
    response_time_ms Float64,
    cache_hit UInt8,
    client_ip String,
    error_message String
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, endpoint)
TTL timestamp + INTERVAL 30 DAY DELETE
SETTINGS merge_with_ttl_timeout = 86400;

