-- BGP Routing Events (High Volume)
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
ORDER BY (timestamp, asn);

-- Threat Intelligence Feeds & Logs
CREATE TABLE IF NOT EXISTS threat_events (
    timestamp DateTime,
    asn UInt32,
    source String, -- e.g., 'spamhaus', 'abuse_ch'
    category String, -- 'spam', 'c2', 'malware'
    target_ip String,
    description String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, asn);

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

-- SOTA: Materialized View to auto-aggregate BGP events in real-time
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

-- SOTA: Materialized View for Threat events
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

-- API Request Logging
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
ORDER BY (timestamp, endpoint);

