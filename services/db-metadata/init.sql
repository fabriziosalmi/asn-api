-- Enable extension for UUIDs if needed, though basic types suffice for now
CREATE TABLE IF NOT EXISTS asn_registry (
    asn BIGINT PRIMARY KEY,
    name VARCHAR(255),
    country_code CHAR(2),
    registry VARCHAR(50), -- ARIN, RIPE, etc.
    
    -- Main Scores (0-100)
    total_score INTEGER DEFAULT 100,
    hygiene_score INTEGER DEFAULT 100,
    threat_score INTEGER DEFAULT 100,
    stability_score INTEGER DEFAULT 100,
    
    -- Phase 4: SOTA Intelligence
    downstream_score INTEGER DEFAULT 100,
    whois_entropy_score DECIMAL(5,2) DEFAULT 0.0,
    
    risk_level VARCHAR(20) DEFAULT 'UNKNOWN', -- LOW, MEDIUM, HIGH, CRITICAL
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_scored_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS asn_signals (
    asn BIGINT REFERENCES asn_registry(asn),
    
    -- Routing Hygiene (Category A)
    rpki_invalid_percent DECIMAL(5,2),
    rpki_unknown_percent DECIMAL(5,2),
    has_route_leaks BOOLEAN DEFAULT FALSE,
    has_bogon_ads BOOLEAN DEFAULT FALSE,
    prefix_granularity_score INTEGER, -- Derived metric
    is_stub_but_transit BOOLEAN DEFAULT FALSE,
    
    -- Threat Intel (Category B)
    spamhaus_listed BOOLEAN DEFAULT FALSE,
    spam_emission_rate DECIMAL(10,5),
    botnet_c2_count INTEGER DEFAULT 0,
    phishing_hosting_count INTEGER DEFAULT 0,
    malware_distribution_count INTEGER DEFAULT 0,
    
    -- Identity (Category C)
    has_peeringdb_profile BOOLEAN DEFAULT FALSE,
    upstream_tier1_count INTEGER DEFAULT 0,
    is_whois_private BOOLEAN DEFAULT FALSE,
    
    -- Phase 4 Signals
    is_zombie_asn BOOLEAN DEFAULT FALSE,
    whois_entropy DECIMAL(5,2) DEFAULT 0.0,
    
    -- Phase 5 Forensics
    ddos_blackhole_count INTEGER DEFAULT 0,
    excessive_prepending_count INTEGER DEFAULT 0,
    
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (asn)
);


CREATE TABLE IF NOT EXISTS asn_whitelist (
    asn BIGINT PRIMARY KEY REFERENCES asn_registry(asn),
    reason TEXT,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_asn_score ON asn_registry(total_score);
