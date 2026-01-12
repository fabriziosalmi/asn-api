# Field Reference

Detailed explanation of all response fields and their meanings.

## Core Fields

### asn
- **Type**: Integer
- **Description**: The Autonomous System Number being evaluated
- **Example**: `15169`
- **Note**: Valid range is 1 to 4294967295 (32-bit ASN)

### name
- **Type**: String or null
- **Description**: The organization name registered for this ASN
- **Example**: `"GOOGLE"`, `"CLOUDFLARENET"`
- **Note**: Retrieved from WHOIS data. May be null for newly allocated ASNs

### country_code
- **Type**: String or null
- **Description**: ISO 3166-1 alpha-2 country code where the ASN is registered
- **Example**: `"US"`, `"NL"`, `"SG"`
- **Special Values**:
  - `"XX"`: Unknown or not yet determined
  - `null`: Data not available
- **Note**: Represents legal registration, not physical infrastructure location

### registry
- **Type**: String or null
- **Description**: Regional Internet Registry managing this ASN
- **Values**: `"ARIN"`, `"RIPE"`, `"APNIC"`, `"LACNIC"`, `"AFRINIC"`
- **Example**: `"ARIN"` (North America), `"RIPE"` (Europe)
- **Note**: May be null if not yet determined from WHOIS data

### risk_score
- **Type**: Integer (0-100)
- **Description**: Composite trust score (higher is better)
- **Interpretation**:
  - `90-100`: Trusted, minimal risk
  - `75-89`: Low to moderate risk
  - `50-74`: Significant concerns
  - `0-49`: High risk, known issues

### risk_level
- **Type**: Enum
- **Values**: `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`
- **Mapping**:
  - `LOW`: score >= 90
  - `MEDIUM`: 75 <= score < 90
  - `HIGH`: 50 <= score < 75
  - `CRITICAL`: score < 50

### last_updated
- **Type**: String (ISO 8601 timestamp)
- **Description**: When this ASN was last evaluated
- **Example**: `"2026-01-11 23:03:28.308666+00:00"`
- **Note**: Scores are recalculated on events or periodic refresh (typically every 5-15 minutes)

## Score Breakdown

### breakdown.hygiene
- **Type**: Integer (0-100)
- **Weight**: 40% of total score
- **Description**: Routing best practices and protocol compliance
- **Penalties Applied For**:
  - RPKI invalid routes (-30)
  - High RPKI unknown percentage (-10)
  - Route leaks (-25)
  - Bogon advertisements (-40)
  - Stub-to-transit violations (-20)

### breakdown.threat
- **Type**: Integer (0-100)
- **Weight**: 35% of total score
- **Description**: Association with malicious infrastructure
- **Penalties Applied For**:
  - Spamhaus listing (-50)
  - Botnet C2 hosting (-10 per host)
  - Phishing domains (-5 per domain)
  - Malware distribution (-10 per sample)
  - High spam rate (-20)

### breakdown.stability
- **Type**: Integer (0-100)
- **Weight**: 25% of total score
- **Description**: Operational reliability and BGP behavior
- **Penalties Applied For**:
  - High route churn (-20)
  - Withdrawal spikes (-15)
  - Path instability (-10)

## Signal Details

### Hygiene Signals

#### rpki_invalid_percent
- **Type**: Float (0.0-100.0)
- **Description**: Percentage of announced prefixes with RPKI status INVALID
- **Threshold**: Any value > 0 triggers penalty
- **Example**: `2.5` means 2.5% of routes fail RPKI validation

#### rpki_unknown_percent
- **Type**: Float (0.0-100.0)
- **Description**: Percentage of announced prefixes without ROA coverage
- **Threshold**: Values > 50% trigger penalty
- **Note**: High values indicate lack of RPKI adoption, not necessarily malicious

#### has_route_leaks
- **Type**: Boolean
- **Description**: Detection of valley-free routing policy violations
- **True When**: ASN announces routes in violation of customer/peer/provider relationships
- **Impact**: Strong indicator of misconfiguration or hijacking

#### has_bogon_ads
- **Type**: Boolean
- **Description**: Advertisement of bogon/reserved IP space
- **Examples**: RFC 1918 private ranges, documentation ranges, unallocated space
- **Impact**: Severe penalty, indicates serious misconfiguration

#### is_stub_but_transit
- **Type**: Boolean
- **Description**: Stub ASN (single upstream) providing transit to others
- **True When**: Single-homed ASN appears in AS_PATH between unrelated networks
- **Impact**: Suspicious behavior, possible hijack or misconfiguration

#### prefix_granularity_score
- **Type**: Integer (0-100) or null
- **Description**: Score based on prefix announcement granularity
- **Lower Values**: Excessive deaggregation (many small prefixes)
- **Higher Values**: Appropriate aggregation
- **Note**: null when insufficient data

### Threat Signals

#### spamhaus_listed
- **Type**: Boolean
- **Description**: Presence on Spamhaus DROP (Don't Route Or Peer) or EDROP lists
- **True When**: ASN is confirmed as controlled by spammers or malicious actors
- **Data Source**: Updated hourly from Spamhaus feeds
- **Impact**: Major penalty (-50)

#### spam_emission_rate
- **Type**: Float
- **Description**: Normalized spam emission score based on external reports
- **Range**: Typically 0.0 to 1.0, higher is worse
- **Threshold**: > 0.01 triggers penalty
- **Data Source**: Aggregated spam trap data

#### botnet_c2_count
- **Type**: Integer
- **Description**: Count of known botnet command and control servers
- **Data Source**: Threat intelligence feeds (Spamhaus, CINS Score)
- **Note**: Historical data retained for 90 days

#### phishing_hosting_count
- **Type**: Integer
- **Description**: Count of active phishing domains or IPs
- **Data Source**: PhishTank, OpenPhish, URLhaus
- **Update Frequency**: Hourly

#### malware_distribution_count
- **Type**: Integer
- **Description**: Count of malware distribution endpoints
- **Data Source**: URLhaus, VirusTotal
- **Note**: Includes both active and recently remediated

### Metadata Signals

#### has_peeringdb_profile
- **Type**: Boolean
- **Description**: Presence of PeeringDB entry for this ASN
- **False When**: No public peering information available
- **Impact**: Reduces transparency score
- **Note**: Not having PeeringDB is not inherently malicious, but reduces trust

#### upstream_tier1_count
- **Type**: Integer
- **Description**: Count of direct Tier-1 upstream providers
- **Range**: Typically 0-10
- **Interpretation**:
  - `0`: Single-homed or stub network (higher risk)
  - `1-2`: Typical for most networks
  - `3+`: Well-connected, higher resilience
- **Data Source**: AS relationship inference from BGP data

#### is_whois_private
- **Type**: Boolean
- **Description**: WHOIS information is hidden or uses privacy services
- **True When**: Contact information is redacted or uses privacy proxies
- **Impact**: Minor transparency penalty
- **Note**: Some legitimate organizations use privacy services

## Details Array

The `details` field provides human-readable explanations for all detected issues. Each entry follows the format:

```
[Icon] [Category]: [Description]
```

Only signals that triggered penalties are included. An empty array means no issues detected.

### Example Entries

```json
[
  "RPKI: 2.5% of routes have INVALID RPKI status",
  "ROUTING: Valley-free violation detected (possible route leak)",
  "THREAT: Listed on Spamhaus DROP/EDROP",
  "THREAT: 3 known Botnet C2 servers hosted",
  "METADATA: No PeeringDB profile (reduces transparency)"
]
```

## Null vs Zero Values

Understanding the difference between null and zero:

- `null`: Data not yet available or unknown
- `0` or `false`: Data collected, no issues detected
- Empty array `[]`: No details to report (good sign)

Examples:
- `"registry": null` - Registry not yet determined from WHOIS
- `"botnet_c2_count": 0` - Checked, none found
- `"details": []` - All signals clean
