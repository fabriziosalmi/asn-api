# Signals Reference

This document describes all signals collected and analyzed by the platform.

## Hygiene Signals

### rpki_invalid_percent

Percentage of announced prefixes with RPKI status INVALID. Indicates Route Origin Authorization (ROA) violations.

- **Type**: Float (0.0 - 100.0)
- **Source**: RPKI validators
- **Update Frequency**: Real-time

### rpki_unknown_percent

Percentage of announced prefixes without ROA coverage. High values indicate lack of RPKI deployment.

- **Type**: Float (0.0 - 100.0)
- **Source**: RPKI validators
- **Update Frequency**: Real-time

### has_route_leaks

Boolean indicating detection of valley-free routing violations. Occurs when an ASN announces routes in violation of BGP relationship policies.

- **Type**: Boolean
- **Source**: BGP stream analysis
- **Update Frequency**: Real-time

### has_bogon_ads

Boolean indicating advertisement of bogon prefixes (RFC 1918, documentation ranges, unallocated space).

- **Type**: Boolean
- **Source**: BGP stream analysis
- **Update Frequency**: Real-time

### is_stub_but_transit

Boolean indicating a stub ASN (single upstream) is providing transit services. Often indicates misconfiguration or hijacking.

- **Type**: Boolean
- **Source**: AS relationship inference
- **Update Frequency**: Daily

### prefix_granularity_score

Score based on prefix announcement granularity. Penalizes excessive deaggregation.

- **Type**: Integer (0-100)
- **Source**: BGP stream analysis
- **Update Frequency**: Daily

## Threat Signals

### spamhaus_listed

Boolean indicating presence on Spamhaus DROP or EDROP lists.

- **Type**: Boolean
- **Source**: Spamhaus feeds
- **Update Frequency**: Hourly

### spam_emission_rate

Normalized spam emission rate based on external reports.

- **Type**: Float
- **Source**: Aggregated spam reports
- **Update Frequency**: Daily

### botnet_c2_count

Count of known botnet command and control servers hosted within the ASN.

- **Type**: Integer
- **Source**: Threat intelligence feeds
- **Update Frequency**: Hourly

### phishing_hosting_count

Count of active phishing domains hosted within the ASN.

- **Type**: Integer
- **Source**: PhishTank, URLhaus
- **Update Frequency**: Hourly

### malware_distribution_count

Count of malware distribution points within the ASN.

- **Type**: Integer
- **Source**: URLhaus, VirusTotal
- **Update Frequency**: Hourly

## Metadata Signals

### has_peeringdb_profile

Boolean indicating presence of a PeeringDB entry. Absence reduces transparency.

- **Type**: Boolean
- **Source**: PeeringDB API
- **Update Frequency**: Daily

### upstream_tier1_count

Count of direct Tier-1 upstream providers. Higher values indicate better connectivity and resilience.

- **Type**: Integer
- **Source**: AS relationship data
- **Update Frequency**: Daily

### is_whois_private

Boolean indicating WHOIS information is hidden or uses privacy services.

- **Type**: Boolean
- **Source**: WHOIS queries
- **Update Frequency**: Weekly
