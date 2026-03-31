# Scoring Model

The risk score is a weighted composite of three signal categories, resulting in a value from 0 (maximum risk) to 100 (fully trusted).

## Score Calculation

```
Total Score = (Hygiene × 0.40) + (Threat × 0.35) + (Stability × 0.25)
```

Each component starts at 100 and receives penalties based on detected signals.

## Risk Levels

| Score Range | Level | Interpretation |
|-------------|-------|----------------|
| 90-100 | LOW | Trusted, no significant issues |
| 70-89 | MEDIUM | Minor concerns, monitor |
| 50-69 | HIGH | Significant risk factors |
| 0-49 | CRITICAL | Known malicious or severely compromised |

## Hygiene Score (40%)

Evaluates routing best practices and protocol compliance.

| Signal | Penalty | Description |
|--------|---------|-------------|
| RPKI Invalid | -20 | Routes with invalid RPKI status (>1%) |
| Route Leaks | -20 | Valley-free routing violations |
| Bogon Ads | -10 | Advertising reserved/unallocated space |
| High Fragmentation | -10 | Excessive prefix fragmentation (score >50) |
| Zombie ASN | -15 | Registered but silent (0 prefixes) |

## Threat Score (35%)

Measures association with malicious activity.

| Signal | Penalty | Description |
|--------|---------|-------------|
| Spamhaus Listed | -30 | Present on DROP/EDROP lists |
| Botnet C2 | -20/host (max -40) | Hosting command and control servers |
| High Spam Rate | -15 | Excessive spam emission |
| WHOIS Entropy | -10 | Algorithmically generated Org Name |
| Persistent Threats | -10 | Repeated threat activity (>5 events in 30d) |

## Stability Score (25%)

Assesses operational reliability based on historical behavior.

| Signal | Penalty/Bonus | Description |
|--------|---------------|-------------|
| High Churn | -25 | >2 upstream changes in 90 days |
| Predictive Instability | -15 | Statistical analysis flags instability |
| Route Flapping | -5 | >100 withdrawals in 7 days |
| Bad Neighborhood | -15 | Avg upstream score < 50 |
| Suspicious Upstreams | -5 | Avg upstream score 50–69 |
| Toxic Downstreams | -20 | Avg downstream score < 70 |
| DDoS Sponge | -15 | >5 blackhole events in 7 days |
| Traffic Chaos | -10 | >10 excessive prepending events in 7 days |
| PeeringDB Profile | +5 | Verified peering presence |
| Tier-1 Upstreams | +5 | Multiple Tier-1 transit providers |

## Score History

All score changes are recorded in ClickHouse with millisecond precision. The `/asn/{asn}/history` endpoint provides access to historical data for trend analysis.

Historical data enables:

- Detection of score degradation over time
- Correlation with external events
- Predictive stability analysis
