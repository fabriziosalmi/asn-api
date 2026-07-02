# Scoring Model

The risk score is an additive model, resulting in a value from 0 (maximum risk) to 100 (fully trusted).

## Score Calculation

```
Total Score = clamp(0, 100, 100 − Σ penalties + Σ bonuses)
```

There is no weighted average across categories. Every ASN starts at 100; each rule subtracts (or adds) points and is attributed to a `hygiene`, `threat`, or `stability` sub-score. Each sub-score is reported as `100 + its net penalty`, clamped to 0-100.

## Risk Levels

| Score Range | Level | Interpretation |
|-------------|-------|----------------|
| 90-100 | LOW | Trusted, no significant issues |
| 70-89 | MEDIUM | Minor concerns, monitor |
| 50-69 | HIGH | Significant risk factors |
| 0-49 | CRITICAL | Known malicious or severely compromised |

## Hygiene Sub-score

Evaluates routing best practices and protocol compliance.

| Signal | Penalty | Description |
|--------|---------|-------------|
| RPKI Invalid | -20 | Routes with invalid RPKI status (>1%) |
| Route Leaks | -20 | Valley-free routing violations |
| Bogon Ads | -10 | Advertising reserved/unallocated space |
| High Fragmentation | -10 | Excessive prefix fragmentation (score >50) |
| Stub-but-transit | -10 | Small originator acting as a transit hop |
| Zombie ASN | -15 | Registered but silent (0 prefixes) |

## Threat Sub-score

Measures association with malicious activity.

| Signal | Penalty | Description |
|--------|---------|-------------|
| Spamhaus Listed | -30 | Present on DROP/EDROP lists |
| Botnet C2 | -20/host (max -40) | Hosting command and control servers |
| Malware Distribution | -10/host (max -30) | Hosting malware distribution points |
| Phishing Hosting | -5/host (max -20) | Hosting phishing domains |
| High Spam Rate | -15 | Excessive spam emission |
| WHOIS Entropy | -10 | Algorithmically generated Org Name |
| Persistent Threats | -10 | Repeated threat activity (>5 events in 30d) |

## Stability Sub-score

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

Each score is recorded in ClickHouse (`asn_score_history`, `DateTime` / second precision). The `/v1/asn/{asn}/history` endpoint provides access to historical data for trend analysis.

Historical data enables:

- Detection of score degradation over time
- Correlation with external events
- Predictive stability analysis
