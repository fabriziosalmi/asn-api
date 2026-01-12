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
| 75-89 | MEDIUM | Minor concerns, monitor |
| 50-74 | HIGH | Significant risk factors |
| 0-49 | CRITICAL | Known malicious or severely compromised |

## Hygiene Score (40%)

Evaluates routing best practices and protocol compliance.

| Signal | Penalty | Description |
|--------|---------|-------------|
| RPKI Invalid | -30 | Routes with invalid RPKI status |
| RPKI Unknown | -10 | Routes without ROA coverage |
| Route Leaks | -25 | Valley-free routing violations |
| Bogon Ads | -40 | Advertising reserved/unallocated space |
| Stub Transit | -20 | Stub ASN acting as transit provider |

## Threat Score (35%)

Measures association with malicious activity.

| Signal | Penalty | Description |
|--------|---------|-------------|
| Spamhaus Listed | -50 | Present on DROP/EDROP lists |
| Botnet C2 | -10/host | Hosting command and control servers |
| Phishing | -5/domain | Hosting phishing infrastructure |
| Malware | -10/sample | Distributing malware |
| High Spam Rate | -20 | Excessive spam emission |

## Stability Score (25%)

Assesses operational reliability based on historical behavior.

| Signal | Penalty | Description |
|--------|---------|-------------|
| High Churn | -20 | Excessive route changes |
| Withdrawal Spikes | -15 | Abnormal withdrawal patterns |
| Path Instability | -10 | Frequent AS path changes |

## Score History

All score changes are recorded in ClickHouse with millisecond precision. The `/asn/{asn}/history` endpoint provides access to historical data for trend analysis.

Historical data enables:

- Detection of score degradation over time
- Correlation with external events
- Predictive stability analysis
