# Introduction

The ASN Risk Platform provides real-time risk intelligence for Autonomous Systems (ASNs) on the Internet. It aggregates signals from BGP routing data, threat intelligence feeds, and historical stability metrics to produce a trust score between 0 (high risk) and 100 (trusted).

## Use Cases

- **Supply Chain Security**: Assess the risk profile of upstream providers and transit networks
- **Threat Intelligence**: Identify ASNs hosting malicious infrastructure
- **Network Operations**: Monitor BGP hygiene and detect routing anomalies
- **Compliance**: Verify that traffic does not traverse high-risk networks

## Core Components

| Component | Purpose |
|-----------|---------|
| Ingestor | Streams BGP data from RIPE RIS and fetches threat feeds |
| Engine | Calculates risk scores using weighted signal analysis |
| API | RESTful interface for score queries and bulk analysis |
| Dashboard | Grafana-based visualization and monitoring |

## Scoring Overview

The platform evaluates each ASN across three categories:

1. **Hygiene (40%)**: RPKI validation status, route leak detection, bogon advertisements
2. **Threats (35%)**: Presence on blocklists, hosted malware, botnet infrastructure
3. **Stability (25%)**: BGP announcement volatility, withdrawal frequency

Scores are updated continuously as new data arrives and stored with full history for trend analysis.
