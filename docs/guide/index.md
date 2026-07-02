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
| Engine | Calculates risk scores from 16 signal fields via 22 additive rules |
| API | Versioned REST interface (`/v1/`) with pagination, caching, rate limiting |
| Dashboard | Grafana-based visualization and monitoring (5 pre-built dashboards) |

## Scoring Overview

Every ASN starts at 100; the engine applies additive penalties and bonuses (no weighted average) and clamps to 0-100. Rules are grouped into three `breakdown` sub-scores:

1. **Hygiene**: RPKI validation status, route leak detection, bogon advertisements, stub-as-transit, zombie ASNs
2. **Threats**: Blocklist presence, malware/phishing hosting, botnet infrastructure, WHOIS entropy
3. **Stability**: BGP volatility, withdrawal frequency, upstream/downstream quality, and forensic penalties (DDoS sponge, AS-path prepending)

Scores are updated continuously as new data arrives; history is stored in ClickHouse and queryable for trend analysis (up to a 365-day window).

## Architecture Highlights (v7.5.0)

- **Async Redis** with atomic Lua-based rate limiting
- **Pydantic Settings** for validated, fail-fast configuration
- **Structured JSON logging** with distributed trace IDs across all services
- **Alembic** for database schema migrations
- **Multi-stage Docker builds** running as non-root user
- **ClickHouse TTL** policies for automatic data retention
