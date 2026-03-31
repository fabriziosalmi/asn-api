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
| Engine | Calculates risk scores using weighted signal analysis (30+ signals) |
| API | Versioned REST interface (`/v1/`) with pagination, caching, rate limiting |
| Dashboard | Grafana-based visualization and monitoring (4 pre-built dashboards) |

## Scoring Overview

The platform evaluates each ASN across four categories:

1. **Hygiene (40%)**: RPKI validation status, route leak detection, bogon advertisements, zombie ASNs
2. **Threats (35%)**: Blocklist presence, malware hosting, botnet infrastructure, WHOIS entropy
3. **Stability (25%)**: BGP announcement volatility, withdrawal frequency, upstream quality
4. **Forensics (Bonus/Penalty)**: DDoS sponge detection, AS path prepending, downstream risk

Scores are updated continuously as new data arrives and stored with full history (365 days) for trend analysis.

## Architecture Highlights (v7.4.0)

- **Async Redis** with atomic Lua-based rate limiting
- **Pydantic Settings** for validated, fail-fast configuration
- **Structured JSON logging** with distributed trace IDs across all services
- **Alembic** for database schema migrations
- **Multi-stage Docker builds** running as non-root user
- **ClickHouse TTL** policies for automatic data retention
