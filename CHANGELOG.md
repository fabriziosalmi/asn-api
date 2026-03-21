# Changelog

All notable changes to the ASN Risk Intelligence Platform.

## [Phase 6] - Enterprise Hardening (Mar 2026)
### Added
- **Security**: Disabled Grafana anonymous admin access; hardened API key gateway.
- **Observability**: Distributed Tracing (`X-Trace-ID`) and status-check `/health` endpoint for all dependencies.
- **Resilience**: Circuit Breaker pattern for RIPEstat/PeeringDB enrichment.
- **Performance**: Redis-backed Rate Limiting and ClickHouse Materialized Views for BGP Forensics.
- **Infrastructure**: Nginx Reverse Proxy and Docker resource limits (CPU/Memory).
- **Integrita Dati**: Multi-prefix BGP parsing and exponential backoff for ingestor reconnections.

## [Phase 5] - BGP Forensics (Jan 2026)
### Added
- **DDoS Sponge Detection**: Identifying ASNs tagged with Blackhole communities.
- **Traffic Engineering Chaos**: Detecting excessive AS Path Prepending.
- **Space Squatting**: Validation logic for RIR allocations.
- **Ingestor**: Updated to parse BGP Communities from RIPE RIS.
- **Scorer**: New forensic signals: `ddos_blackhole_count`, `excessive_prepending_count`.

## [Phase 4] - Advanced Intelligence (Jan 2026)
### Added
- **Downstream Risk Analysis**: "Cone of Silence" algorithm.
- **Zombie ASN Detection**: Identification of parked/silent networks.
- **WHOIS Entropy Scoring**: Detection of algorithmically generated shell company names.
- **Peer Pressure Dashboard**: Visualization of upstream dependencies.

## [Phase 3] - Production Readiness (Jan 2026)
### Added
- **Automated Test Suite**: `pytest` integration for Scorer and API.
- **CI/CD**: GitLab CI pipeline configuration.
- **Rate Limiting strategy**: Documentation and architecture.

## [Phase 2] - Intelligence Features (Dec 2025)
### Added
- **BGP Topology Visualization**: Graph-based view of ASN connections.
- **Route Leak Detection**: Valley-free violation analysis.
- **Predictive Stability**: ML-based stability scoring.

## [Phase 1] - MVP (Dec 2025)
### Added
- Real threat feeds (Spamhaus, URLhaus, PhishTank).
- API authentication with API keys.
- Historical score timeline.
- PeeringDB enrichment.
- Whitelist management.
- System health monitoring.
- Bulk analysis endpoint.
