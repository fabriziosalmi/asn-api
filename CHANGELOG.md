# Changelog

All notable changes to the ASN Risk Intelligence Platform.

## [Unreleased]
- **Enterprise**: RFC-Compliant Rate Limiting Headers (`X-RateLimit-*`).
- **Forensics**: Dashboard for BGP Community and Prepending analysis.

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
