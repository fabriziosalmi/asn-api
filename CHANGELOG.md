# Changelog

All notable changes to the ASN Risk Intelligence Platform.

## [7.4.1] - Security Hardening (Apr 2026)
### Fixed
- **CORS Wildcard**: Removed `*` default, now requires explicit `CORS_ORIGINS` configuration.
- **API Key Validation**: Added `min_length=32` requirement for API secret keys.
- **Rate Limit Bypass**: Fixed fallback that disabled rate limiting when Redis was unavailable (now returns 503).
- **GitLab CI Credentials**: Removed hardcoded `POSTGRES_PASSWORD` from CI variables.

### Changed
- **Nginx Health Check**: Now proxies to upstream API instead of returning static OK.
- **ASN Validation**: Added range validation in scorer engine (1-4,294,967,295).

## [7.2.0] - P3 Hardening (Mar 2026)
### Added
- **Load Testing**: Locust load test suite with two user profiles and performance targets.
- **CI Matrix**: GitHub Actions tests against Python 3.11 + 3.12.
- **Docker Hardening**: Multi-stage builds, non-root `appuser`, health checks on all containers.
- **Data Retention**: ClickHouse TTL policies (BGP 90d, threats 180d, API logs 30d).
- **Redis Config**: `maxmemory 256mb` with `allkeys-lru` eviction.

## [7.1.0] - P2 Improvements (Mar 2026)
### Added
- **Pydantic Settings**: Validated configuration via `api_settings.py` and `engine_settings.py`.
- **Structured JSON Logging**: `python-json-logger` across all services, configurable via `LOG_FORMAT`.
- **Error Envelope**: Standardized `{error, code, request_id}` on all error responses.
- **Cache Invalidation**: Scorer busts Redis cache after score updates.
- **Correlation IDs**: `trace_id` propagated from API middleware through Celery to scorer.
- **History Pagination**: `/v1/asn/{asn}/history` supports `offset` and `limit` query params.
- **Alembic Migrations**: Baseline migration matching init.sql schema.
- **FastAPI Lifespan**: Proper startup/shutdown with Redis cleanup.

## [7.0.0] - State-of-the-Art Overhaul (Mar 2026)
### Changed (Breaking)
- **API Versioning**: All endpoints now under `/v1/` prefix. Legacy routes supported but hidden.
- **Async Redis**: Replaced sync `redis.Redis` with `redis.asyncio.Redis`.
- **No Default Credentials**: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `API_SECRET_KEY` are required.
- **Unified Env Vars**: `DB_HOST`/`CLICKHOUSE_HOST` renamed to `DB_META_HOST`/`DB_TS_HOST`.

### Added
- **CORS Middleware**: Configurable via `CORS_ORIGINS` env var.
- **Atomic Rate Limiting**: Redis Lua script replacing racy INCR+EXPIRE.
- **ASN Validation**: 1-4,294,967,295 range check returns 400.
- **Stable ETags**: SHA256-based instead of Python `hash()`.
- **Auth Logging**: Failed authentication attempts logged with client IP.
- **DB Pool Tuning**: `pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`.
- **DB Indexes**: `idx_signals_asn`, `idx_whitelist_asn`.
- **Pre-commit Hooks**: ruff, black, detect-private-key.
- **pip-audit**: Dependency security scanning in CI.

### Removed
- Unused `pandas` and `numpy` from engine requirements.
- All `print()` calls replaced with structured `logger` calls.
- Bare `except:` clauses replaced with typed exception handling.

## [Phase 6] - Enterprise Hardening (Mar 2026)
### Added
- Disabled Grafana anonymous admin access; hardened API key gateway.
- Distributed Tracing (`X-Trace-ID`) and `/health` endpoint.
- Circuit Breaker pattern for RIPEstat/PeeringDB enrichment.
- Redis-backed Rate Limiting and ClickHouse Materialized Views.
- Nginx Reverse Proxy and Docker resource limits.
- Multi-prefix BGP parsing and exponential backoff for ingestor.

## [Phase 5] - BGP Forensics (Jan 2026)
### Added
- DDoS Sponge Detection via Blackhole communities.
- Traffic Engineering Chaos: excessive AS Path Prepending detection.
- Space Squatting: RIR allocation validation.
- New forensic signals: `ddos_blackhole_count`, `excessive_prepending_count`.

## [Phase 4] - Advanced Intelligence (Jan 2026)
### Added
- Downstream Risk Analysis ("Cone of Silence" algorithm).
- Zombie ASN Detection.
- WHOIS Entropy Scoring.
- Peer Pressure Dashboard.

## [Phase 3] - Production Readiness (Jan 2026)
### Added
- Automated Test Suite (`pytest`).
- CI/CD: GitLab CI pipeline.
- Rate Limiting strategy documentation.

## [Phase 2] - Intelligence Features (Dec 2025)
### Added
- BGP Topology Visualization.
- Route Leak Detection.
- Predictive Stability (ML-based).

## [Phase 1] - MVP (Dec 2025)
### Added
- Real threat feeds (Spamhaus, URLhaus, PhishTank).
- API authentication with API keys.
- Historical score timeline.
- PeeringDB enrichment.
- Whitelist management.
- System health monitoring.
- Bulk analysis endpoint.
