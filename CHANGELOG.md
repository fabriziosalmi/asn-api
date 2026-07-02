# Changelog

All notable changes to the ASN Risk Intelligence Platform.

## [7.5.0] - Scoring Activation & Reliability (Jul 2026)
### Added
- **Live routing-hygiene signals**: the scoring engine now derives `has_bogon_ads`,
  `is_stub_but_transit` and RPKI validity (`rpki_invalid_percent`/`rpki_unknown_percent`)
  from the local BGP view and RIPE Stat (cached 6h, circuit-breaker gated). Previously
  these signals were never populated and their penalties never fired.
- **Threat-signal materialization**: ingestor detections in ClickHouse (`threat_events`)
  are now aggregated into `asn_signals` (spamhaus/malware/route-leak), so Category-B
  scoring reflects real detections instead of insert-time defaults.
- **Scorer test suite**: expanded from 2 to 53 unit tests (every penalty, cap, bonus,
  clamping, risk-level threshold, and the bogon/stub/RPKI helpers).

### Changed
- **Rate limiting is now per real client IP** (reads `X-Real-IP`/`X-Forwarded-For` set by
  nginx + uvicorn `--proxy-headers`) instead of collapsing all traffic into the nginx
  container's IP (a single global bucket).
- **Rate limiter fails OPEN** on a Redis outage (serves the request, logs loudly) and
  **`/health`, `/`, `/metrics` are exempt** — a Redis blip no longer 503s every request
  or kills liveness probes. (Reverses the 7.4.1 "returns 503" behavior, which was worse.)
- **`/feeds/edl` now requires `X-API-Key`** — previously it exposed the full scored-ASN
  inventory to anonymous callers. ⚠️ EDL consumers must now send the key (Palo Alto /
  Fortinet EDL sources support a custom header).
- **WebSocket auth** accepts the `X-API-Key` handshake header (query param kept as
  fallback); nginx access log no longer records the query string, keeping the key out of logs.
- **`/metrics`** is blocked at the edge (nginx returns 403 for `/api/metrics`).
- Enrichment (RIPE/PeeringDB) no longer runs on every re-score of an already-known ASN.

### Fixed
- **ClickHouse thread-safety**: the API used a single non-thread-safe `clickhouse-driver`
  client across a 20-thread pool → protocol corruption under concurrency. Now one client
  per pool thread (`threading.local`).
- **nginx would not start** on open-source nginx: removed the NGINX-Plus-only
  `health_check_timeout` directive that failed `nginx -t`.
- **Broken CI**: the 7.4.1 `min_length=32` secret constraint broke the whole test suite
  (conftest/CI used a 15-char key); also fixed an unused import (ruff) and applied `black`.
  Test suite is green again (119 tests) and lint-clean.
- **WebSocket pubsub leak**: the per-connection Redis pubsub is now closed on disconnect.

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
