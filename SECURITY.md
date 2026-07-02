# Security Policy

## Reporting a vulnerability

Please report security issues privately to **fabrizio.salmi@gmail.com** rather
than opening a public issue. Include steps to reproduce and, where possible, a
minimal proof of concept. You can expect an initial acknowledgement within a few
days.

## Supported versions

The latest `7.x` release receives security fixes. Older majors are not maintained.

## Operational hardening notes

- **API key**: `API_SECRET_KEY` must be at least 32 characters. Generate one with
  `make secrets` (`openssl rand -hex 32`). Never commit `.env`.
- **Authentication**: all API endpoints require `X-API-Key`, including `/feeds/edl`
  and the WebSocket firehose (send the key as the `X-API-Key` handshake header so
  it does not appear in URLs or proxy logs).
- **CORS**: set `CORS_ORIGINS` explicitly for browser-facing deployments; the
  wildcard `*` disables credentialed requests.
- **Metrics**: `/metrics` is blocked at the nginx edge — scrape it only from the
  internal network.
- **Rate limiting** is per client IP (via `X-Real-IP` from the trusted proxy) and
  fails open if Redis is unavailable, prioritising availability over enforcement.
