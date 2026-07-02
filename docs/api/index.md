# API Overview

The ASN Risk API provides RESTful access to risk scores and analytics.

## Base URL

```
http://localhost:80/api
```

For production deployments, use HTTPS with a reverse proxy.

## Authentication

All scoring endpoints require an API key passed via the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:80/api/v1/asn/15169
```

See [Authentication](./authentication.md) for details.

## Response Format

All responses are JSON with the following structure for successful requests:

```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "risk_score": 85,
  ...
}
```

Error responses use a structured envelope:

```json
{
  "error": "ASN not found or not yet scored",
  "code": "HTTP_404",
  "request_id": "1711700400-a1b2c3d4"
}
```

## Rate Limiting

Default limits:

- 100 requests per minute per client IP
- 1000 ASNs per bulk request

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
```

## Endpoints Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | No | Service information |
| GET | `/health` | No | Health check |
| GET | `/v1/asn/{asn}` | Yes | Get ASN risk score |
| GET | `/v1/asn/{asn}/history` | Yes | Get score history |
| GET | `/v1/asn/{asn}/upstreams` | Yes | Upstream risk analysis |
| GET | `/v1/asn/{asn}/peeringdb` | Yes | PeeringDB metadata |
| GET | `/v1/tools/compare` | Yes | Compare two ASNs |
| GET | `/v1/tools/domain-risk` | Yes | Resolve domain → ASN → risk |
| POST | `/v1/tools/bulk-risk-check` | Yes | Bulk ASN analysis |
| POST | `/v1/whitelist` | Yes | Add ASN to whitelist |
| GET | `/feeds/edl` | Yes | Firewall EDL feed (plain text) |
| WS | `/v1/stream` | Yes | Real-time score firehose |

Legacy routes without the `/v1/` prefix remain for backward compatibility but are hidden from the schema.

## OpenAPI Specification

Interactive documentation is available at:

- Swagger UI: `http://localhost:80/api/docs`
- ReDoc: `http://localhost:80/api/redoc`
- OpenAPI JSON: `http://localhost:80/api/openapi.json`
