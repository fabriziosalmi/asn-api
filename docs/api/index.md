# API Overview

The ASN Risk API provides RESTful access to risk scores and analytics.

## Base URL

```
http://localhost:8080
```

For production deployments, use HTTPS with a reverse proxy.

## Authentication

All scoring endpoints require an API key passed via the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/asn/15169
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

Error responses follow RFC 7807:

```json
{
  "detail": "ASN not found or not yet scored"
}
```

## Rate Limiting

Default limits:

- 100 requests per minute per API key
- 1000 ASNs per bulk request

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
```

## Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Service information |
| GET | `/health` | Health check |
| GET | `/asn/{asn}` | Get ASN risk score |
| GET | `/asn/{asn}/history` | Get score history |
| POST | `/tools/bulk-risk-check` | Bulk ASN analysis |
| POST | `/whitelist` | Add ASN to whitelist |

## OpenAPI Specification

Interactive documentation is available at:

- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`
- OpenAPI JSON: `http://localhost:8080/openapi.json`
