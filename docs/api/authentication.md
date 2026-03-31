# Authentication

The API uses API key authentication for all protected endpoints.

## API Key Header

Include the API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:80/api/v1/asn/15169
```

## Configuration

The API key is configured via the `API_SECRET_KEY` environment variable. This variable is **required** -- the API will not start without it.

### Generate a Secure Key

```bash
openssl rand -hex 32
```

### Set in Environment

Add to your `.env` file:

```bash
API_SECRET_KEY=your-generated-key-here
```

Or set directly:

```bash
export API_SECRET_KEY="your-generated-key"
docker-compose restart asn-api
```

## Error Responses

Authentication failures return a structured error envelope:

```json
{
  "error": "Invalid or Missing API Key",
  "code": "HTTP_403",
  "request_id": "1711700400-a1b2c3d4"
}
```

Failed authentication attempts are logged with the client IP address for security monitoring.

## Public Endpoints

The following endpoints do not require authentication:

| Endpoint | Description |
|----------|-------------|
| `GET /api/` | Service information |
| `GET /api/health` | Health check with dependency status |
| `GET /api/docs` | Swagger UI |
| `GET /api/redoc` | ReDoc documentation |
| `GET /api/openapi.json` | OpenAPI specification |

## Rate Limiting

All requests (authenticated or not) are subject to per-IP rate limiting. Limits are enforced atomically via Redis and returned in response headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Requests allowed per minute |
| `X-RateLimit-Remaining` | Remaining requests in window |
| `X-RateLimit-Reset` | Window reset (Unix timestamp) |
| `Retry-After` | Seconds until limit resets (429 responses only) |

Configure the limit via the `API_RATE_LIMIT` environment variable (default: 100 requests/minute).

## Multiple API Keys

For multi-tenant deployments, implement a key management layer using a reverse proxy or API gateway. The platform supports a single master key by default.
