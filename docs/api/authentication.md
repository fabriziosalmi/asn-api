# Authentication

The API uses API key authentication for all protected endpoints.

## API Key Header

Include the API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/asn/15169
```

## Development Key

For local development, use the default key:

```
dev-secret
```

This key is configured via the `API_SECRET_KEY` environment variable.

## Production Configuration

For production deployments:

1. Generate a secure API key:

```bash
openssl rand -hex 32
```

2. Set the environment variable:

```bash
export API_SECRET_KEY="your-generated-key"
```

3. Restart the API service:

```bash
docker-compose restart asn-api
```

## Error Responses

### Missing API Key

```
HTTP/1.1 403 Forbidden

{
  "detail": "Invalid or Missing API Key"
}
```

### Invalid API Key

```
HTTP/1.1 403 Forbidden

{
  "detail": "Invalid or Missing API Key"
}
```

## Public Endpoints

The following endpoints do not require authentication:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Service information |
| `GET /health` | Health check |
| `GET /docs` | Swagger UI |
| `GET /redoc` | ReDoc documentation |
| `GET /openapi.json` | OpenAPI specification |

## Multiple API Keys

For multi-tenant deployments, implement a key management layer using a reverse proxy or API gateway. The platform supports a single master key by default.
