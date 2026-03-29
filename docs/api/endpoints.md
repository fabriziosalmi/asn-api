# Endpoints

All endpoints require `X-API-Key` header unless noted otherwise. All endpoints are available under the `/v1/` prefix. Legacy routes without prefix are supported for backward compatibility.

## GET /v1/asn/{asn}

Retrieve the complete risk profile for an Autonomous System.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| asn | integer | Yes | AS number (1 - 4,294,967,295) |

### Request

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8080/v1/asn/15169
```

### Response

```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "country_code": "US",
  "registry": "ARIN",
  "risk_score": 95,
  "risk_level": "LOW",
  "rank_percentile": 98.5,
  "downstream_score": 92,
  "last_updated": "2026-03-29 10:00:00+00:00",
  "breakdown": {
    "hygiene": 100,
    "threat": 100,
    "stability": 95
  },
  "signals": {
    "hygiene": {
      "rpki_invalid_percent": 0.0,
      "rpki_unknown_percent": 0.0,
      "has_route_leaks": false,
      "has_bogon_ads": false,
      "is_stub_but_transit": false,
      "prefix_granularity_score": 0
    },
    "threats": {
      "spamhaus_listed": false,
      "spam_emission_rate": 0.0,
      "botnet_c2_count": 0,
      "phishing_hosting_count": 0,
      "malware_distribution_count": 0
    },
    "metadata": {
      "has_peeringdb_profile": true,
      "upstream_tier1_count": 3,
      "is_whois_private": false
    },
    "forensics": {
      "ddos_blackhole_count": 0,
      "excessive_prepending_count": 0
    }
  },
  "details": []
}
```

### Error Responses

All errors return a structured envelope:

```json
{
  "error": "ASN not found or not yet scored",
  "code": "HTTP_404",
  "request_id": "1711700400-a1b2c3d4"
}
```

| Code | Description |
|------|-------------|
| 400 | Invalid ASN (out of range 1-4,294,967,295) |
| 403 | Invalid or missing API key |
| 404 | ASN not found or not yet scored |

---

## GET /v1/asn/{asn}/upstreams

Upstream Risk Analysis: evaluates the risk of the ASN's transit providers.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| asn | integer | Yes | AS number |

### Request

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8080/v1/asn/3333/upstreams
```

### Response

```json
{
  "asn": 3333,
  "risk_score": 95,
  "avg_upstream_score": 88,
  "upstreams": [
    {
      "asn": 1299,
      "name": "TELIA",
      "score": 90,
      "risk_level": "LOW",
      "connection_count": 450
    },
    {
      "asn": 2914,
      "name": "NTT",
      "score": 85,
      "risk_level": "LOW",
      "connection_count": 300
    }
  ]
}
```

---

## GET /v1/asn/{asn}/history

Retrieve paginated historical score data for trend analysis.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| asn | integer | Yes | - | AS number |
| days | integer | No | 30 | Days of history (max 365) |
| offset | integer | No | 0 | Skip first N records |
| limit | integer | No | 200 | Max records to return (max 1000) |

### Request

```bash
curl -H "X-API-Key: $API_KEY" "http://localhost:8080/v1/asn/15169/history?days=7&offset=0&limit=50"
```

### Response

```json
{
  "asn": 15169,
  "total": 168,
  "offset": 0,
  "limit": 50,
  "data": [
    {
      "timestamp": "2026-03-29T10:30:00",
      "score": 95
    },
    {
      "timestamp": "2026-03-29T09:30:00",
      "score": 95
    }
  ]
}
```

---

## POST /v1/tools/bulk-risk-check

Analyze multiple ASNs in a single request. Max 1000 ASNs.

### Request

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 8075]}' \
  http://localhost:8080/v1/tools/bulk-risk-check
```

### Response

```json
{
  "results": [
    {"asn": 15169, "score": 95, "level": "LOW", "name": "GOOGLE"},
    {"asn": 13335, "score": 90, "level": "LOW", "name": "CLOUDFLARENET"},
    {"asn": 8075, "score": null, "level": "UNKNOWN", "name": "Unknown"}
  ],
  "total": 3
}
```

---

## POST /v1/whitelist

Add an ASN to the ignore list (score set to 100). Automatically invalidates the cache for this ASN.

### Request

```bash
curl -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"asn": 64512, "reason": "Internal network"}' \
  http://localhost:8080/v1/whitelist
```

### Validation

- `asn`: 1 - 4,294,967,295
- `reason`: 1 - 500 characters

### Response

```json
{
  "status": "success",
  "message": "ASN 64512 added to whitelist."
}
```

---

## GET /health

Health check endpoint. Does not require authentication.

### Request

```bash
curl http://localhost:8080/health
```

### Response

```json
{
  "status": "healthy",
  "timestamp": "2026-03-29T10:00:00.000000",
  "version": "7.2.0",
  "dependencies": {
    "postgres": "up",
    "clickhouse": "up",
    "redis": "up"
  }
}
```

Returns `503` with `"status": "degraded"` if any dependency is down.

---

## Response Headers

Every response includes these headers:

| Header | Example | Description |
|--------|---------|-------------|
| `X-Trace-ID` | `1711700400-a1b2c3d4` | Correlation ID for distributed tracing |
| `X-RateLimit-Limit` | `100` | Rate limit ceiling per minute |
| `X-RateLimit-Remaining` | `99` | Remaining requests in window |
| `X-RateLimit-Reset` | `1711700460` | Window reset (Unix timestamp) |
| `X-Response-Time` | `12.34ms` | Server processing time |
| `ETag` | `W/"a1b2c3d4e5f67890"` | Stable SHA256-based cache tag |
| `Retry-After` | `45` | Seconds until rate limit resets (429 only) |
