# Endpoints

## GET /asn/{asn}

Retrieve the complete risk profile for an Autonomous System.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| asn | integer | Yes | The AS number to query |

### Request

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169
```

### Response

```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "country_code": "XX",
  "registry": null,
  "risk_score": 55,
  "risk_level": "HIGH",
  "last_updated": "2026-01-11 23:03:28.308666+00:00",
  "breakdown": {
    "hygiene": 100,
    "threat": 90,
    "stability": 70
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
      "has_peeringdb_profile": false,
      "upstream_tier1_count": 1,
      "is_whois_private": false
    }
  },
  "details": [
    "METADATA: No PeeringDB profile (reduces transparency)"
  ]
}
```

### Error Responses

| Code | Description |
|------|-------------|
| 403 | Invalid or missing API key |
| 404 | ASN not found or not yet scored |

---

## GET /asn/{asn}/history

Retrieve historical score data for trend analysis.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| asn | integer | Yes | - | The AS number to query |
| days | integer | No | 30 | Number of days of history (max 365) |

### Request

```bash
curl -H "X-API-Key: dev-secret" "http://localhost:8080/asn/15169/history?days=7"
```

### Response

```json
[
  {
    "timestamp": "2026-01-12T10:30:00",
    "score": 85
  },
  {
    "timestamp": "2026-01-11T18:45:00",
    "score": 82
  },
  {
    "timestamp": "2026-01-11T12:00:00",
    "score": 85
  }
]
```

---

## POST /tools/bulk-risk-check

Analyze multiple ASNs in a single request.

### Request Body

```json
{
  "asns": [15169, 13335, 8075, 3356]
}
```

Maximum 1000 ASNs per request.

### Request

```bash
curl -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 8075]}' \
  http://localhost:8080/tools/bulk-risk-check
```

### Response

```json
{
  "results": [
    {
      "asn": 15169,
      "score": 55,
      "level": "HIGH",
      "name": "GOOGLE"
    },
    {
      "asn": 13335,
      "score": 75,
      "level": "MEDIUM",
      "name": "CLOUDFLARENET"
    },
    {
      "asn": 8075,
      "score": null,
      "level": "UNKNOWN",
      "name": "Unknown"
    }
  ]
}
```

---

## POST /whitelist

Add an ASN to the ignore list.

### Request Body

```json
{
  "asn": 64512,
  "reason": "Internal network - expected behavior"
}
```

### Request

```bash
curl -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asn": 64512, "reason": "Internal network"}' \
  http://localhost:8080/whitelist
```

### Response

```json
{
  "status": "success",
  "message": "ASN 64512 added to whitelist."
}
```

---

## GET /health

Health check endpoint for load balancers and monitoring.

### Request

```bash
curl http://localhost:8080/health
```

### Response

```json
{
  "status": "healthy"
}
```

This endpoint does not require authentication.
