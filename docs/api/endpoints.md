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
curl -H "X-API-Key: $API_KEY" http://localhost:80/api/v1/asn/15169
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
curl -H "X-API-Key: $API_KEY" http://localhost:80/api/v1/asn/3333/upstreams
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
curl -H "X-API-Key: $API_KEY" "http://localhost:80/api/v1/asn/15169/history?days=7&offset=0&limit=50"
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
  http://localhost:80/api/v1/tools/bulk-risk-check
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
  http://localhost:80/api/v1/whitelist
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
curl http://localhost:80/api/health
```

### Response

```json
{
  "status": "healthy",
  "timestamp": "2026-03-29T10:00:00.000000",
  "version": "7.3.0",
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

---

## GET /v1/tools/compare

Compare two ASNs side-by-side to identify which is safer and where the risk differences lie. Returns delta values across all scoring dimensions.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| asn_a | integer | Yes | First ASN to compare |
| asn_b | integer | Yes | Second ASN to compare |

### Request

```bash
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:80/api/v1/tools/compare?asn_a=15169&asn_b=3356"
```

### Response

```json
{
  "asn_a": {
    "asn": 15169,
    "name": "GOOGLE",
    "country_code": "US",
    "total_score": 95,
    "risk_level": "LOW",
    "hygiene_score": 100,
    "threat_score": 100,
    "stability_score": 85
  },
  "asn_b": {
    "asn": 3356,
    "name": "LEVEL3",
    "country_code": "US",
    "total_score": 80,
    "risk_level": "MEDIUM",
    "hygiene_score": 90,
    "threat_score": 85,
    "stability_score": 75
  },
  "comparison": {
    "safer_overall": 15169,
    "score_diff": 15,
    "better_hygiene": 15169,
    "better_threat_profile": 15169,
    "more_stable": 15169
  }
}
```

The `comparison` object will have `null` for a dimension when both ASNs are equal on that dimension.

### Error Responses

| Code | Description |
|------|-------------|
| 400 | Invalid ASN number |
| 404 | One or both ASNs not found in database |

---

## GET /v1/tools/domain-risk

Resolve a domain to its hosting ASN and return the infrastructure risk score. Critical for phishing investigation, malware analysis, and SOC triage workflows.

**Pipeline:** Domain → DNS A record → IP → Cymru ASN lookup → Risk DB query

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| domain | string | Yes | Domain to analyze (e.g. `example.com`), max 253 chars |

### Request

```bash
curl -H "X-API-Key: $API_KEY" \
  "http://localhost:80/api/v1/tools/domain-risk?domain=malicious-site.example"
```

### Response (ASN found and scored)

```json
{
  "domain": "malicious-site.example",
  "resolved_ip": "198.51.100.42",
  "asn": 64496,
  "infrastructure_risk": {
    "asn": 64496,
    "name": "EXAMPLE-ISP",
    "country_code": "US",
    "total_score": 35,
    "risk_level": "CRITICAL",
    "hygiene_score": 60,
    "threat_score": 20,
    "stability_score": 70
  }
}
```

### Response (ASN not yet scored)

```json
{
  "domain": "new-domain.example",
  "resolved_ip": "203.0.113.5",
  "asn": 64497,
  "infrastructure_risk": {
    "asn": 64497,
    "status": "Not scored yet"
  }
}
```

### Response (IP not mappable to ASN)

```json
{
  "domain": "edge-case.example",
  "resolved_ip": "1.2.3.4",
  "asn": null,
  "error": "Could not map IP to an ASN"
}
```

### Security

- Private/loopback/link-local IPs are rejected with `400` to prevent SSRF
- DNS resolution uses async resolver with configurable timeout
- Cymru TXT record lookup (`origin.asn.cymru.com`) for accurate ASN attribution

### Error Responses

| Code | Description |
|------|-------------|
| 400 | Domain resolves to private/non-global IP (SSRF protection) |
| 400 | Cannot resolve domain (DNS failure or NXDOMAIN) |
| 403 | Invalid or missing API key |

---

## GET /v1/asn/{asn}/peeringdb

Fetch and cache live PeeringDB metadata for an ASN. Provides business context: network type, Internet Exchange presence, and facility count. Cached for 24 hours.

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| asn | integer | Yes | AS number |

### Request

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:80/api/v1/asn/15169/peeringdb
```

### Response (profile found)

```json
{
  "asn": 15169,
  "found": true,
  "peeringdb_data": {
    "name": "Google LLC",
    "type": "Content",
    "website": "https://www.google.com",
    "ix_count": 42,
    "fac_count": 18,
    "peering_policy": "Open"
  }
}
```

The `type` field reflects the PeeringDB `info_type`: `"NSP"` (Network Service Provider), `"Content"`, `"Cable/DSL/ISP"`, `"Enterprise"`, `"Educational/Research"`, `"Nonprofit"`, etc.

### Response (no profile)

```json
{
  "asn": 64512,
  "found": false,
  "peeringdb_data": null
}
```

### Error Responses

| Code | Description |
|------|-------------|
| 400 | Invalid ASN number |
| 502 | PeeringDB returned an unexpected status code |
| 503 | Failed to reach PeeringDB (network error) |

---

## GET /feeds/edl

Returns a plain-text External Dynamic List (EDL) of all ASNs with a risk score at or below the specified threshold. Compatible with Palo Alto Networks, Fortinet FortiGate, Check Point, and any firewall that accepts plain-text IP/AS block lists.

**Does not require authentication.** The list is intended for firewall automation and must be publicly accessible to the device polling it.

### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| max_score | float | No | 50.0 | Include ASNs with score ≤ this value (0.0–100.0) |

### Request

```bash
# Default: all CRITICAL+HIGH ASNs (score ≤ 50)
curl http://localhost:80/api/feeds/edl

# Strict: only CRITICAL ASNs (score ≤ 49)
curl "http://localhost:80/api/feeds/edl?max_score=49"

# Broad: any ASN not fully trusted (score ≤ 89)
curl "http://localhost:80/api/feeds/edl?max_score=89"
```

### Response

Plain text, one ASN per line in `ASXXXXX` format:

```
AS174
AS3257
AS64496
AS64497
```

Content-Type: `text/plain`

### Firewall Integration

**Palo Alto Networks (PAN-OS):**
```
Objects → External Dynamic Lists → Add
Type: Predefined IP/Domain (use "IP List" with ASN filter in policy)
Source: http://your-asn-api/api/feeds/edl?max_score=50
Refresh: every 5 minutes
```

**Fortinet FortiGate:**
```
Security Profiles → Threat Feeds → Add
Type: IP Address
URL: http://your-asn-api/api/feeds/edl
```

See [Integrations Guide](/guide/integrations) for complete firewall configuration examples.

---

## WebSocket /v1/stream

Real-time firehose of ASN score update events over a persistent WebSocket connection. Each message is a JSON object published to the Redis `events:asn_updates` channel after each scoring cycle.

Authentication is passed as a **query parameter** (not a header) because WebSocket upgrade requests cannot carry custom headers in most browsers.

### Connection

```
ws://localhost:80/api/v1/stream?api_key=YOUR_KEY
```

### Authentication

The `api_key` query parameter is required. The connection is closed with code `1008` (Policy Violation) if the key is missing or invalid.

### Message Format

Score update event:

```json
{
  "asn": 15169,
  "score": 93,
  "previous_score": 95,
  "risk_level": "LOW",
  "timestamp": "2026-03-29T10:15:00Z"
}
```

Keepalive ping (sent every 30 seconds):

```json
{"type": "ping"}
```

### Backpressure & OOM Protection

The server maintains a bounded queue of **100 messages per connection**. If the client cannot consume messages fast enough and the queue fills up, the connection is closed with code `1008`. Reconnect with backoff.

### Example (Python)

```python
import asyncio
import websockets
import json

async def stream_updates():
    url = "ws://localhost:80/api/v1/stream?api_key=YOUR_KEY"
    async with websockets.connect(url) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("type") == "ping":
                continue  # heartbeat
            print(f"AS{msg['asn']}: {msg['previous_score']} → {msg['score']} ({msg['risk_level']})")

asyncio.run(stream_updates())
```

### Example (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:80/api/v1/stream?api_key=YOUR_KEY');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'ping') return;
  console.log(`AS${msg.asn}: ${msg.previous_score} → ${msg.score} (${msg.risk_level})`);
};

ws.onclose = (event) => {
  console.log(`Closed: code=${event.code}. Reconnecting...`);
  // Implement exponential backoff
};
```

### Close Codes

| Code | Reason |
|------|--------|
| `1000` | Normal closure |
| `1008` | Auth failure or queue overflow |
