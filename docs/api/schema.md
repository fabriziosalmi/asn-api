# Response Schema

## RiskScoreResponse

The primary response object for ASN queries.

```typescript
interface RiskScoreResponse {
  asn: number
  name: string | null
  country_code: string | null      // ISO 3166-1 alpha-2, "XX" if unknown
  registry: string | null           // RIR: ARIN, RIPE, APNIC, LACNIC, AFRINIC
  risk_score: number                // 0-100
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  rank_percentile: number           // 0.00-100.00
  downstream_score: number | null   // 0-100
  last_updated: string              // ISO 8601 timestamp
  breakdown: ScoreBreakdown
  signals: AllSignals
  details: PenaltyDetail[]          // Structured actionable feedback
}
```

## ScoreBreakdown

Component scores that comprise the total.

```typescript
interface ScoreBreakdown {
  hygiene: number    // 0-100
  threat: number     // 0-100
  stability: number  // 0-100
}
```

## AllSignals

Complete signal data organized by category.

```typescript
interface AllSignals {
  hygiene: HygieneSignals
  threats: ThreatSignals
  metadata: MetadataSignals
}
```

### HygieneSignals

```typescript
interface HygieneSignals {
  rpki_invalid_percent: number
  rpki_unknown_percent: number
  has_route_leaks: boolean
  has_bogon_ads: boolean
  is_stub_but_transit: boolean
  prefix_granularity_score: number | null
}
```

### ThreatSignals

```typescript
interface ThreatSignals {
  spamhaus_listed: boolean
  spam_emission_rate: number
  botnet_c2_count: number
  phishing_hosting_count: number
  malware_distribution_count: number
}
```

### MetadataSignals

```typescript
interface MetadataSignals {
  has_peeringdb_profile: boolean
  upstream_tier1_count: number
  is_whois_private: boolean
}
```

### ForensicsSignals

```typescript
interface ForensicsSignals {
  ddos_blackhole_count: number    // Prefixes blackholed by upstreams (>5 triggers penalty)
  excessive_prepending_count: number  // AS paths with >3x prepend (>10 triggers penalty)
  whois_entropy: number | null    // Shannon entropy of WHOIS data (low = suspicious)
  is_zombie_asn: boolean          // True if ASN appears in BGP but has no current registrations
}
```

## HistoryPoint

Individual historical score entry.

```typescript
interface HistoryPoint {
  timestamp: string  // ISO 8601 format
  score: number      // 0-100
}
```

## BulkResult

Individual result in bulk analysis response.

```typescript
interface BulkResult {
  asn: number
  score: number | null
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN"
  name: string
}
```

## Upstream Risk Evaluation

Response object for upstream risk analysis.

```typescript
interface PeerPressureResponse {
  asn: number
  risk_score: number
  avg_upstream_score: number
  upstreams: UpstreamPeer[]
}

interface UpstreamPeer {
  asn: number
  name: string | null
  score: number
  risk_level: string
  connection_count: number
}
```

## Error Response

All error responses follow a consistent structure with a stable `code` for programmatic handling.

```typescript
interface ErrorResponse {
  error: string        // Human-readable message
  code: string         // Machine-readable error code (e.g. "ASN_NOT_FOUND")
  request_id: string   // Correlates to X-Trace-ID response header
}
```

### Example

```json
{
  "error": "ASN 99999999 not found in database",
  "code": "ASN_NOT_FOUND",
  "request_id": "1711700400-a1b2c3d4"
}
```

## Details Field Format

The `details` array contains structured objects for programmatic handling.

```typescript
interface PenaltyDetail {
  code: string        // Stable error code (e.g. RPKI_INVALID)
  severity: string    // LOW, MEDIUM, HIGH, CRITICAL
  description: string // Human-readable text
  action: string      // Remediation 
}
```

## CompareResponse

Returned by `GET /v1/tools/compare`.

```typescript
interface CompareResponse {
  asn_a: RiskScoreResponse
  asn_b: RiskScoreResponse
  comparison: {
    safer_overall: number | null   // ASN number of the safer network, null if equal
    score_diff: number             // Absolute score difference (asn_a - asn_b)
    better_hygiene: number | null  // ASN with better hygiene sub-score
    better_threat_profile: number | null  // ASN with lower threat sub-score
    more_stable: number | null     // ASN with better stability sub-score
  }
}
```

## DomainRiskResponse

Returned by `GET /v1/tools/domain-risk`.

```typescript
interface DomainRiskResponse {
  domain: string
  resolved_ip: string | null
  asn: number | null
  infrastructure_risk: RiskScoreResponse | { asn: number; status: string } | { error: string }
}
```

## PeeringDBResponse

Returned by `GET /v1/asn/{asn}/peeringdb`.

```typescript
interface PeeringDBResponse {
  asn: number
  found: boolean
  peeringdb_data: {
    name: string
    type: string          // e.g. "NSP", "Content", "Cable/DSL/ISP", "Enterprise"
    website: string | null
    ix_count: number      // Internet Exchange presence count
    fac_count: number     // Facility count
    peering_policy: string // "Open", "Selective", "Restrictive", "No"
  } | null
}
```

## WebSocketMessage

Messages streamed over `WS /v1/stream`. Two distinct shapes:

```typescript
// Score update event
interface ScoreUpdateMessage {
  asn: number
  score: number
  previous_score: number
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  timestamp: string  // ISO 8601
}

// Keepalive heartbeat (sent every 30 seconds)
interface PingMessage {
  type: "ping"
}
```

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 403 | Authentication failed |
| 404 | Resource not found |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Internal server error |
