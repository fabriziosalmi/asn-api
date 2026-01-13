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

## Peer Pressure

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

Standard error format following RFC 7807.

```typescript
interface ErrorResponse {
  detail: string
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

### Example

```json
"details": [
  {
      "code": "RPKI_INVALID",
      "severity": "HIGH",
      "description": "2.5% of routes have INVALID RPKI status",
      "action": "Review ROA configuration for advertised prefixes."
  }
]
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
