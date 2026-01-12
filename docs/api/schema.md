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
  last_updated: string              // ISO 8601 timestamp
  breakdown: ScoreBreakdown
  signals: AllSignals
  details: string[]                 // Human-readable explanations
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

## Error Response

Standard error format following RFC 7807.

```typescript
interface ErrorResponse {
  detail: string
}
```

## Details Field Format

The `details` array contains human-readable explanations for detected risk signals. Each entry uses emoji icons for visual categorization:

### Icon Legend

| Icon | Category | Example |
|------|----------|---------|
| ⚠️ | Warning | RPKI validation issues |
| 🚨 | Critical | Route leaks, valley-free violations |
| 🔴 | Severe | Bogon advertisements |
| 🛑 | Blocklist | Spamhaus listings |
| 🤖 | Botnet | C2 infrastructure |
| 🎣 | Phishing | Phishing domains |
| 🦠 | Malware | Malware distribution |
| 📧 | Spam | Spam emission |
| 📡 | Metadata | Transparency issues |
| 🔗 | Connectivity | Network resilience |
| 🕵️ | Privacy | Hidden WHOIS |

### Example Details

```json
"details": [
  "⚠️ RPKI: 2.5% of routes have INVALID RPKI status",
  "🚨 ROUTING: Valley-free violation detected (possible route leak)",
  "🛑 THREAT: Listed on Spamhaus DROP/EDROP",
  "🤖 THREAT: 3 known Botnet C2 servers hosted",
  "📡 METADATA: No PeeringDB profile (reduces transparency)"
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
