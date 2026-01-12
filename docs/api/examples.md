# Examples

Complete working examples for common use cases.

## Basic Score Query

Query a single ASN:

```bash
curl -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169 | jq .
```

With pretty output using jq:

```bash
curl -s -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169 | \
  jq '{asn, name, score: .risk_score, level: .risk_level}'
```

Output:
```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "score": 55,
  "level": "HIGH"
}
```

## Historical Analysis

Get 7 days of score history:

```bash
curl -s -H "X-API-Key: dev-secret" \
  "http://localhost:8080/asn/15169/history?days=7" | \
  jq '.[] | "\(.timestamp): \(.score)"'
```

Output:
```
"2026-01-11 23:03:28": 55
"2026-01-11 21:42:59": 55
"2026-01-11 21:42:23": 70
"2026-01-11 21:42:15": 75
```

## Bulk Analysis

Analyze multiple ASNs in one request:

```bash
curl -s -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 3356, 174]}' \
  http://localhost:8080/tools/bulk-risk-check | \
  jq '.results[] | select(.score != null) | "\(.name) (AS\(.asn)): \(.score)/100 - \(.level)"'
```

Output:
```
"GOOGLE (AS15169): 55/100 - HIGH"
"CLOUDFLARENET (AS13335): 75/100 - MEDIUM"
```

## Extract Specific Signals

Get only threat-related signals:

```bash
curl -s -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169 | \
  jq '.signals.threats'
```

Output:
```json
{
  "spamhaus_listed": false,
  "spam_emission_rate": 0.0,
  "botnet_c2_count": 0,
  "phishing_hosting_count": 0,
  "malware_distribution_count": 0
}
```

## Filter by Risk Level

Find critical ASNs from a list:

```bash
curl -s -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asns": [15169, 13335, 3356, 174, 64512]}' \
  http://localhost:8080/tools/bulk-risk-check | \
  jq '.results[] | select(.level == "CRITICAL" or .level == "HIGH")'
```

## Monitor Score Changes

Simple monitoring script:

```bash
#!/bin/bash
ASN=15169
PREVIOUS_SCORE=$(cat /tmp/asn_${ASN}_score 2>/dev/null || echo 100)

CURRENT_SCORE=$(curl -s -H "X-API-Key: dev-secret" \
  http://localhost:8080/asn/${ASN} | jq -r .risk_score)

echo "$CURRENT_SCORE" > /tmp/asn_${ASN}_score

if [ "$CURRENT_SCORE" -lt "$PREVIOUS_SCORE" ]; then
  echo "ALERT: AS${ASN} score dropped from ${PREVIOUS_SCORE} to ${CURRENT_SCORE}"
fi
```

## Supply Chain Risk Assessment

Analyze an organization's ASN portfolio:

```bash
#!/bin/bash
# Example: Check all ASNs for a company
ASN_LIST='[15169, 36040, 36492, 19527, 43515]'  # Google's ASNs

curl -s -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d "{\"asns\": ${ASN_LIST}}" \
  http://localhost:8080/tools/bulk-risk-check | \
  jq -r '.results[] | select(.score != null) | 
    if .score < 50 then "CRITICAL"
    elif .score < 75 then "HIGH"
    elif .score < 90 then "MEDIUM"
    else "LOW" end + 
    " \(.name) (AS\(.asn)): \(.score)"' | \
  sort
```

## Whitelist Management

Add ASN to ignore list:

```bash
curl -X POST \
  -H "X-API-Key: dev-secret" \
  -H "Content-Type: application/json" \
  -d '{"asn": 64512, "reason": "Private ASN - internal use"}' \
  http://localhost:8080/whitelist
```

Response:
```json
{
  "status": "success",
  "message": "ASN 64512 added to whitelist."
}
```

## Python Integration

```python
import requests

API_KEY = "dev-secret"
BASE_URL = "http://localhost:8080"

def get_asn_risk(asn: int) -> dict:
    headers = {"X-API-Key": API_KEY}
    response = requests.get(f"{BASE_URL}/asn/{asn}", headers=headers)
    response.raise_for_status()
    return response.json()

def bulk_analyze(asn_list: list) -> dict:
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
    response = requests.post(
        f"{BASE_URL}/tools/bulk-risk-check",
        headers=headers,
        json={"asns": asn_list}
    )
    response.raise_for_status()
    return response.json()

# Usage
data = get_asn_risk(15169)
print(f"{data['name']}: {data['risk_score']}/100 ({data['risk_level']})")

# Bulk analysis
results = bulk_analyze([15169, 13335, 3356])
for r in results["results"]:
    if r["score"]:
        print(f"AS{r['asn']}: {r['score']}/100")
```

## Grafana Dashboard Query

Create a Grafana panel using the API as a data source:

```javascript
// In Grafana, use JSON API datasource
// URL: http://localhost:8080/asn/15169
// Headers: X-API-Key: dev-secret
// JSONPath: $.risk_score
```

## Continuous Monitoring with Watch

Monitor changes in real-time:

```bash
watch -n 60 'curl -s -H "X-API-Key: dev-secret" http://localhost:8080/asn/15169 | \
  jq -r "\(.name): \(.risk_score) (\(.risk_level)) - Updated: \(.last_updated)"'
```
