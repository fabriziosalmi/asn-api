# Integrations

Practical integration patterns for common security tools and workflows.

## Firewall EDL Feed

The `/feeds/edl` endpoint exports a plain-text list of high-risk ASNs in the `ASXXXXX` format. It requires **no authentication** and is designed to be polled directly by firewalls.

By default it returns every ASN with `risk_score ≤ 50` (CRITICAL + HIGH risk). Adjust the `max_score` parameter to tune aggressiveness.

### Palo Alto Networks (PAN-OS)

1. Navigate to **Objects → External Dynamic Lists → Add**
2. Set **Type** to `IP List`
3. Set **Source** to your EDL URL:  
   `http://your-asn-api-host/api/feeds/edl?max_score=50`
4. Set **Check for updates** to `Every 5 minutes`
5. In your Security Policy, reference the EDL in a **Block** rule for traffic sourcing from or destined to blocked ASNs

> Note: PAN-OS External Dynamic Lists require plain-line format. The EDL output (`AS174`, `AS3257`, …) satisfies this requirement when used with a BGP community-based AS path filter.

### Fortinet FortiGate

1. Navigate to **Security Profiles → Threat Feeds → Add**
2. Set **Type** to `IP Address`
3. Set **URI** to `http://your-asn-api-host/api/feeds/edl`
4. Optional: append `?max_score=49` for CRITICAL-only
5. Apply the feed to a Firewall Policy using an **External Block List** object

### Generic / cURL polling

```bash
#!/bin/bash
# Pull the EDL and update a local blocklist file
curl -sf "http://your-asn-api-host/api/feeds/edl?max_score=50" \
  > /etc/firewall/asn-blocklist.txt

# Reload your firewall rules (example for ipset)
ipset flush asn-blocklist
while read -r asn; do
  # Strip "AS" prefix and do a route lookup per ASN
  NUM="${asn#AS}"
  whois -h whois.radb.net -- "-i origin AS${NUM}" | \
    grep '^route:' | awk '{print $2}' | \
    xargs -I{} ipset add asn-blocklist {}
done < /etc/firewall/asn-blocklist.txt
```

### Threshold Tuning

| `max_score` | Risk levels included | Typical use |
|-------------|---------------------|-------------|
| 49 | CRITICAL only | Strict — known malicious networks |
| 74 | CRITICAL + HIGH | Balanced — recommended default |
| 89 | + MEDIUM | Aggressive — may block legitimate traffic |

A cron job refreshing the EDL list every 5 minutes provides near-real-time blocking with minimal latency.

---

## Real-Time WebSocket Feed

The WebSocket endpoint at `WS /v1/stream` delivers score change events in real time. Use it to drive live dashboards, trigger SIEM alerts, or build correlation rules.

### Connection

```
ws://your-asn-api-host/api/v1/stream?api_key=YOUR_KEY
```

### Message examples

Score update:
```json
{
  "asn": 64496,
  "score": 22,
  "previous_score": 68,
  "risk_level": "CRITICAL",
  "timestamp": "2026-03-29T14:30:00Z"
}
```

Keepalive (every 30 seconds):
```json
{"type": "ping"}
```

### Python consumer with automatic reconnect

```python
import asyncio
import json
import websockets
from websockets.exceptions import ConnectionClosed

API_KEY = "your-api-key"
WS_URL = f"ws://your-asn-api-host/api/v1/stream?api_key={API_KEY}"

async def handle_update(msg: dict):
    if msg.get("type") == "ping":
        return
    asn = msg["asn"]
    old = msg["previous_score"]
    new = msg["score"]
    level = msg["risk_level"]
    if level == "CRITICAL":
        print(f"[ALERT] AS{asn} score dropped {old} → {new}: now {level}")

async def stream(backoff: float = 1.0):
    while True:
        try:
            async with websockets.connect(WS_URL, ping_interval=None) as ws:
                print("Connected to score stream")
                backoff = 1.0  # reset on success
                async for raw in ws:
                    await handle_update(json.loads(raw))
        except ConnectionClosed as e:
            print(f"Connection closed ({e.code}). Reconnecting in {backoff}s…")
        except Exception as e:
            print(f"Error: {e}. Reconnecting in {backoff}s…")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)  # exponential backoff, cap at 60s

asyncio.run(stream())
```

### SIEM / Splunk HEC forwarding

```python
import asyncio
import json
import aiohttp
import websockets

SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector"
SPLUNK_TOKEN = "your-hec-token"
ASN_API_WS = "ws://your-asn-api-host/api/v1/stream?api_key=your-key"

async def forward_to_splunk(session: aiohttp.ClientSession, msg: dict):
    payload = {"event": msg, "sourcetype": "asn:score_update"}
    await session.post(
        SPLUNK_HEC_URL,
        json=payload,
        headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"},
        ssl=False,
    )

async def main():
    async with aiohttp.ClientSession() as session:
        async with websockets.connect(ASN_API_WS) as ws:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "ping":
                    await forward_to_splunk(session, msg)

asyncio.run(main())
```

---

## Domain Risk Enrichment (SOC Triage)

The `GET /v1/tools/domain-risk` endpoint automates the most common IOC enrichment step: resolving a domain to its hosting ASN and evaluating infrastructure risk.

### curl one-liner (alert triage)

```bash
# Enrich a suspicious domain from an alert
curl -s -H "X-API-Key: $API_KEY" \
  "http://your-asn-api-host/api/v1/tools/domain-risk?domain=suspicious.example.com" | \
  jq '{domain, resolved_ip, asn, risk: .infrastructure_risk.risk_level, score: .infrastructure_risk.total_score}'
```

Output:
```json
{
  "domain": "suspicious.example.com",
  "resolved_ip": "198.51.100.42",
  "asn": 64496,
  "risk": "CRITICAL",
  "score": 22
}
```

### Batch enrichment from IOC list

```python
import asyncio
import aiohttp

API_KEY = "your-api-key"
BASE_URL = "http://your-asn-api-host/api"

async def enrich_domain(session: aiohttp.ClientSession, domain: str) -> dict:
    url = f"{BASE_URL}/v1/tools/domain-risk"
    async with session.get(url, params={"domain": domain}) as resp:
        if resp.status == 200:
            return await resp.json()
        return {"domain": domain, "error": resp.status}

async def bulk_enrich(domains: list[str]):
    headers = {"X-API-Key": API_KEY}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [enrich_domain(session, d) for d in domains]
        results = await asyncio.gather(*tasks)
        for r in results:
            if "infrastructure_risk" in r:
                risk = r["infrastructure_risk"]
                level = risk.get("risk_level", "UNKNOWN")
                score = risk.get("total_score", "?")
                print(f"{r['domain']:40s} {r['resolved_ip']:16s} AS{r['asn']} {level} ({score})")
            else:
                print(f"{r.get('domain'):40s} ERROR: {r.get('error')}")

domains = [
    "phishing-kit.example.com",
    "c2-server.example.net",
    "legit-site.com",
]
asyncio.run(bulk_enrich(domains))
```

---

## ASN Comparison for Vendor Risk

Use `GET /v1/tools/compare` to compare the security posture of two ISPs or cloud providers during procurement decisions.

```bash
# Compare AWS (16509) vs Azure (8075)
curl -s -H "X-API-Key: $API_KEY" \
  "http://your-asn-api-host/api/v1/tools/compare?asn_a=16509&asn_b=8075" | \
  jq '.comparison'
```

### Risk-based routing (BGP policy helper)

```python
import httpx

def should_prefer(asn_a: int, asn_b: int, api_key: str, base_url: str) -> int | None:
    """Return the safer ASN, or None if equal."""
    resp = httpx.get(
        f"{base_url}/v1/tools/compare",
        params={"asn_a": asn_a, "asn_b": asn_b},
        headers={"X-API-Key": api_key},
    )
    resp.raise_for_status()
    safer = resp.json()["comparison"]["safer_overall"]
    return safer  # None if scores are equal
```

---

## Prometheus Metrics

The API exposes Prometheus-format metrics at `/metrics` (no authentication required). Scrape this endpoint to monitor API health in Grafana.

```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: asn-api
    static_configs:
      - targets: ['your-asn-api-host:80']
    metrics_path: /api/metrics
    scrape_interval: 15s
```

Key metrics exported:

| Metric | Type | Description |
|--------|------|-------------|
| `asn_api_requests_total` | Counter | Total HTTP requests by method/path/status |
| `asn_api_request_duration_seconds` | Histogram | Request latency distribution |
| `asn_api_cache_hits_total` | Counter | L1/L2 cache hit counts |
| `asn_api_active_websocket_connections` | Gauge | Live WebSocket client count |
| `asn_api_rate_limit_hits_total` | Counter | Rate-limited requests |
