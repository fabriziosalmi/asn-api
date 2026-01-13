# Rate Limiting Strategies for ASN API

To protect the API from abuse and ensure fair usage, we recommend implementing one of the following rate limiting strategies.

## 1. Token Bucket (Recommended)

The **Token Bucket** algorithm is ideal for allowing burst traffic while enforcing a steady rate.

*   **Mechanism**: A bucket is filled with tokens at a constant rate. Each request consumes a token. If the bucket is empty, the request is rejected with `429 Too Many Requests`.
*   **Pros**: Simple, allows bursts (e.g., loading a dashboard).
*   **Cons**: Requires a centralized store (Redis) for distributed systems.

### Implementation with `slowapi` (FastAPI)

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/asn/{asn}")
@limiter.limit("10/second") # Burst limit
def get_asn_score(asn: int):
    ...
```

## 2. Leaky Bucket

The **Leaky Bucket** algorithm smooths out bursts by processing requests at a constant rate.

*   **Mechanism**: Requests enter a queue (bucket). The queue is drained at a constant rate. If the queue is full, new requests are discarded.
*   **Pros**: Smooths traffic perfectly.
*   **Cons**: Can increase latency for users during bursts.

## 3. Fixed Window Counter

A simple counter resets every time window (e.g., 1 minute).

*   **Mechanism**: "Allow 60 requests per minute". Reset counter at `:00`.
*   **Pros**: Easiest to implement.
*   **Cons**: Vulnerable to "boundary attacks" (e.g., 60 requests at 00:59 and 60 at 01:00 = 120 requests in 2 seconds).

## Recommended Configuration

For the ASN Risk Platform:

| User Tier | Rate Limit | Justification |
| :--- | :--- | :--- |
| **Public / Anon** | `5/minute` | Prevent scraping, allow basic testing. |
| **API Key (Standard)** | `10/second` | Allow dashboard loading (bursts) but cap sustained load. |
| **Internal** | Unlimited | Service-to-service communication. |

## Storage Backend

Use **Redis** to store rate limit counters. It is fast, supports atomic increments, and automatic key expiry (TTL).

```bash
# Redis Key Example
rate_limit:127.0.0.1:2026-01-13-10-30
```
