# Load Testing

Uses [Locust](https://locust.io/) for load testing the ASN Risk API.

## Quick Start

```bash
pip install locust

# Start the API stack
docker-compose up -d

# Run with web UI (http://localhost:8089)
locust -f tests/load/locustfile.py --host http://localhost:80

# Headless mode (CI-friendly)
locust -f tests/load/locustfile.py --host http://localhost:80 \
  --users 50 --spawn-rate 5 --run-time 60s --headless --csv=results
```

## Test Profiles

- **ASNApiUser** (weight 3): Simulates normal API consumers with mixed endpoint usage
- **CacheStressUser** (weight 1): Hammers a single ASN to validate cache performance

## Performance Targets

| Endpoint | P50 | P95 | P99 |
|----------|-----|-----|-----|
| `/health` | <10ms | <50ms | <100ms |
| `/v1/asn/{asn}` (cached) | <20ms | <50ms | <100ms |
| `/v1/asn/{asn}` (uncached) | <200ms | <500ms | <1000ms |
| `/v1/asn/{asn}/history` | <100ms | <300ms | <500ms |
| `/v1/tools/bulk-risk-check` | <500ms | <2000ms | <5000ms |
