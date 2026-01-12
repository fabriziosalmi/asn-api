#!/bin/bash
# Load Test Script for ASN API
# Generates realistic traffic patterns to populate Grafana dashboard

API_KEY="${API_KEY:-dev-secret}"
BASE_URL="${BASE_URL:-http://localhost:8080}"
DURATION="${1:-60}"  # seconds
RATE="${2:-5}"       # requests per second

echo "=== ASN API Load Test ==="
echo "Duration: ${DURATION}s"
echo "Rate: ${RATE} req/s"
echo "Target: ${BASE_URL}"
echo ""

# Popular ASNs to test (mix of cache hits and misses)
POPULAR_ASNS=(13335 15169 8075 32934 16509 20940 7922 3356 174 1299)
RANDOM_ASNS=()

# Generate some random ASNs for variety
for i in {1..20}; do
    RANDOM_ASNS+=($((10000 + RANDOM % 50000)))
done

ALL_ASNS=("${POPULAR_ASNS[@]}" "${RANDOM_ASNS[@]}")

start_time=$(date +%s)
request_count=0
error_count=0

echo "Starting load test..."
echo ""

while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    # Pick a random ASN (favor popular ones 70% of the time)
    if [ $((RANDOM % 100)) -lt 70 ]; then
        asn=${POPULAR_ASNS[$((RANDOM % ${#POPULAR_ASNS[@]}))]}
    else
        asn=${ALL_ASNS[$((RANDOM % ${#ALL_ASNS[@]}))]}
    fi
    
    # Make request in background
    response=$(curl -s -w "\n%{http_code}" -H "X-API-Key: ${API_KEY}" "${BASE_URL}/asn/${asn}" 2>/dev/null)
    status_code=$(echo "$response" | tail -n1)
    
    request_count=$((request_count + 1))
    
    if [ "$status_code" -ge 400 ]; then
        error_count=$((error_count + 1))
        echo "⚠️  Error: AS${asn} returned ${status_code}"
    else
        echo -n "."
    fi
    
    # Rate limiting
    sleep $(awk "BEGIN {print 1.0/$RATE}")
done

echo ""
echo ""
echo "=== Load Test Complete ==="
echo "Total Requests: ${request_count}"
echo "Errors: ${error_count}"
echo "Success Rate: $(awk "BEGIN {printf \"%.2f%%\", (1-$error_count/$request_count)*100}")"
echo ""
echo "View results in Grafana:"
echo "  http://localhost:3000/d/api_performance"
