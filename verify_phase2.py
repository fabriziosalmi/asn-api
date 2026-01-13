import requests
import time

API_URL = "http://localhost:8000"
API_KEY = "dev-secret"
HEADERS = {"X-API-Key": API_KEY}

def test_asn_score():
    print("\n[TEST] Testing /asn/{asn} Structure & Headers...")
    asn = 3333 # RIPE NCC
    # Trigger a score first (might be 404 if not in DB, assuming DB has some data or we need to seed it)
    # Actually, we rely on existing data. If 3333 is not there, we might fail.
    # Let's hope the system has data or handled by previous steps.
    
    try:
        r = requests.get(f"{API_URL}/asn/{asn}", headers=HEADERS)
        if r.status_code == 404:
            print("ASN 3333 not found, trying to seed it via scoring... (Not implemented in this script)")
            return
            
        data = r.json()
        
        # 1. Check Structure
        print(f"Status: {r.status_code}")
        if 'details' in data and isinstance(data['details'], list):
            if len(data['details']) > 0:
                first = data['details'][0]
                if 'code' in first and 'action' in first:
                    print(f"✅ Structured Details Validated: {first['code']}")
                else:
                    print(f"❌ Structured Details Invalid Schema: {first}")
            else:
                 print("✅ Details list present (empty)")
        else:
             print("❌ 'details' field missing or not a list")
             
        if 'rank_percentile' in data:
            print(f"✅ Rank Percentile Configured: {data['rank_percentile']}%")
        else:
            print("❌ Rank Percentile missing")

        # 2. Check ETag / Smart Caching
        etag = r.headers.get('ETag')
        if etag:
            print(f"✅ ETag Present: {etag}")
            # Test 304 Not Modified
            r2 = requests.get(f"{API_URL}/asn/{asn}", headers={**HEADERS, "If-None-Match": etag})
            if r2.status_code == 304:
                print("✅ Smart Caching (304) Validated")
            else:
                print(f"❌ Smart Caching Failed: Got {r2.status_code}")
        else:
            print("❌ ETag Header missing")

    except Exception as e:
        print(f"❌ Test Failed: {e}")

def test_peer_pressure():
    print("\n[TEST] Testing /asn/{asn}/upstreams (Peer Pressure)...")
    asn = 3333
    try:
        r = requests.get(f"{API_URL}/asn/{asn}/upstreams", headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            print(f"✅ Peer Pressure Endpoint reachable")
            print(f"ASN: {data['asn']}, Avg Upstream Score: {data['avg_upstream_score']}")
            if 'upstreams' in data:
                print(f"✅ Found {len(data['upstreams'])} upstreams")
            else:
                print("❌ 'upstreams' list missing")
        else:
            print(f"❌ Endpoint Failed: {r.status_code} {r.text}")
    except Exception as e:
        print(f"❌ Test Failed: {e}")

if __name__ == "__main__":
    test_asn_score()
    test_peer_pressure()
