# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import asyncio
import os
import random
import time
import json
import websockets
import requests
from datetime import datetime
from clickhouse_driver import Client
import redis
import logging
from celery import Celery

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ingestor")

# Configuration
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', 'db-timeseries')
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'default')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', '')
REDIS_URL = os.getenv('BROKER_URL', 'redis://broker-cache:6379/0')

class DataIngestor:
    def __init__(self):
        self.ch_client = Client(host=CLICKHOUSE_HOST, user=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD)
        self.redis_client = redis.Redis.from_url(REDIS_URL)
        self.celery_app = Celery('ingestor', broker=REDIS_URL)
        self.running = True
        
        # Test ASNs to simulate traffic for
        self.watched_asns = [15169, 2914, 174, 3356, 12345, 666, 9999, 45102]

    async def connect_ripe_ris(self):
        """
        Connects to RIPE RIS Live WebSocket to process REAL BGP updates.
        """
        uri = "wss://ris-live.ripe.net/v1/ws/"
        logger.info(f"[RIPE RIS] Connecting to {uri}...")
        
        backoff = 1
        while self.running:
            try:
                async with websockets.connect(uri) as websocket:
                    backoff = 1 # Reset backoff on success
                    # Subscribe to a stream
                    subscribe_msg = {
                        "type": "ris_subscribe",
                        "data": {
                            "host": "rrc21",
                            "type": "UPDATE",
                            "require": "announcements"
                        }
                    }
                    await websocket.send(json.dumps(subscribe_msg))
                    print("[RIPE RIS] Subscribed to global BGP stream (RRC21)")

                    batch = []
                    last_flush = time.time()

                    async for message in websocket:
                        data = json.loads(message)
                        if data["type"] == "ris_message":
                            parsed_list = self._parse_ripe_message(data["data"])
                            if parsed_list:
                                batch.extend(parsed_list)

                        # Flush to ClickHouse every 2 seconds or 1000 items
                        if len(batch) >= 1000 or (time.time() - last_flush > 2.0 and batch):
                            self._flush_bgp_batch(batch, "REAL")
                            batch = []
                            last_flush = time.time()
                            
            except Exception as e:
                print(f"[RIPE RIS] Connection error: {e}. Reconnecting in {backoff}s...")
                await asyncio.sleep(backoff)
                backoff = min(60, backoff * 2) # Exponential backoff capped at 60s

    def _parse_ripe_message(self, msg):
        """
        Robust Multi-Prefix Parsing.
        Processes ALL prefixes in an announcement to prevent data loss.
        """
        try:
            # Extract Path
            path = msg.get("path", [])
            if not path: return None
            
            origin_asn = path[-1]
            upstream_asn = path[-2] if len(path) > 1 else 0
            
            # Extract ALL Announcements
            announcements = msg.get("announcements", [])
            if not announcements: return None
            
            # Extract Communities
            communities = []
            raw_comms = msg.get("communities", [])
            for c in raw_comms:
                try:
                    if isinstance(c, list) and len(c) == 2:
                         val = c[0] * 65536 + c[1] 
                         communities.append(val)
                    elif isinstance(c, int):
                         communities.append(c)
                except: continue

            events = []
            for announce in announcements:
                prefixes = announce.get("prefixes", [])
                for prefix in prefixes:
                    events.append({
                        'timestamp': datetime.now(),
                        'asn': int(origin_asn),
                        'prefix': str(prefix),
                        'event_type': 'announce',
                        'upstream_as': int(upstream_asn),
                        'path': [int(p) for p in path if isinstance(p, int)], 
                        'community': communities
                    })
            return events
        except Exception:
            return None

    def _flush_bgp_batch(self, batch, source_label):
        if not batch: return
        try:
            # Offload sync ClickHouse write to a thread to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            loop.run_in_executor(
                None, 
                lambda: self.ch_client.execute(
                    'INSERT INTO bgp_events (timestamp, asn, prefix, event_type, upstream_as, path, community) VALUES',
                    batch
                )
            )
        except Exception as e:
            print(f"[BGP-{source_label}] DB Error: {source_label}: {e}")

    async def simulate_bgp_stream(self):
        """
        Simulates a continuous stream of BGP updates (Announcements/Withdrawals).
        Kept for ensuring traffic on test ASNs.
        """
        print("[BGP] Starting BGP Stream simulation...")
        while self.running:
            # Generate a batch of events
            batch = []
            for _ in range(random.randint(1, 10)):
                asn = random.choice(self.watched_asns)
                event_type = random.choice(['announce', 'withdraw'])
                prefix = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"
                
                # Create detailed event
                event = {
                    'timestamp': datetime.now(),
                    'asn': asn,
                    'prefix': prefix,
                    'event_type': event_type,
                    'upstream_as': random.choice(self.watched_asns),
                    'path': [asn, random.choice(self.watched_asns)],
                    'community': [65000 + random.randint(1, 100)]
                }
                batch.append(event)
                
                # Notify system of activity for this ASN (so we can trigger scoring if needed)
                # self.redis_client.publish('asn_activity', str(asn))

            if batch:
                try:
                    loop = asyncio.get_event_loop()
                    loop.run_in_executor(
                        None,
                        lambda: self.ch_client.execute(
                            'INSERT INTO bgp_events (timestamp, asn, prefix, event_type, upstream_as, path, community) VALUES',
                            batch
                        )
                    )
                except Exception as e:
                    print(f"[BGP] Error writing to ClickHouse: {e}")

            await asyncio.sleep(random.uniform(0.5, 2.0))

    async def simulate_threat_intel_feed(self):
        """
        Simulates fetching threat intelligence feeds (e.g. Spamhaus DROP) every 60 seconds.
        """
        print("[Threat] Starting Threat Intel Feed fetcher...")
        while self.running:
            print("[Threat] Fetching new threat data...")
            # Simulate finding a "bad" ASN
            bad_asn = 666
            
            threat_event = [{
                'timestamp': datetime.now(),
                'asn': bad_asn,
                'source': 'simulated_feed',
                'category': 'spam',
                'target_ip': '1.2.3.4',
                'description': ' detected spam mission'
            }]
            
            try:
                loop = asyncio.get_event_loop()
                loop.run_in_executor(
                    None,
                    lambda: self.ch_client.execute(
                        'INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES',
                        threat_event
                    )
                )
                print(f"[Threat] Logged new threat event for ASN {bad_asn}")
                
                # Trigger an immediate rescore for this ASN
                self.redis_client.lpush('scoring_queue', bad_asn)
                
            except Exception as e:
                print(f"[Threat] Error writing to ClickHouse: {e}")

            await asyncio.sleep(30) # Run every 30s

    async def fetch_threat_intelligence(self):
        """
        Fetches REAL Threat Intel Feeds (Spamhaus, CINS, URLHaus) and correlates them.
        Runs every 6 hours.
        """
        print("[Threat] Starting Real Threat Intel fetcher...")
        
        import re
        import ipaddress

        while self.running:
            try:
                # 1. Fetch from Sources
                threat_prefixes = set() # CIDRs (strings)
                threat_ips = set()      # Individual IPs (strings)
                stats = {'spamhaus': 0, 'cins': 0, 'urlhaus': 0}

                # --- Source 1: Spamhaus DROP (Networks) ---
                try:
                    print("[Threat] Downloading Spamhaus DROP...")
                    r = requests.get("https://www.spamhaus.org/drop/drop.txt", timeout=15)
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            if line.strip() and not line.startswith(';'):
                                parts = line.split(';')
                                if parts:
                                    p = parts[0].strip()
                                    threat_prefixes.add(p)
                                    stats['spamhaus'] += 1
                except Exception as e:
                    print(f"[Threat] Spamhaus fetch failed: {e}")

                # --- Source 2: CINS Army (IPs) ---
                try:
                    print("[Threat] Downloading CINS Army...")
                    r = requests.get("http://cinsscore.com/list/ci-badguys.txt", timeout=15)
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            ip = line.strip()
                            if ip:
                                threat_ips.add(ip)
                                stats['cins'] += 1
                except Exception as e:
                    print(f"[Threat] CINS fetch failed: {e}")

                # --- Source 3: URLHaus (IPs from Online URLs) ---
                # Note: We use the simpler text export of online URLs and extract IPs
                try:
                    print("[Threat] Downloading URLHaus...")
                    r = requests.get("https://urlhaus.abuse.ch/downloads/text_online/", timeout=15)
                    if r.status_code == 200:
                        # Regex to find IPv4 in URLs
                        found_ips = re.findall(r'http://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r.text)
                        for ip in found_ips:
                            threat_ips.add(ip)
                            stats['urlhaus'] += 1
                except Exception as e:
                    print(f"[Threat] URLHaus fetch failed: {e}")

                print(f"[Threat] Stats: {stats}. Total Networks: {len(threat_prefixes)}, Total IPs: {len(threat_ips)}")

                # 2. Correlate with Active BGP view (Optimized)
                # Get all prefixes announced in the last hour
                query = """
                SELECT prefix, argMax(asn, timestamp) as asn
                FROM bgp_events 
                WHERE timestamp > now() - INTERVAL 1 HOUR
                GROUP BY prefix
                """
                active_routes = self.ch_client.execute(query) # list of (prefix_str, asn_int)
                
                print(f"[Threat] Checking {len(threat_prefixes) + len(threat_ips)} threats against {len(active_routes)} active BGP routes...")

                found_threats = 0
                
                # Optimization: Use a set for exact prefix matches (O(1) vs O(N))
                # And only use the heavy overlap check if necessary
                bad_networks_obj = []
                for tp in threat_prefixes:
                    try:
                        bad_networks_obj.append(ipaddress.ip_network(tp))
                    except: pass
                
                for route_prefix, route_asn in active_routes:
                    try:
                        source_match = None
                        
                        # Check 1: Exact Match (Fastest)
                        if route_prefix in threat_prefixes:
                            source_match = "Spamhaus (Exact)"
                        
                        # Check 2: IP inside route (if route is /32 or similar)
                        # For brevity and MVP, we check if the route prefix START matches any threat IP
                        # but a real FAANG system would use a Radix Tree (Pytricia)
                        if not source_match:
                            # Heuristic: if it's a small route, check if any threat IP is inside
                            # For now, we use a simple set check for the network address
                            net_addr = route_prefix.split('/')[0]
                            if net_addr in threat_ips:
                                source_match = "CINS/URLHaus (NetAddr Match)"

                        # Check 3: Overlap (Slower, only if not found)
                        if not source_match:
                            route_net = ipaddress.ip_network(route_prefix)
                            for bad_net in bad_networks_obj:
                                if bad_net.overlaps(route_net):
                                    source_match = "Spamhaus (Overlap)"
                                    break

                        if source_match:
                            threat_event = [{
                                'timestamp': datetime.now(),
                                'asn': route_asn,
                                'source': source_match,
                                'category': 'botnet/malware',
                                'target_ip': route_prefix,
                                'description': f'{source_match} detection on {route_prefix}'
                            }]
                            
                            loop = asyncio.get_event_loop()
                            loop.run_in_executor(
                                None,
                                lambda: self.ch_client.execute(
                                    'INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES',
                                    threat_event
                                )
                            )
                            # Instant Rescore
                            self.celery_app.send_task('tasks.calculate_asn_score', args=[route_asn])
                            found_threats += 1
                    
                    except Exception:
                        continue
                    
                    if found_threats % 100 == 0:
                        await asyncio.sleep(0)

                print(f"[Threat] Analysis complete. Flagged {found_threats} ASNs.")
                    
            except Exception as e:
                print(f"[Threat] Error in fetcher loop: {e}")

            await asyncio.sleep(21600) # Run every 6 hours

    async def scan_noisy_neighbors(self):
        """
        Periodically scans ClickHouse for high-volume ASNs and queues them for scoring.
        This ensures our Risk Registry (Postgres) is populated with active networks, not just threats.
        """
        print("[Scanner] Starting Noisy Neighbor scanner...")
        while self.running:
            try:
                # Find ASNs with activity in the last minute
                query = """
                SELECT asn 
                FROM bgp_events 
                WHERE timestamp > now() - INTERVAL 1 MINUTE
                GROUP BY asn 
                HAVING count() > 5
                LIMIT 50
                """
                rows = self.ch_client.execute(query)
                
                if rows:
                    print(f"[Scanner] Found {len(rows)} active ASNs. Queuing for risk analysis...")
                    for row in rows:
                        asn = row[0]
                        # Push to scoring queue (via Celery)
                        self.celery_app.send_task('tasks.calculate_asn_score', args=[asn])
                        
            except Exception as e:
                print(f"[Scanner] Error during scan: {e}")
            
            await asyncio.sleep(10) # Run every 10s

    async def detect_route_leaks(self):
        """
        [The Guard] - Route Leak Hunter.
        Detects anomalies like "Small ASN announcing Huge Prefix".
        Runs generic heuristics every 5 minutes.
        """
        print("[Guard] Starting Route Leak Hunter...")
        
        # Known Tier-1 ASNs (Allowed to announce /8, /9, etc.)
        TIER_1_ASNS = {
            3356, 1299, 174, 2914, 3257, 6453, 3491, 701, 1239, 7018, 6461, 5511, 3549
        }

        while self.running:
            try:
                # Get unique announcements from last 5 minutes
                query = """
                SELECT DISTINCT asn, prefix 
                FROM bgp_events 
                WHERE timestamp > now() - INTERVAL 5 MINUTE 
                  AND event_type = 'announce'
                """
                rows = self.ch_client.execute(query)
                
                leaks_found = 0
                for row in rows:
                    asn, prefix = row
                    
                    try:
                        # Check Prefix Size
                        if '/' in prefix:
                            cidr = int(prefix.split('/')[1])
                            
                            # Heuristic: Non-Tier1 announcing /10 or bigger (smaller number)
                            if cidr <= 10 and asn not in TIER_1_ASNS:
                                description = f"Route Leak Risk: Non-Tier1 ASN {asn} announced huge block {prefix}."
                                print(f"[Guard] 🚨 {description}")
                                
                                threat_event = [{
                                    'timestamp': datetime.now(),
                                    'asn': asn,
                                    'source': 'Route Leak Guard',
                                    'category': 'route_leak',
                                    'target_ip': prefix,
                                    'description': description
                                }]
                                
                                loop = asyncio.get_event_loop()
                                loop.run_in_executor(
                                    None,
                                    lambda: self.ch_client.execute(
                                        'INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES',
                                        threat_event
                                    )
                                )
                                self.celery_app.send_task('tasks.calculate_asn_score', args=[asn])
                                leaks_found += 1
                                
                    except Exception:
                        continue

                if leaks_found > 0:
                    print(f"[Guard] Cycle complete. Flagged {leaks_found} leaks.")
                    
            except Exception as e:
                print(f"[Guard] Error: {e}")
            
            await asyncio.sleep(300)

    async def start(self):
        # Robust wait for dependencies
        logger.info("Verifying database connectivity...")
        while True:
            try:
                self.ch_client.execute("SELECT 1")
                self.redis_client.ping()
                logger.info("Databases are ONLINE.")
                break
            except Exception as e:
                logger.warning(f"Waiting for DBs: {e}")
                await asyncio.sleep(2)
        
        task3 = asyncio.create_task(self.connect_ripe_ris())
        task4 = asyncio.create_task(self.scan_noisy_neighbors())
        task5 = asyncio.create_task(self.fetch_threat_intelligence())
        task6 = asyncio.create_task(self.detect_route_leaks())
        
        await asyncio.gather(task3, task4, task5, task6)


if __name__ == "__main__":
    ingestor = DataIngestor()
    asyncio.run(ingestor.start())
