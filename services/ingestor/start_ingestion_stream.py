# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import asyncio
import os
import random
import threading
import time
import json
import logging
from datetime import datetime

import websockets
import requests
from clickhouse_driver import Client
import redis
from celery import Celery

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("ingestor")

# Configuration
CLICKHOUSE_HOST = os.getenv("DB_TS_HOST", "db-timeseries")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
REDIS_URL = os.getenv("BROKER_URL", "redis://broker-cache:6379/0")


class DataIngestor:
    def __init__(self) -> None:
        self.ch_client = Client(
            host=CLICKHOUSE_HOST, user=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
        )
        # clickhouse-driver Client is NOT thread-safe; protect all execute() calls
        self._ch_lock = threading.Lock()
        self.redis_client = redis.Redis.from_url(REDIS_URL)
        self.celery_app = Celery("ingestor", broker=REDIS_URL)
        self.running = True

        # Test ASNs to simulate traffic for
        self.watched_asns = [15169, 2914, 174, 3356, 12345, 666, 9999, 45102]

    def _ch_execute_sync(self, query: str, params=None):
        """Thread-safe wrapper around ch_client.execute()."""
        with self._ch_lock:
            if params is not None:
                return self.ch_client.execute(query, params)
            return self.ch_client.execute(query)

    async def connect_ripe_ris(self) -> None:
        """Connects to RIPE RIS Live WebSocket to process REAL BGP updates."""
        uri = "wss://ris-live.ripe.net/v1/ws/"
        logger.info("ris_connecting uri=%s", uri)

        backoff = 1
        while self.running:
            try:
                async with websockets.connect(uri) as websocket:
                    backoff = 1
                    subscribe_msg = {
                        "type": "ris_subscribe",
                        "data": {
                            "host": "rrc21",
                            "type": "UPDATE",
                            "require": "announcements",
                        },
                    }
                    await websocket.send(json.dumps(subscribe_msg))
                    logger.info("ris_subscribed host=rrc21")

                    batch: list[dict] = []
                    last_flush = time.time()

                    async for message in websocket:
                        data = json.loads(message)
                        if data["type"] == "ris_message":
                            parsed_list = self._parse_ripe_message(data["data"])
                            if parsed_list:
                                batch.extend(parsed_list)

                        if len(batch) >= 1000 or (
                            time.time() - last_flush > 2.0 and batch
                        ):
                            await self._flush_bgp_batch(batch, "REAL")
                            batch = []
                            last_flush = time.time()

            except Exception as e:
                logger.warning("ris_connection_error error=%s backoff=%ss", e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(60, backoff * 2)

    def _parse_ripe_message(self, msg: dict) -> list[dict] | None:
        """Robust Multi-Prefix Parsing."""
        try:
            path = msg.get("path", [])
            if not path:
                return None

            origin_asn = path[-1]
            upstream_asn = path[-2] if len(path) > 1 else 0

            announcements = msg.get("announcements", [])
            if not announcements:
                return None

            communities: list[int] = []
            raw_comms = msg.get("communities", [])
            for c in raw_comms:
                try:
                    if isinstance(c, list) and len(c) == 2:
                        val = c[0] * 65536 + c[1]
                        communities.append(val)
                    elif isinstance(c, int):
                        communities.append(c)
                except (TypeError, ValueError):
                    continue

            events = []
            for announce in announcements:
                prefixes = announce.get("prefixes", [])
                for prefix in prefixes:
                    events.append(
                        {
                            "timestamp": datetime.now(),
                            "asn": int(origin_asn),
                            "prefix": str(prefix),
                            "event_type": "announce",
                            "upstream_as": int(upstream_asn),
                            "path": [int(p) for p in path if isinstance(p, int)],
                            "community": communities,
                        }
                    )
            return events
        except (KeyError, ValueError, TypeError) as e:
            logger.debug("parse_error error=%s", e)
            return None

    async def _flush_bgp_batch(self, batch: list[dict], source_label: str) -> None:
        if not batch:
            return
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda b=batch: self._ch_execute_sync(
                    "INSERT INTO bgp_events (timestamp, asn, prefix, event_type, upstream_as, path, community) VALUES",
                    b,
                ),
            )
        except Exception as e:
            logger.error("bgp_flush_error source=%s error=%s", source_label, e)

    async def simulate_bgp_stream(self) -> None:
        """Simulates a continuous stream of BGP updates."""
        logger.info("bgp_simulation_start")
        while self.running:
            batch = []
            for _ in range(random.randint(1, 10)):
                asn = random.choice(self.watched_asns)
                event_type = random.choice(["announce", "withdraw"])
                prefix = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"

                event = {
                    "timestamp": datetime.now(),
                    "asn": asn,
                    "prefix": prefix,
                    "event_type": event_type,
                    "upstream_as": random.choice(self.watched_asns),
                    "path": [asn, random.choice(self.watched_asns)],
                    "community": [65000 + random.randint(1, 100)],
                }
                batch.append(event)

            if batch:
                try:
                    await self._flush_bgp_batch(batch, "SIM")
                except Exception as e:
                    logger.error("bgp_sim_write_error error=%s", e)

            await asyncio.sleep(random.uniform(0.5, 2.0))

    async def simulate_threat_intel_feed(self) -> None:
        """Simulates fetching threat intelligence feeds every 30 seconds."""
        logger.info("threat_sim_start")
        while self.running:
            logger.debug("threat_sim_cycle")
            bad_asn = 666

            threat_event = [
                {
                    "timestamp": datetime.now(),
                    "asn": bad_asn,
                    "source": "simulated_feed",
                    "category": "spam",
                    "target_ip": "1.2.3.4",
                    "description": "detected spam emission",
                }
            ]

            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None,
                    lambda te=threat_event: self._ch_execute_sync(
                        "INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES",
                        te,
                    ),
                )
                logger.info("threat_sim_logged asn=%s", bad_asn)

                self.redis_client.lpush("scoring_queue", bad_asn)

            except Exception as e:
                logger.error("threat_sim_error error=%s", e)

            await asyncio.sleep(30)

    async def fetch_threat_intelligence(self) -> None:
        """Fetches REAL Threat Intel Feeds and correlates them. Runs every 6 hours."""
        import re
        import ipaddress

        logger.info("threat_intel_start")

        while self.running:
            try:
                threat_prefixes: set[str] = set()
                threat_ips: set[str] = set()
                stats = {"spamhaus": 0, "cins": 0, "urlhaus": 0}

                # Source 1: Spamhaus DROP
                try:
                    logger.info("threat_fetch source=spamhaus")
                    r = requests.get(
                        "https://www.spamhaus.org/drop/drop.txt", timeout=15
                    )
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            if line.strip() and not line.startswith(";"):
                                parts = line.split(";")
                                if parts:
                                    p = parts[0].strip()
                                    threat_prefixes.add(p)
                                    stats["spamhaus"] += 1
                except Exception as e:
                    logger.warning("threat_fetch_failed source=spamhaus error=%s", e)

                # Source 2: CINS Army
                try:
                    logger.info("threat_fetch source=cins")
                    r = requests.get(
                        "https://cinsscore.com/list/ci-badguys.txt", timeout=15
                    )
                    if r.status_code == 200:
                        for line in r.text.splitlines():
                            ip = line.strip()
                            if ip:
                                threat_ips.add(ip)
                                stats["cins"] += 1
                except Exception as e:
                    logger.warning("threat_fetch_failed source=cins error=%s", e)

                # Source 3: URLHaus
                try:
                    logger.info("threat_fetch source=urlhaus")
                    r = requests.get(
                        "https://urlhaus.abuse.ch/downloads/text_online/", timeout=15
                    )
                    if r.status_code == 200:
                        found_ips = re.findall(
                            r"http://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", r.text
                        )
                        for ip in found_ips:
                            threat_ips.add(ip)
                            stats["urlhaus"] += 1
                except Exception as e:
                    logger.warning("threat_fetch_failed source=urlhaus error=%s", e)

                logger.info(
                    "threat_fetch_complete stats=%s networks=%s ips=%s",
                    stats,
                    len(threat_prefixes),
                    len(threat_ips),
                )

                # Correlate with Active BGP view
                query = """
                SELECT prefix, argMax(asn, timestamp) as asn
                FROM bgp_events
                WHERE timestamp > now() - INTERVAL 1 HOUR
                GROUP BY prefix
                """
                active_routes = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: self._ch_execute_sync(query)
                )

                logger.info(
                    "threat_correlation_start threats=%s routes=%s",
                    len(threat_prefixes) + len(threat_ips),
                    len(active_routes),
                )

                found_threats = 0

                bad_networks_obj = []
                for tp in threat_prefixes:
                    try:
                        bad_networks_obj.append(ipaddress.ip_network(tp))
                    except ValueError:
                        pass

                for route_prefix, route_asn in active_routes:
                    try:
                        source_match = None

                        if route_prefix in threat_prefixes:
                            source_match = "Spamhaus (Exact)"

                        if not source_match:
                            net_addr = route_prefix.split("/")[0]
                            if net_addr in threat_ips:
                                source_match = "CINS/URLHaus (NetAddr Match)"

                        if not source_match:
                            route_net = ipaddress.ip_network(route_prefix)
                            for bad_net in bad_networks_obj:
                                if bad_net.overlaps(route_net):
                                    source_match = "Spamhaus (Overlap)"
                                    break

                        if source_match:
                            threat_event = [
                                {
                                    "timestamp": datetime.now(),
                                    "asn": route_asn,
                                    "source": source_match,
                                    "category": "botnet/malware",
                                    "target_ip": route_prefix,
                                    "description": f"{source_match} detection on {route_prefix}",
                                }
                            ]

                            _loop = asyncio.get_running_loop()
                            _fut = _loop.run_in_executor(
                                None,
                                lambda te=threat_event: self._ch_execute_sync(
                                    "INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES",
                                    te,
                                ),
                            )
                            _fut.add_done_callback(
                                lambda f: logger.warning("ch_threat_insert_failed error=%s", f.exception()) if f.exception() else None
                            )
                            self.celery_app.send_task(
                                "tasks.calculate_asn_score", args=[route_asn]
                            )
                            found_threats += 1

                    except (ValueError, TypeError):
                        continue

                    if found_threats % 100 == 0 and found_threats > 0:
                        await asyncio.sleep(0)

                logger.info("threat_correlation_complete flagged=%s", found_threats)

            except Exception as e:
                logger.error("threat_intel_error error=%s", e)

            await asyncio.sleep(21600)

    async def scan_noisy_neighbors(self) -> None:
        """Periodically scans for high-volume ASNs and queues them for scoring."""
        logger.info("scanner_start")
        while self.running:
            try:
                query = """
                SELECT asn
                FROM bgp_events
                WHERE timestamp > now() - INTERVAL 1 MINUTE
                GROUP BY asn
                HAVING count() > 5
                LIMIT 50
                """
                rows = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: self._ch_execute_sync(query)
                )

                if rows:
                    logger.info("scanner_found active_asns=%s", len(rows))
                    for row in rows:
                        asn = row[0]
                        self.celery_app.send_task(
                            "tasks.calculate_asn_score", args=[asn]
                        )

            except Exception as e:
                logger.error("scanner_error error=%s", e)

            await asyncio.sleep(10)

    async def detect_route_leaks(self) -> None:
        """[The Guard] - Route Leak Hunter. Runs every 5 minutes."""
        logger.info("guard_start")

        TIER_1_ASNS = {
            3356,
            1299,
            174,
            2914,
            3257,
            6453,
            3491,
            701,
            1239,
            7018,
            6461,
            5511,
            3549,
        }

        while self.running:
            try:
                query = """
                SELECT DISTINCT asn, prefix
                FROM bgp_events
                WHERE timestamp > now() - INTERVAL 5 MINUTE
                  AND event_type = 'announce'
                """
                rows = await asyncio.get_running_loop().run_in_executor(
                    None, lambda: self._ch_execute_sync(query)
                )

                leaks_found = 0
                for row in rows:
                    asn, prefix = row

                    try:
                        if "/" in prefix:
                            cidr = int(prefix.split("/")[1])

                            if cidr <= 10 and asn not in TIER_1_ASNS:
                                description = f"Route Leak Risk: Non-Tier1 ASN {asn} announced huge block {prefix}."
                                logger.warning(
                                    "route_leak asn=%s prefix=%s", asn, prefix
                                )

                                threat_event = [
                                    {
                                        "timestamp": datetime.now(),
                                        "asn": asn,
                                        "source": "Route Leak Guard",
                                        "category": "route_leak",
                                        "target_ip": prefix,
                                        "description": description,
                                    }
                                ]

                                _loop = asyncio.get_running_loop()
                                _fut = _loop.run_in_executor(
                                    None,
                                    lambda te=threat_event: self.ch_client.execute(
                                        "INSERT INTO threat_events (timestamp, asn, source, category, target_ip, description) VALUES",
                                        te,
                                    ),
                                )
                                _fut.add_done_callback(
                                    lambda f: logger.warning("ch_leak_insert_failed error=%s", f.exception()) if f.exception() else None
                                )
                                self.celery_app.send_task(
                                    "tasks.calculate_asn_score", args=[asn]
                                )
                                leaks_found += 1

                    except (ValueError, TypeError):
                        continue

                if leaks_found > 0:
                    logger.info("guard_cycle_complete leaks=%s", leaks_found)

            except Exception as e:
                logger.error("guard_error error=%s", e)

            await asyncio.sleep(300)

    async def start(self) -> None:
        logger.info("ingestor_starting")
        while True:
            try:
                self._ch_execute_sync("SELECT 1")
                self.redis_client.ping()
                logger.info("dependencies_online")
                break
            except Exception as e:
                logger.warning("waiting_for_deps error=%s", e)
                await asyncio.sleep(2)

        task3 = asyncio.create_task(self.connect_ripe_ris())
        task4 = asyncio.create_task(self.scan_noisy_neighbors())
        task5 = asyncio.create_task(self.fetch_threat_intelligence())
        task6 = asyncio.create_task(self.detect_route_leaks())

        await asyncio.gather(task3, task4, task5, task6)


if __name__ == "__main__":
    ingestor = DataIngestor()
    asyncio.run(ingestor.start())
