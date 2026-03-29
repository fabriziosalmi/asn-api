# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)
#
# Load testing for ASN Risk API using Locust.
#
# Usage:
#   pip install locust
#   locust -f tests/load/locustfile.py --host http://localhost:8080
#
# Headless mode:
#   locust -f tests/load/locustfile.py --host http://localhost:8080 \
#     --users 50 --spawn-rate 5 --run-time 60s --headless

import os
import random

from locust import HttpUser, task, between, tag


API_KEY = os.getenv("API_KEY", "dev-secret")
HEADERS = {"X-API-Key": API_KEY}

# ASNs to test with (mix of well-known and random)
KNOWN_ASNS = [15169, 13335, 2914, 174, 3356, 8075, 16509, 32934, 20940, 45102]


class ASNApiUser(HttpUser):
    """Simulates a typical API consumer."""

    wait_time = between(0.5, 2.0)

    @tag("health")
    @task(1)
    def health_check(self):
        self.client.get("/health")

    @tag("score")
    @task(10)
    def get_asn_score(self):
        asn = random.choice(KNOWN_ASNS)
        self.client.get(f"/v1/asn/{asn}", headers=HEADERS, name="/v1/asn/[asn]")

    @tag("score")
    @task(3)
    def get_asn_score_random(self):
        asn = random.randint(1, 100000)
        self.client.get(f"/v1/asn/{asn}", headers=HEADERS, name="/v1/asn/[asn]")

    @tag("history")
    @task(5)
    def get_asn_history(self):
        asn = random.choice(KNOWN_ASNS)
        days = random.choice([7, 14, 30])
        self.client.get(
            f"/v1/asn/{asn}/history?days={days}&limit=50",
            headers=HEADERS,
            name="/v1/asn/[asn]/history",
        )

    @tag("upstreams")
    @task(3)
    def get_upstreams(self):
        asn = random.choice(KNOWN_ASNS)
        self.client.get(
            f"/v1/asn/{asn}/upstreams",
            headers=HEADERS,
            name="/v1/asn/[asn]/upstreams",
        )

    @tag("bulk")
    @task(1)
    def bulk_check(self):
        asns = random.sample(KNOWN_ASNS, k=min(5, len(KNOWN_ASNS)))
        self.client.post(
            "/v1/tools/bulk-risk-check",
            headers=HEADERS,
            json={"asns": asns},
            name="/v1/tools/bulk-risk-check",
        )


class CacheStressUser(HttpUser):
    """Hammers the same ASN to test cache performance."""

    wait_time = between(0.1, 0.3)
    weight = 1  # Lower weight than main user

    @task
    def cached_score(self):
        self.client.get("/v1/asn/15169", headers=HEADERS, name="/v1/asn/[cached]")
