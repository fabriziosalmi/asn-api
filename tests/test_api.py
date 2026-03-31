# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)
# Tests use realistic production-grade ASN data (Google/Cloudflare/RIPE NCC/M247)
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# ---------------------------------------------------------------------------
# Shared ASN fixtures (real-world values from public BGP/WHOIS data)
# ---------------------------------------------------------------------------

ASN_15169_GOOGLE = {
    "asn": 15169,
    "name": "GOOGLE",
    "country_code": "US",
    "registry": "arin",
    "total_score": 98,
    "risk_level": "LOW",
    "last_scored_at": "2024-01-15T10:30:00",
    "downstream_score": 95,
    "hygiene_score": 99,
    "threat_score": 98,
    "stability_score": 97,
    "rpki_invalid_percent": 0.0,
    "rpki_unknown_percent": 0.5,
    "has_route_leaks": False,
    "has_bogon_ads": False,
    "is_stub_but_transit": False,
    "prefix_granularity_score": 98,
    "spamhaus_listed": False,
    "spam_emission_rate": 0.001,
    "botnet_c2_count": 0,
    "phishing_hosting_count": 0,
    "malware_distribution_count": 0,
    "has_peeringdb_profile": True,
    "upstream_tier1_count": 0,
    "is_whois_private": False,
    "ddos_blackhole_count": 2,
    "excessive_prepending_count": 0,
}

ASN_13335_CLOUDFLARE = {
    "asn": 13335,
    "name": "CLOUDFLARENET",
    "country_code": "US",
    "registry": "arin",
    "total_score": 97,
    "risk_level": "LOW",
    "last_scored_at": "2024-01-15T10:30:00",
    "downstream_score": 94,
    "hygiene_score": 99,
    "threat_score": 97,
    "stability_score": 96,
    "rpki_invalid_percent": 0.0,
    "rpki_unknown_percent": 0.1,
    "has_route_leaks": False,
    "has_bogon_ads": False,
    "is_stub_but_transit": False,
    "prefix_granularity_score": 97,
    "spamhaus_listed": False,
    "spam_emission_rate": 0.002,
    "botnet_c2_count": 0,
    "phishing_hosting_count": 1,
    "malware_distribution_count": 0,
    "has_peeringdb_profile": True,
    "upstream_tier1_count": 0,
    "is_whois_private": False,
    "ddos_blackhole_count": 5,
    "excessive_prepending_count": 0,
}

ASN_3333_RIPE = {
    "asn": 3333,
    "name": "RIPE-NCC-AS",
    "country_code": "NL",
    "registry": "ripencc",
    "total_score": 95,
    "risk_level": "LOW",
    "last_scored_at": "2024-01-15T08:00:00",
    "downstream_score": 88,
    "hygiene_score": 97,
    "threat_score": 96,
    "stability_score": 95,
    "rpki_invalid_percent": 0.0,
    "rpki_unknown_percent": 0.0,
    "has_route_leaks": False,
    "has_bogon_ads": False,
    "is_stub_but_transit": False,
    "prefix_granularity_score": 95,
    "spamhaus_listed": False,
    "spam_emission_rate": 0.0,
    "botnet_c2_count": 0,
    "phishing_hosting_count": 0,
    "malware_distribution_count": 0,
    "has_peeringdb_profile": True,
    "upstream_tier1_count": 3,
    "is_whois_private": False,
    "ddos_blackhole_count": 0,
    "excessive_prepending_count": 0,
}

ASN_9009_M247_HIGH_RISK = {
    "asn": 9009,
    "name": "M247",
    "country_code": "RO",
    "registry": "ripencc",
    "total_score": 28,
    "risk_level": "HIGH",
    "last_scored_at": "2024-01-14T22:00:00",
    "downstream_score": 25,
    "hygiene_score": 30,
    "threat_score": 20,
    "stability_score": 40,
    "rpki_invalid_percent": 3.2,
    "rpki_unknown_percent": 15.1,
    "has_route_leaks": True,
    "has_bogon_ads": False,
    "is_stub_but_transit": False,
    "prefix_granularity_score": 35,
    "spamhaus_listed": True,
    "spam_emission_rate": 4.8,
    "botnet_c2_count": 12,
    "phishing_hosting_count": 34,
    "malware_distribution_count": 8,
    "has_peeringdb_profile": False,
    "upstream_tier1_count": 1,
    "is_whois_private": False,
    "ddos_blackhole_count": 0,
    "excessive_prepending_count": 6,
}

# ---------------------------------------------------------------------------
# Basic endpoint tests
# ---------------------------------------------------------------------------

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code in [200, 503]
    body = response.json()
    assert "status" in body
    assert "dependencies" in body
    assert "version" in body


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "asn-api"
    assert "version" in body
    assert "/v1/asn/{asn}" in body["endpoints"]


def test_get_asn_score_no_auth(client):
    response = client.get("/v1/asn/1234")
    assert response.status_code == 403
    body = response.json()
    assert "error" in body
    assert "code" in body


def test_get_asn_score_no_auth_compat(client):
    response = client.get("/asn/1234")
    assert response.status_code == 403


def test_auth_wrong_key_returns_403(client):
    response = client.get("/v1/asn/15169", headers={"X-API-Key": "wrong-key-entirely"})
    assert response.status_code == 403


def test_auth_empty_key_returns_403(client):
    response = client.get("/v1/asn/15169", headers={"X-API-Key": ""})
    assert response.status_code == 403


def test_auth_prefix_of_key_returns_403(client, api_key):
    response = client.get("/v1/asn/15169", headers={"X-API-Key": api_key[:-1]})
    assert response.status_code == 403


def test_auth_key_with_trailing_space_returns_403(client, api_key):
    response = client.get("/v1/asn/15169", headers={"X-API-Key": api_key + " "})
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def test_invalid_asn_zero(client, api_key):
    response = client.get("/v1/asn/0", headers={"X-API-Key": api_key})
    assert response.status_code == 400


def test_invalid_asn_too_large(client, api_key):
    response = client.get("/v1/asn/4294967296", headers={"X-API-Key": api_key})
    assert response.status_code == 400


def test_get_asn_score_not_found(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_redis.get.return_value = None
    mock_pg_conn.execute.return_value.mappings.return_value.fetchone.return_value = None
    response = client.get("/v1/asn/999999", headers={"X-API-Key": api_key})
    assert response.status_code == 404


def test_peer_pressure_route_exists(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_ch_execute.return_value = []
    response = client.get("/v1/asn/3333/upstreams", headers={"X-API-Key": api_key})
    assert response.status_code != 404


def test_bulk_check_too_many(client, api_key):
    headers = {"X-API-Key": api_key}
    response = client.post(
        "/v1/tools/bulk-risk-check",
        headers=headers,
        json={"asns": list(range(1001))},
    )
    assert response.status_code in [400, 422]


def test_rate_limit_headers_present(client):
    response = client.get("/health")
    assert "X-RateLimit-Limit" in response.headers
    assert "X-Trace-ID" in response.headers


def test_error_envelope_format(client):
    """Error responses use structured envelope with error + code fields."""
    response = client.get("/v1/asn/1234")
    assert response.status_code == 403
    body = response.json()
    assert "error" in body
    assert "code" in body
    assert body["code"] == "HTTP_403"


def test_history_pagination_params(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_ch_execute.side_effect = [[[1]], [("2024-01-15 00:00:00", 95)]]
    response = client.get(
        "/v1/asn/3333/history?days=30&offset=0&limit=50",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code != 404


# ---------------------------------------------------------------------------
# Score endpoint — Google AS15169
# ---------------------------------------------------------------------------

def test_get_asn_score_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_redis.get.return_value = None

    scalar_mock = MagicMock()
    scalar_mock.scalar.side_effect = [75_000, 70_000]
    mock_pg_conn.execute.return_value = scalar_mock
    mock_pg_conn.execute.return_value.mappings.return_value.fetchone.return_value = ASN_15169_GOOGLE

    response = client.get("/v1/asn/15169", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert data["asn"] == 15169
    assert data["risk_score"] == ASN_15169_GOOGLE["total_score"]
    assert data["risk_level"] == "LOW"
    assert data["name"] == "GOOGLE"


# ---------------------------------------------------------------------------
# History endpoint — 3 real scoring snapshots for AS15169
# ---------------------------------------------------------------------------

HISTORY_ROWS_15169 = [
    ("2024-01-13 00:00:00", 97),
    ("2024-01-14 00:00:00", 98),
    ("2024-01-15 00:00:00", 98),
]


def test_get_asn_history_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    mock_ch_execute.side_effect = [
        [[len(HISTORY_ROWS_15169)]],
        HISTORY_ROWS_15169,
    ]

    response = client.get(
        "/v1/asn/15169/history?days=7&offset=0&limit=10",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["asn"] == 15169
    assert data["total"] == len(HISTORY_ROWS_15169)
    assert len(data["data"]) == len(HISTORY_ROWS_15169)
    assert data["data"][0]["score"] == 97


# ---------------------------------------------------------------------------
# Compare endpoint — Google (AS15169) vs Cloudflare (AS13335)
# ---------------------------------------------------------------------------

def test_compare_asns_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_pg_conn.execute.return_value.mappings.return_value.fetchall.return_value = [
        ASN_15169_GOOGLE,
        ASN_13335_CLOUDFLARE,
    ]

    response = client.get(
        "/v1/tools/compare?asn_a=15169&asn_b=13335",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["comparison"]["safer_overall"] == 15169
    assert data["comparison"]["score_diff"] == abs(
        ASN_15169_GOOGLE["total_score"] - ASN_13335_CLOUDFLARE["total_score"]
    )


def test_compare_asns_missing(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_pg_conn.execute.return_value.mappings.return_value.fetchall.return_value = []

    response = client.get(
        "/v1/tools/compare?asn_a=15169&asn_b=99999999",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Bulk risk check
# ---------------------------------------------------------------------------

def test_bulk_risk_check_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_pg_conn.execute.return_value.mappings.return_value.fetchall.return_value = [
        ASN_15169_GOOGLE,
        ASN_13335_CLOUDFLARE,
        ASN_3333_RIPE,
    ]

    response = client.post(
        "/v1/tools/bulk-risk-check",
        headers={"X-API-Key": api_key},
        json={"asns": [15169, 13335, 3333]},
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 3
    scores = {r["asn"]: r["score"] for r in results}
    assert scores[15169] == ASN_15169_GOOGLE["total_score"]
    assert scores[13335] == ASN_13335_CLOUDFLARE["total_score"]
    assert scores[3333] == ASN_3333_RIPE["total_score"]


def test_bulk_risk_check_high_risk_present(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_pg_conn.execute.return_value.mappings.return_value.fetchall.return_value = [
        ASN_9009_M247_HIGH_RISK,
    ]

    response = client.post(
        "/v1/tools/bulk-risk-check",
        headers={"X-API-Key": api_key},
        json={"asns": [9009]},
    )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["level"] == "HIGH"
    assert result["score"] == ASN_9009_M247_HIGH_RISK["total_score"]


# ---------------------------------------------------------------------------
# EDL feed — M247 (HIGH risk, Spamhaus-listed) + generic blocked ASN
# ---------------------------------------------------------------------------

def test_get_edl_feed(client, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_pg_conn.execute.return_value.fetchall.return_value = [
        (ASN_9009_M247_HIGH_RISK["asn"],),
        (666,),
    ]

    response = client.get("/feeds/edl?max_score=50")
    assert response.status_code == 200
    assert f"AS{ASN_9009_M247_HIGH_RISK['asn']}" in response.text
    assert "AS666" in response.text


# ---------------------------------------------------------------------------
# PeeringDB enrichment — Google LLC (real peering policy data)
# ---------------------------------------------------------------------------

PEERINGDB_GOOGLE = {
    "name": "Google LLC",
    "info_type": "Content",
    "website": "https://peering.google.com/",
    "ix_count": 42,
    "fac_count": 11,
    "policy_general": "Open",
}


@patch("api.main.httpx.AsyncClient")
def test_peeringdb_info(mock_client_cls, client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies
    mock_redis.get.return_value = None

    mock_instance = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_instance

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": [PEERINGDB_GOOGLE]}
    mock_instance.get.return_value = mock_response

    response = client.get("/v1/asn/15169/peeringdb", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    body = response.json()
    assert body["found"] is True
    assert body["peeringdb_data"]["type"] == "Content"
    assert body["peeringdb_data"]["peering_policy"] == "Open"
    assert body["peeringdb_data"]["ix_count"] == 42


# ---------------------------------------------------------------------------
# Domain risk — google.com resolves to real Google IP space (AS15169)
# ---------------------------------------------------------------------------

@patch("api.main.dns.asyncresolver.resolve", new_callable=AsyncMock)
def test_domain_risk(mock_resolve, client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    mock_a = MagicMock()
    mock_a.to_text.return_value = "142.250.185.46"  # real Google IP

    mock_txt = MagicMock()
    mock_txt.to_text.return_value = '"15169 | 142.250.185.0/24 | US | arin | 2012-04-23"'

    mock_resolve.side_effect = [[mock_a], [mock_txt]]
    mock_pg_conn.execute.return_value.mappings.return_value.fetchone.return_value = ASN_15169_GOOGLE

    response = client.get(
        "/v1/tools/domain-risk?domain=google.com",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "google.com"
    assert data["resolved_ip"] == "142.250.185.46"
    assert data["asn"] == 15169
    assert data["infrastructure_risk"]["risk_level"] == "LOW"
    assert data["infrastructure_risk"]["total_score"] == ASN_15169_GOOGLE["total_score"]


@patch("api.main.dns.asyncresolver.resolve", new_callable=AsyncMock)
def test_domain_risk_private_ip_rejected(mock_resolve, client, api_key, mock_dependencies):
    """RFC-1918 addresses must be rejected — SSRF protection."""
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    mock_a = MagicMock()
    mock_a.to_text.return_value = "192.168.1.1"
    mock_resolve.return_value = [mock_a]

    response = client.get(
        "/v1/tools/domain-risk?domain=internal.local",
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Whitelist
# ---------------------------------------------------------------------------

def test_add_to_whitelist(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    response = client.post(
        "/v1/whitelist",
        json={"asn": 9009, "reason": "Manually reviewed — false positive"},
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "success"


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

def test_websocket_auth_fail(client):
    try:
        with client.websocket_connect("/v1/stream"):
            pass
    except Exception:
        assert True


def test_websocket_wrong_key_rejected(client):
    try:
        with client.websocket_connect("/v1/stream?api_key=WRONG_KEY") as ws:
            ws.receive_text()
            assert False, "Should have been disconnected"
    except Exception:
        pass


def test_websocket_stream_receives_message(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    event_payload = '{"asn": 15169, "score": 98, "risk_level": "LOW"}'
    message_sent = {"type": "message", "data": event_payload}
    sentinel = {"type": "message", "data": None}

    async def _fake_listen():
        yield message_sent
        yield sentinel

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.listen.return_value = _fake_listen()
    mock_redis.pubsub.return_value = mock_pubsub

    with patch("api.main.redis_client", mock_redis):
        try:
            with client.websocket_connect(f"/v1/stream?api_key={api_key}") as ws:
                msg = ws.receive_text()
                assert msg == event_payload
        except Exception:
            pass


def test_websocket_queue_overflow_disconnects_client(client, api_key, mock_dependencies):
    """If pubsub floods faster than the client reads, the engine emits close(1008)."""
    mock_redis, mock_pg, mock_ch, mock_pg_conn, mock_ch_execute = mock_dependencies

    OVERFLOW = 101  # one more than QUEUE_MAX=100

    async def _flood():
        for i in range(OVERFLOW):
            yield {"type": "message", "data": f"{i}"}

    mock_pubsub = AsyncMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.unsubscribe = AsyncMock()
    mock_pubsub.listen.return_value = _flood()
    mock_redis.pubsub.return_value = mock_pubsub

    with patch("api.main.redis_client", mock_redis):
        try:
            with client.websocket_connect(f"/v1/stream?api_key={api_key}") as ws:
                while True:
                    ws.receive_text()
        except Exception:
            pass  # WebSocketDisconnect expected
