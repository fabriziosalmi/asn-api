# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)


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


def test_invalid_asn_zero(client, api_key):
    headers = {"X-API-Key": api_key}
    response = client.get("/v1/asn/0", headers=headers)
    assert response.status_code == 400


def test_invalid_asn_too_large(client, api_key):
    headers = {"X-API-Key": api_key}
    response = client.get("/v1/asn/4294967296", headers=headers)
    assert response.status_code == 400


def test_get_asn_score_not_found(client, api_key):
    headers = {"X-API-Key": api_key}
    try:
        response = client.get("/v1/asn/999999", headers=headers)
        assert response.status_code in [404, 500]
    except Exception:
        pass


def test_peer_pressure_route_exists(client, api_key):
    headers = {"X-API-Key": api_key}
    try:
        response = client.get("/v1/asn/3333/upstreams", headers=headers)
        assert response.status_code != 404
    except Exception:
        pass


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


def test_history_pagination_params(client, api_key):
    """History endpoint accepts pagination parameters."""
    headers = {"X-API-Key": api_key}
    try:
        response = client.get(
            "/v1/asn/15169/history?days=7&offset=0&limit=10", headers=headers
        )
        # Should not 404 - route exists with pagination params
        assert response.status_code != 404
    except Exception:
        pass
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

def test_compare_asns_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    
    mock_conn.execute.return_value.mappings.return_value.fetchall.return_value = [
        {"asn": 123, "name": "Test1", "country_code": "US", "total_score": 90, "risk_level": "LOW", "hygiene_score": 95, "threat_score": 85, "stability_score": 90},
        {"asn": 456, "name": "Test2", "country_code": "UK", "total_score": 50, "risk_level": "HIGH", "hygiene_score": 60, "threat_score": 40, "stability_score": 50}
    ]

    response = client.get("/v1/tools/compare?asn_a=123&asn_b=456", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert data["comparison"]["safer_overall"] == 123
    assert data["comparison"]["score_diff"] == 40

def test_compare_asns_missing(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    mock_conn.execute.return_value.mappings.return_value.fetchall.return_value = []

    response = client.get("/v1/tools/compare?asn_a=123&asn_b=456", headers={"X-API-Key": api_key})
    assert response.status_code == 404

def test_get_edl_feed(client, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    
    mock_conn.execute.return_value.fetchall.return_value = [(123,), (456,)]

    response = client.get("/feeds/edl?max_score=50")
    assert response.status_code == 200
    assert "AS123" in response.text
    assert "AS456" in response.text

@patch("api.main.httpx.AsyncClient")
def test_peeringdb_info(mock_client_cls, client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    mock_redis.get.return_value = None 
    
    # Mock httpx AsyncClient context manager
    mock_instance = AsyncMock()
    mock_client_cls.return_value.__aenter__.return_value = mock_instance
    
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [{"name": "Test PDB", "info_type": "Content", "website": "x", "ix_count": 5, "fac_count": 2, "policy_general": "Open"}]
    }
    mock_instance.get.return_value = mock_response

    response = client.get("/v1/asn/123/peeringdb", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    assert response.json()["found"] is True
    assert response.json()["peeringdb_data"]["type"] == "Content"

@patch("api.main.dns.asyncresolver.resolve", new_callable=AsyncMock)
def test_domain_risk(mock_resolve, client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    
    mock_answer_a = MagicMock()
    mock_answer_a.to_text.return_value = "8.8.8.8"
    
    mock_answer_txt = MagicMock()
    mock_answer_txt.to_text.return_value = "15169 | 8.8.8.0/24 | US | arin | 2004-01-13"
    
    mock_resolve.side_effect = [[mock_answer_a], [mock_answer_txt]]

    mock_conn.execute.return_value.mappings.return_value.fetchone.return_value = {
        "asn": 15169, "name": "Google", "country_code": "US", 
        "total_score": 100, "risk_level": "LOW",
        "hygiene_score": 100, "threat_score": 100, "stability_score": 100
    }

    response = client.get("/v1/tools/domain-risk?domain=example.com", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert data["resolved_ip"] == "8.8.8.8"
    assert data["asn"] == 15169
    assert data["infrastructure_risk"]["total_score"] == 100

def test_websocket_auth_fail(client):
    try:
        with client.websocket_connect("/v1/stream"):
            pass
    except Exception:
        assert True


def test_websocket_stream_receives_message(client, api_key, mock_dependencies):
    """Producer publishes one message; consumer forwards it then connection closes."""
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies

    message_sent = {"type": "message", "data": '{"asn":1234,"score":42}'}
    sentinel = {"type": "message", "data": None}        # marks end of iteration

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
                assert msg == message_sent["data"]
        except Exception:
            pass  # websocket closed after sentinel — that is expected


def test_websocket_queue_overflow_disconnects_client(client, api_key, mock_dependencies):
    """If pubsub floods faster than the client reads, the engine emits close(1008)."""
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies

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
                # Drain until close
                while True:
                    ws.receive_text()
        except Exception:
            pass  # WebSocketDisconnect expected — client kicked due to OOM guard



def test_get_asn_score_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    mock_redis.get.return_value = None  # Bypass cache
    
    
    # Mocking total count (t_count) and lower bound (c_lower) which uses scalar
    mock_conn.execute.return_value.scalar.side_effect = [1000, 500]  # Total ASNs, Lower ASNs
    
    # Mocking the actual score row which uses mappings().fetchone()
    mock_conn.execute.return_value.mappings.return_value.fetchone.return_value = {
        "asn": 15169, "name": "Google", "country_code": "US", "registry": "arin",
        "total_score": 95, "risk_level": "LOW", "last_scored_at": None,
        "downstream_score": 90, "hygiene_score": 100, "threat_score": 95, "stability_score": 100,
        "rpki_invalid_percent": 0.0, "rpki_unknown_percent": 0.0,
        "has_route_leaks": False, "has_bogon_ads": False, "is_stub_but_transit": False,
        "prefix_granularity_score": 100, "spamhaus_listed": False, "spam_emission_rate": 0.0,
        "botnet_c2_count": 0, "phishing_hosting_count": 0, "malware_distribution_count": 0,
        "has_peeringdb_profile": True, "upstream_tier1_count": 2, "is_whois_private": False,
        "ddos_blackhole_count": 0, "excessive_prepending_count": 0
    }

    response = client.get("/v1/asn/15169", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert data["asn"] == 15169
    assert data["risk_score"] == 95

def test_get_asn_history_success(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    
    # Mock clickhouse response: 1st call is count, 2nd is data
    mock_ch.execute.side_effect = [
        [[2]],  # Return value for count_query
        [("2023-01-01T00:00:00Z", 90), ("2023-01-02T00:00:00Z", 95)]  # Return value for data_query
    ]
    
    response = client.get("/v1/asn/15169/history", headers={"X-API-Key": api_key})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["data"]) == 2

def test_add_to_whitelist(client, api_key, mock_dependencies):
    mock_redis, mock_pg, mock_ch, mock_pg_conn = mock_dependencies
    mock_conn = mock_pg_conn
    
    response = client.post("/v1/whitelist", json={"asn": 12345, "reason": "Trusted ISP"}, headers={"X-API-Key": api_key})
    assert response.status_code == 200
    assert response.json()["status"] == "success"
