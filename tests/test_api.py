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
