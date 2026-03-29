# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import os
import json
import time
import hashlib
import logging
import urllib.parse
from datetime import datetime
from fastapi import FastAPI, HTTPException, Security, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from clickhouse_driver import Client
from typing import List, Optional, Dict
import redis.asyncio as aioredis
import asyncio

# Logging - structured format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("asn_api")

app = FastAPI(
    title="ASN Risk API",
    version="7.0.0",
    description="""
    ## Autonomous System Risk Scoring API

    This API provides real-time risk assessment for Internet Autonomous Systems (ASNs).
    It aggregates signals from **BGP Routing**, **Threat Intelligence**, and **Historical Stability** to calculate a trust score (0-100).

    ### Key Features
    * **Risk Score**: 0 (Malicious) to 100 (Trusted).
    * **Breakdown**: Hygiene, Threat, and Stability components.
    * **History**: 30-day trend analysis.
    """,
    openapi_tags=[
        {"name": "Scoring", "description": "Core risk assessment endpoints."},
        {"name": "Analytics", "description": "Historical data and trends."},
        {"name": "System", "description": "Health checks and metadata."},
    ],
)

# CORS - configurable allowed origins
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
API_KEY_NAME = "X-API-Key"
API_KEY = os.getenv("API_SECRET_KEY")

if not API_KEY:
    raise RuntimeError(
        "CRITICAL: API_SECRET_KEY environment variable is missing. Halting execution for security."
    )

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)


async def get_api_key(
    request: Request, api_key_header: str = Security(api_key_header)
):
    if not api_key_header or api_key_header != API_KEY:
        client_ip = request.client.host if request.client else "unknown"
        logger.warning("auth_failure ip=%s", client_ip)
        raise HTTPException(status_code=403, detail="Invalid or Missing API Key")
    return api_key_header


# Database Connections - unified env var naming
PG_USER = os.getenv("POSTGRES_USER")
PG_PASS = os.getenv("POSTGRES_PASSWORD")
PG_HOST = os.getenv("DB_META_HOST", "db-metadata")
PG_DB = os.getenv("POSTGRES_DB", "asn_registry")
CH_HOST = os.getenv("DB_TS_HOST", "db-timeseries")
CH_USER = os.getenv("CLICKHOUSE_USER", "default")
CH_PASS = os.getenv("CLICKHOUSE_PASSWORD", "")

if not PG_USER or not PG_PASS:
    raise RuntimeError(
        "CRITICAL: POSTGRES_USER and POSTGRES_PASSWORD must be set."
    )

PG_PASS_SAFE = urllib.parse.quote_plus(PG_PASS)

pg_engine = create_engine(
    f"postgresql://{PG_USER}:{PG_PASS_SAFE}@{PG_HOST}/{PG_DB}",
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
)
ch_client = Client(host=CH_HOST, user=CH_USER, password=CH_PASS)

# Async Redis
REDIS_HOST = os.getenv("REDIS_HOST", "broker-cache")
redis_client: aioredis.Redis = aioredis.Redis(
    host=REDIS_HOST, port=6379, decode_responses=True, socket_timeout=2
)
CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))

# Rate limiting Lua script - atomic INCR + EXPIRE
RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

# Valid ASN range (32-bit)
ASN_MIN = 1
ASN_MAX = 4294967295


# --- Models ---
class HygieneSignals(BaseModel):
    rpki_invalid_percent: float = 0.0
    rpki_unknown_percent: float = 0.0
    has_route_leaks: bool = False
    has_bogon_ads: bool = False
    is_stub_but_transit: bool = False
    prefix_granularity_score: Optional[int] = None


class ThreatSignals(BaseModel):
    spamhaus_listed: bool = False
    spam_emission_rate: float = 0.0
    botnet_c2_count: int = 0
    phishing_hosting_count: int = 0
    malware_distribution_count: int = 0


class MetadataSignals(BaseModel):
    has_peeringdb_profile: bool = False
    upstream_tier1_count: int = 0
    is_whois_private: bool = False


class ForensicsSignals(BaseModel):
    ddos_blackhole_count: int = 0
    excessive_prepending_count: int = 0


class AllSignals(BaseModel):
    hygiene: HygieneSignals
    threats: ThreatSignals
    metadata: MetadataSignals
    forensics: ForensicsSignals


class PenaltyDetail(BaseModel):
    code: str
    severity: str
    description: str
    action: str


class RiskScoreResponse(BaseModel):
    asn: int
    name: Optional[str] = "Unknown"
    country_code: Optional[str] = None
    registry: Optional[str] = None
    risk_score: int
    risk_level: str
    rank_percentile: Optional[float] = None
    downstream_score: Optional[int] = None
    last_updated: str
    breakdown: Dict[str, int]
    signals: AllSignals
    details: List[PenaltyDetail] = []


class HistoryPoint(BaseModel):
    timestamp: str
    score: int


class UpstreamPeer(BaseModel):
    asn: int
    name: Optional[str] = None
    score: int
    risk_level: str
    connection_count: int


class PeerPressureResponse(BaseModel):
    asn: int
    risk_score: int
    avg_upstream_score: int
    upstreams: List[UpstreamPeer]


class WhitelistRequest(BaseModel):
    asn: int = Field(..., ge=ASN_MIN, le=ASN_MAX)
    reason: str = Field(..., min_length=1, max_length=500)


class BulkAnalysisRequest(BaseModel):
    asns: List[int] = Field(..., max_length=1000)


class ErrorResponse(BaseModel):
    error: str
    request_id: Optional[str] = None


# --- Helpers ---


def _validate_asn(asn: int) -> None:
    if not (ASN_MIN <= asn <= ASN_MAX):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid ASN: must be between {ASN_MIN} and {ASN_MAX}",
        )


def _stable_etag(value: str) -> str:
    return f'W/"{hashlib.sha256(value.encode()).hexdigest()[:16]}"'


# --- Routes ---


@app.middleware("http")
async def add_response_time(request: Request, call_next):
    start_time = time.time()
    cache_hit = False
    error_msg = ""

    # Generate Trace ID
    trace_id = request.headers.get(
        "X-Trace-ID", f"{int(time.time())}-{os.urandom(4).hex()}"
    )

    # Rate Limiting (atomic via Lua script)
    client_ip = request.client.host if request.client else "0.0.0.0"
    rate_limit_key = f"rl:{client_ip}"
    limit = int(os.getenv("API_RATE_LIMIT", "100"))
    window = 60

    try:
        current = await redis_client.eval(
            RATE_LIMIT_SCRIPT, 1, rate_limit_key, window
        )
        remaining = max(0, limit - current)

        if current > limit:
            ttl = await redis_client.ttl(rate_limit_key)
            return Response(
                content=json.dumps(
                    {"error": f"Rate limit exceeded. Try again in {ttl} seconds."}
                ),
                status_code=429,
                media_type="application/json",
                headers={
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + ttl),
                    "X-Trace-ID": trace_id,
                },
            )
    except Exception as e:
        logger.error("rate_limit_error trace_id=%s error=%s", trace_id, e)
        remaining = limit - 1

    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    # Standard headers
    response.headers["X-Response-Time"] = f"{process_time:.2f}ms"
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window)
    response.headers["X-Trace-ID"] = trace_id

    # Extract details for logging
    endpoint = request.url.path
    method = request.method
    status_code = response.status_code

    if hasattr(request.state, "cache_hit"):
        cache_hit = request.state.cache_hit

    # Log to ClickHouse asynchronously (non-blocking, fire-and-forget)
    if endpoint.startswith("/v1/asn"):
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            None,
            lambda: ch_client.execute(
                """INSERT INTO api_requests
            (timestamp, endpoint, method, status_code, response_time_ms, cache_hit, client_ip, error_message)
            VALUES""",
                [
                    (
                        datetime.now(),
                        endpoint,
                        method,
                        status_code,
                        process_time,
                        1 if cache_hit else 0,
                        client_ip,
                        error_msg,
                    )
                ],
            ),
        )

    return response


# --- System endpoints (no version prefix) ---


@app.get("/", tags=["System"])
def read_root():
    return {
        "service": "asn-api",
        "version": "7.0.0",
        "endpoints": ["/v1/asn/{asn}", "/v1/asn/{asn}/history"],
    }


@app.get("/health", tags=["System"])
def health_check():
    """Combined Health Check - returns status of all dependencies."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "7.0.0",
        "dependencies": {"postgres": "down", "clickhouse": "down", "redis": "down"},
    }

    try:
        with pg_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            health["dependencies"]["postgres"] = "up"

        ch_client.execute("SELECT 1")
        health["dependencies"]["clickhouse"] = "up"

        # Sync ping for health check is acceptable
        import redis as sync_redis

        sync_r = sync_redis.Redis(host=REDIS_HOST, port=6379, socket_timeout=1)
        sync_r.ping()
        sync_r.close()
        health["dependencies"]["redis"] = "up"

    except Exception as e:
        health["status"] = "degraded"
        logger.error("health_check_failed error=%s", e)

    if all(v == "up" for v in health["dependencies"].values()):
        return health
    else:
        return Response(
            content=json.dumps(health), status_code=503, media_type="application/json"
        )


# --- V1 API endpoints ---


def generate_penalty_details(result: dict) -> List[PenaltyDetail]:
    """Generate structured explanations for detected risk signals."""
    details = []

    def add(code, sev, desc, action):
        details.append(
            PenaltyDetail(code=code, severity=sev, description=desc, action=action)
        )

    rpki_invalid = float(result.get("rpki_invalid_percent") or 0)
    if rpki_invalid > 1.0:
        add(
            "RPKI_INVALID",
            "HIGH",
            f"{rpki_invalid:.1f}% of routes have INVALID RPKI status",
            "Review ROA configuration for advertised prefixes.",
        )

    rpki_unknown = float(result.get("rpki_unknown_percent") or 0)
    if rpki_unknown > 50:
        add(
            "RPKI_UNKNOWN",
            "MEDIUM",
            f"{rpki_unknown:.1f}% routes have NO ROA (Unknown)",
            "Create ROAs to protect your prefixes from hijacking.",
        )

    if result.get("has_route_leaks"):
        add(
            "ROUTE_LEAK",
            "HIGH",
            "Valley-free violation detected",
            "Investigate BGP filters for accidental transit leakage.",
        )

    if result.get("has_bogon_ads"):
        add(
            "BOGON_AD",
            "MEDIUM",
            "Advertising bogon/reserved prefixes",
            "Filter private/reserved ranges from EBGP sessions.",
        )

    if result.get("is_stub_but_transit"):
        add(
            "STUB_TRANSIT",
            "MEDIUM",
            "Stub ASN acting as transit",
            "Verify if you are unintentionally providing transit to peers.",
        )

    if result.get("spamhaus_listed"):
        add(
            "THREAT_SPAMHAUS",
            "CRITICAL",
            "Listed on Spamhaus DROP/EDROP",
            "Immediate removal required. Contact Spamhaus.",
        )

    spam_rate = float(result.get("spam_emission_rate") or 0)
    if spam_rate > 0.1:
        add(
            "THREAT_SPAM",
            "HIGH",
            f"High spam emission rate ({spam_rate:.3f})",
            "Audit customer networks for compromised hosts.",
        )

    botnet_count = result.get("botnet_c2_count") or 0
    if botnet_count > 0:
        add(
            "THREAT_BOTNET",
            "CRITICAL",
            f"Hosting {botnet_count} Botnet C2 servers",
            "Identify and terminate C2 infrastructure immediately.",
        )

    phishing_count = result.get("phishing_hosting_count") or 0
    if phishing_count > 0:
        add(
            "THREAT_PHISHING",
            "HIGH",
            f"Hosting {phishing_count} phishing domains",
            "Take down reported phishing sites.",
        )

    malware_count = result.get("malware_distribution_count") or 0
    if malware_count > 0:
        add(
            "THREAT_MALWARE",
            "CRITICAL",
            f"Hosting {malware_count} malware distribution points",
            "Isolate infected hosts and remediate.",
        )

    if result.get("is_whois_private"):
        add(
            "META_PRIVATE",
            "LOW",
            "WHOIS information is private",
            "Update RIR records with valid contact info.",
        )

    if not result.get("has_peeringdb_profile"):
        add(
            "META_NO_PDB",
            "LOW",
            "No PeeringDB profile",
            "Create a PeeringDB profile to improve visibility/trust.",
        )

    tier1_count = result.get("upstream_tier1_count") or 0
    if tier1_count == 0:
        add(
            "META_NO_TIER1",
            "MEDIUM",
            "No direct Tier-1 upstream",
            "Consider acquiring transit from a Tier-1 provider for better reachability/trust.",
        )

    return details


@app.get("/v1/asn/{asn}", response_model=RiskScoreResponse, tags=["Scoring"])
async def get_asn_score(
    asn: int, response: Response, request: Request, api_key: str = Depends(get_api_key)
):
    """
    **Get the detailed risk score card for a specific ASN.**
    Requires API Key.
    """
    _validate_asn(asn)

    cache_key = f"score:v3:{asn}"
    try:
        cached = await redis_client.get(cache_key)
        if cached:
            request.state.cache_hit = True
            data = json.loads(cached)
            etag = _stable_etag(data["last_updated"])
            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304)

            response.headers["ETag"] = etag
            response.headers["Cache-Control"] = f"public, max-age={CACHE_TTL}"
            return data

        request.state.cache_hit = False
    except Exception as e:
        logger.error("cache_read_error asn=%s error=%s", asn, e)
        request.state.cache_hit = False

    query = text("""
        SELECT r.asn, r.name, r.country_code, r.registry,
               r.total_score, r.risk_level, r.last_scored_at, r.downstream_score,
               r.hygiene_score, r.threat_score, r.stability_score,
               s.rpki_invalid_percent, s.rpki_unknown_percent,
               s.has_route_leaks, s.has_bogon_ads, s.is_stub_but_transit,
               s.prefix_granularity_score,
               s.spamhaus_listed, s.spam_emission_rate,
               s.botnet_c2_count, s.phishing_hosting_count, s.malware_distribution_count,
               s.has_peeringdb_profile, s.upstream_tier1_count, s.is_whois_private,
               s.ddos_blackhole_count, s.excessive_prepending_count
        FROM asn_registry r
        LEFT JOIN asn_signals s ON r.asn = s.asn
        WHERE r.asn = :asn
    """)

    with pg_engine.connect() as conn:
        result = conn.execute(query, {"asn": asn}).mappings().fetchone()

        if not result:
            raise HTTPException(status_code=404, detail="ASN not found or not yet scored")

        result = dict(result)

        score = result["total_score"]

        cache_key_total = "stats:asn_total_count"
        try:
            total_count = await redis_client.get(cache_key_total)
            if total_count:
                total_count = int(total_count)
            else:
                total_count = conn.execute(
                    text("SELECT count(*) FROM asn_registry")
                ).scalar()
                await redis_client.setex(cache_key_total, 300, total_count)
        except Exception:
            total_count = conn.execute(
                text("SELECT count(*) FROM asn_registry")
            ).scalar()

        rank_query = text(
            "SELECT count(*) FROM asn_registry WHERE total_score < :score"
        )
        count_lower = conn.execute(rank_query, {"score": score}).scalar()

        percentile = 0.0
        if total_count > 0:
            percentile = (count_lower / total_count) * 100.0

        level = result["risk_level"]
        if level == "UNKNOWN":
            level = (
                "CRITICAL"
                if score < 50
                else "HIGH"
                if score < 75
                else "MEDIUM"
                if score < 90
                else "LOW"
            )

        details = generate_penalty_details(result)

        response_data = {
            "asn": result["asn"],
            "name": result["name"],
            "country_code": result["country_code"],
            "registry": result["registry"],
            "risk_score": score,
            "risk_level": level,
            "rank_percentile": round(percentile, 1),
            "downstream_score": result.get("downstream_score"),
            "last_updated": str(result["last_scored_at"]),
            "breakdown": {
                "hygiene": result["hygiene_score"],
                "threat": result["threat_score"],
                "stability": result["stability_score"],
            },
            "signals": {
                "hygiene": {
                    "rpki_invalid_percent": float(
                        result["rpki_invalid_percent"] or 0
                    ),
                    "rpki_unknown_percent": float(
                        result["rpki_unknown_percent"] or 0
                    ),
                    "has_route_leaks": result["has_route_leaks"] or False,
                    "has_bogon_ads": result["has_bogon_ads"] or False,
                    "is_stub_but_transit": result["is_stub_but_transit"] or False,
                    "prefix_granularity_score": result["prefix_granularity_score"],
                },
                "threats": {
                    "spamhaus_listed": result["spamhaus_listed"] or False,
                    "spam_emission_rate": float(
                        result["spam_emission_rate"] or 0
                    ),
                    "botnet_c2_count": result["botnet_c2_count"] or 0,
                    "phishing_hosting_count": result["phishing_hosting_count"] or 0,
                    "malware_distribution_count": result["malware_distribution_count"]
                    or 0,
                },
                "metadata": {
                    "has_peeringdb_profile": result["has_peeringdb_profile"]
                    or False,
                    "upstream_tier1_count": result["upstream_tier1_count"] or 0,
                    "is_whois_private": result["is_whois_private"] or False,
                },
                "forensics": {
                    "ddos_blackhole_count": result.get("ddos_blackhole_count") or 0,
                    "excessive_prepending_count": result.get(
                        "excessive_prepending_count"
                    )
                    or 0,
                },
            },
            "details": [d.model_dump() for d in details],
        }

        try:
            await redis_client.setex(cache_key, CACHE_TTL, json.dumps(response_data))
        except Exception as e:
            logger.error("cache_write_error asn=%s error=%s", asn, e)

        etag = _stable_etag(response_data["last_updated"])
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = f"public, max-age={CACHE_TTL}"

        return response_data


@app.get(
    "/v1/asn/{asn}/history", response_model=List[HistoryPoint], tags=["Analytics"]
)
async def get_asn_history(
    asn: int,
    days: int = 30,
    api_key: str = Depends(get_api_key),
):
    """
    **Get the historical score trend for charting.**
    Requires API Key.

    Parameters:
    * `days`: Number of days of history to retrieve (default: 30, max: 365)
    """
    _validate_asn(asn)
    days = min(days, 365)

    query = """
    SELECT
        timestamp,
        score
    FROM asn_score_history
    WHERE asn = %(asn)s
    ORDER BY timestamp DESC
    LIMIT %(limit)s
    """
    params = {"asn": asn, "limit": days * 24}
    try:
        data = ch_client.execute(query, params)
        return [{"timestamp": str(ts), "score": int(score)} for ts, score in data]
    except Exception as e:
        logger.error("history_query_error asn=%s error=%s", asn, e)
        return []


@app.post("/v1/whitelist", tags=["System"])
async def add_to_whitelist(
    req: WhitelistRequest, api_key: str = Depends(get_api_key)
):
    """Whitelist an ASN to exclude it from risk scoring. Requires API Key."""
    try:
        with pg_engine.connect() as conn:
            conn.execute(
                text("""
                INSERT INTO asn_whitelist (asn, reason)
                VALUES (:asn, :reason)
                ON CONFLICT (asn) DO UPDATE SET reason = :reason
            """),
                {"asn": req.asn, "reason": req.reason},
            )
            conn.commit()
        logger.info("whitelist_add asn=%s reason=%s", req.asn, req.reason)
        return {"status": "success", "message": f"ASN {req.asn} added to whitelist."}
    except Exception as e:
        logger.error("whitelist_error asn=%s error=%s", req.asn, e)
        raise HTTPException(status_code=500, detail="Failed to update whitelist")


@app.post("/v1/tools/bulk-risk-check", tags=["Scoring"])
async def bulk_risk_check(
    req: BulkAnalysisRequest, api_key: str = Depends(get_api_key)
):
    """
    **Bulk check multiple ASNs at once.**
    Useful for Supply Chain Risk analysis.
    Returns current known scores. Does not trigger new scoring for speed.
    """
    if len(req.asns) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 ASNs per request")

    query = text("""
        SELECT asn, total_score, risk_level, name
        FROM asn_registry
        WHERE asn = ANY(:asns)
    """)

    results = []
    with pg_engine.connect() as conn:
        rows = conn.execute(query, {"asns": req.asns}).mappings().fetchall()
        row_map = {r["asn"]: r for r in rows}

        for asn_id in req.asns:
            if asn_id in row_map:
                r = row_map[asn_id]
                results.append(
                    {
                        "asn": asn_id,
                        "score": r["total_score"],
                        "level": r["risk_level"],
                        "name": r["name"],
                    }
                )
            else:
                results.append(
                    {
                        "asn": asn_id,
                        "score": None,
                        "level": "UNKNOWN",
                        "name": "Unknown",
                    }
                )

    return {"results": results}


@app.get(
    "/v1/asn/{asn}/upstreams",
    response_model=PeerPressureResponse,
    tags=["Scoring"],
)
async def get_peer_pressure(asn: int, api_key: str = Depends(get_api_key)):
    """
    **"Peer Pressure" Analysis: Upstream Risk Assessment**

    Evaluates the risk of the ASN's upstream providers.
    """
    _validate_asn(asn)

    query_upstreams = """
    SELECT upstream_as, count(*) as c
    FROM bgp_events
    WHERE asn = %(asn)s AND upstream_as != 0 AND timestamp > now() - INTERVAL 30 DAY
    GROUP BY upstream_as ORDER BY c DESC LIMIT 5
    """
    try:
        upstreams_raw = ch_client.execute(query_upstreams, {"asn": asn})
    except Exception as e:
        logger.error("upstream_query_error asn=%s error=%s", asn, e)
        raise HTTPException(status_code=500, detail="Metrics database unavailable")

    upstream_ids = [u[0] for u in upstreams_raw]

    if not upstream_ids:
        return {
            "asn": asn,
            "risk_score": 0,
            "avg_upstream_score": 0,
            "upstreams": [],
        }

    upstreams_data = []
    with pg_engine.connect() as conn:
        my_score_res = conn.execute(
            text("SELECT total_score FROM asn_registry WHERE asn = :asn"), {"asn": asn}
        ).fetchone()
        my_score = my_score_res[0] if my_score_res else 0

        res = conn.execute(
            text(
                "SELECT asn, name, total_score, risk_level FROM asn_registry WHERE asn = ANY(:asns)"
            ),
            {"asns": upstream_ids},
        ).mappings().fetchall()

        score_map = {r["asn"]: r for r in res}
        total_ups_score = 0

        for u_row in upstreams_raw:
            u_asn, count = u_row
            if u_asn in score_map:
                r = score_map[u_asn]
                upstreams_data.append(
                    {
                        "asn": u_asn,
                        "name": r["name"],
                        "score": r["total_score"],
                        "risk_level": r["risk_level"],
                        "connection_count": count,
                    }
                )
                total_ups_score += r["total_score"]
            else:
                upstreams_data.append(
                    {
                        "asn": u_asn,
                        "name": "Unknown",
                        "score": 50,
                        "risk_level": "UNKNOWN",
                        "connection_count": count,
                    }
                )
                total_ups_score += 50

    avg_score = int(total_ups_score / len(upstreams_data)) if upstreams_data else 0

    return {
        "asn": asn,
        "risk_score": my_score,
        "avg_upstream_score": avg_score,
        "upstreams": upstreams_data,
    }


# --- Backward compatibility redirects ---
# Keep old routes working during migration to /v1/


@app.get("/asn/{asn}", response_model=RiskScoreResponse, tags=["Scoring"], include_in_schema=False)
async def get_asn_score_compat(asn: int, response: Response, request: Request, api_key: str = Depends(get_api_key)):
    return await get_asn_score(asn, response, request, api_key)


@app.get("/asn/{asn}/history", response_model=List[HistoryPoint], tags=["Analytics"], include_in_schema=False)
async def get_asn_history_compat(asn: int, days: int = 30, api_key: str = Depends(get_api_key)):
    return await get_asn_history(asn, days, api_key)


@app.post("/whitelist", tags=["System"], include_in_schema=False)
async def add_to_whitelist_compat(req: WhitelistRequest, api_key: str = Depends(get_api_key)):
    return await add_to_whitelist(req, api_key)


@app.post("/tools/bulk-risk-check", tags=["Scoring"], include_in_schema=False)
async def bulk_risk_check_compat(req: BulkAnalysisRequest, api_key: str = Depends(get_api_key)):
    return await bulk_risk_check(req, api_key)


@app.get("/asn/{asn}/upstreams", response_model=PeerPressureResponse, tags=["Scoring"], include_in_schema=False)
async def get_peer_pressure_compat(asn: int, api_key: str = Depends(get_api_key)):
    return await get_peer_pressure(asn, api_key)
