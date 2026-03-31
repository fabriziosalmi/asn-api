# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import json
import time
import orjson
import httpx
import socket
import dns.asyncresolver
import ipaddress
import hashlib
from cachetools import TTLCache
import logging
import urllib.parse
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Security, Depends, Request, Response, Query, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi.responses import ORJSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine
from clickhouse_driver import Client
from typing import List, Optional, Dict
import redis.asyncio as aioredis
import asyncio
import os

from pythonjsonlogger.json import JsonFormatter as JsonLogFormatter

from api_settings import Settings

# --- Configuration (validated) ---
settings = Settings()

# --- Local L1 Memory Cache ---
# Used for super-fast reads before asking Redis (L2)
# Max 5,000 items, TTL is set dynamically during insertion based on settings.cache_ttl
l1_cache = TTLCache(maxsize=5000, ttl=settings.cache_ttl)

# --- Structured JSON Logging ---
_log_handler = logging.StreamHandler()
if settings.log_format == "json":
    _log_handler.setFormatter(
        JsonLogFormatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s",
            rename_fields={"asctime": "timestamp", "levelname": "level"},
        )
    )
logging.basicConfig(level=getattr(logging, settings.log_level), handlers=[_log_handler])
logger = logging.getLogger("asn_api")

# --- Database Connections ---
PG_PASS_SAFE = urllib.parse.quote_plus(settings.postgres_password)

pg_engine = create_async_engine(
    f"postgresql+asyncpg://{settings.postgres_user}:{PG_PASS_SAFE}@{settings.db_meta_host}/{settings.postgres_db}",
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
)
ch_client = Client(
    host=settings.db_ts_host,
    user=settings.clickhouse_user,
    password=settings.clickhouse_password,
)
# Dedicated thread pool for ClickHouse (clickhouse-driver is sync-only).
# All CH calls MUST go through _ch_execute() so exceptions surface instead of
# being silently swallowed by fire-and-forget executors.
_ch_pool = __import__('concurrent.futures', fromlist=['ThreadPoolExecutor']).ThreadPoolExecutor(
    max_workers=settings.db_pool_size, thread_name_prefix="ch"
)

async def _ch_execute(query: str, params=None):
    """Run a sync ClickHouse query in the dedicated thread pool.
    Raises on error — callers decide whether to propagate or catch."""
    loop = asyncio.get_running_loop()
    fn = lambda: ch_client.execute(query, params) if params is not None else ch_client.execute(query)
    return await loop.run_in_executor(_ch_pool, fn)

# --- Async Redis ---
redis_client: aioredis.Redis = aioredis.Redis(
    host=settings.redis_host, port=6379, decode_responses=True, socket_timeout=2
)

# --- Rate Limiting Lua Script (Sliding Window Log) ---
RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local window_secs = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

local time = redis.call('TIME')
local now_ms = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local clear_before = now_ms - (window_secs * 1000)

redis.call('ZREMRANGEBYSCORE', key, 0, clear_before)
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    local member = now_ms .. '-' .. time[2]
    redis.call('ZADD', key, now_ms, member)
    redis.call('PEXPIRE', key, window_secs * 1000)
    return current_count + 1
else
    return current_count + 1
end
"""

# --- Constants ---
ASN_MIN = 1
ASN_MAX = 4294967295
API_VERSION = "7.3.0"


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("startup", extra={"version": API_VERSION})
    yield
    await redis_client.aclose()
    logger.info("shutdown")


# --- App ---
app = FastAPI(
    title="ASN Risk API",
    version=API_VERSION,
    default_response_class=ORJSONResponse,
    description="""
    ## Autonomous System Risk Scoring API

    Real-time risk assessment for Internet Autonomous Systems (ASNs).
    Aggregates signals from **BGP Routing**, **Threat Intelligence**, and **Historical Stability**.

    ### Key Features
    * **Risk Score**: 0 (Malicious) to 100 (Trusted).
    * **Breakdown**: Hygiene, Threat, and Stability components.
    * **History**: Up to 365-day trend analysis with pagination.
    """,
    openapi_tags=[
        {"name": "Scoring", "description": "Core risk assessment endpoints."},
        {"name": "Analytics", "description": "Historical data and trends."},
        {"name": "System", "description": "Health checks and metadata."},
    ],
    lifespan=lifespan,
)

# --- CORS & Compression ---
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Observability: Metrics (Prometheus) ---
Instrumentator().instrument(app).expose(app)

# --- Security ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(request: Request, api_key_header: str = Security(api_key_header)):
    if not api_key_header or api_key_header != settings.api_secret_key:
        client_ip = request.client.host if request.client else "unknown"
        logger.warning("auth_failure", extra={"ip": client_ip})
        raise HTTPException(status_code=403, detail="Invalid or Missing API Key")
    return api_key_header


# --- Error Envelope ---
class ErrorEnvelope(BaseModel):
    error: str
    code: str
    request_id: Optional[str] = None


def error_response(
    status_code: int, code: str, message: str, request_id: str = ""
) -> ORJSONResponse:
    return ORJSONResponse(
        status_code=status_code,
        content=ErrorEnvelope(
            error=message, code=code, request_id=request_id
        ).model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    trace_id = getattr(request.state, "trace_id", "")
    return error_response(
        exc.status_code, f"HTTP_{exc.status_code}", str(exc.detail), trace_id
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    trace_id = getattr(request.state, "trace_id", "")
    logger.error("unhandled_exception", extra={"trace_id": trace_id, "error": str(exc)})
    return error_response(
        500, "INTERNAL_ERROR", "An unexpected error occurred", trace_id
    )


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


class PaginatedHistory(BaseModel):
    asn: int
    total: int
    offset: int
    limit: int
    data: List[HistoryPoint]


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


# --- Helpers ---


def _validate_asn(asn: int) -> None:
    if not (ASN_MIN <= asn <= ASN_MAX):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid ASN: must be between {ASN_MIN} and {ASN_MAX}",
        )


def _stable_etag(value: str) -> str:
    return f'W/"{hashlib.sha256(value.encode()).hexdigest()[:16]}"'


# --- Middleware ---


@app.middleware("http")
async def request_middleware(request: Request, call_next):
    start_time = time.time()

    # Trace ID
    trace_id = request.headers.get(
        "X-Trace-ID", f"{int(time.time())}-{os.urandom(4).hex()}"
    )
    request.state.trace_id = trace_id
    request.state.cache_hit = False

    # Rate Limiting (atomic)
    client_ip = request.client.host if request.client else "0.0.0.0"
    rate_limit_key = f"rl:{client_ip}"
    window = 60

    try:
        current = await redis_client.eval(
            RATE_LIMIT_SCRIPT, 
            1, 
            rate_limit_key, 
            window, 
            settings.api_rate_limit
        )
        remaining = max(0, settings.api_rate_limit - current)

        if current > settings.api_rate_limit:
            ttl = await redis_client.ttl(rate_limit_key)
            return ORJSONResponse(
                status_code=429,
                content=ErrorEnvelope(
                    error=f"Rate limit exceeded. Try again in {ttl} seconds.",
                    code="RATE_LIMITED",
                    request_id=trace_id,
                ).model_dump(),
                headers={
                    "X-RateLimit-Limit": str(settings.api_rate_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + ttl),
                    "X-Trace-ID": trace_id,
                    "Retry-After": str(ttl),
                },
            )
    except Exception as e:
        logger.error("rate_limit_error", extra={"trace_id": trace_id, "error": str(e)})
        remaining = settings.api_rate_limit - 1

    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    # Standard headers
    response.headers["X-Response-Time"] = f"{process_time:.2f}ms"
    response.headers["X-RateLimit-Limit"] = str(settings.api_rate_limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window)
    response.headers["X-Trace-ID"] = trace_id

    # Async ClickHouse request logging (fire-and-forget with error logging)
    endpoint = request.url.path
    if endpoint.startswith("/v1/asn"):
        cache_hit = getattr(request.state, "cache_hit", False)

        async def _log_to_ch() -> None:
            try:
                await _ch_execute(
                    """INSERT INTO api_requests
                    (timestamp, endpoint, method, status_code, response_time_ms, cache_hit, client_ip, error_message)
                    VALUES""",
                    [
                        (
                            datetime.now(),
                            endpoint,
                            request.method,
                            response.status_code,
                            process_time,
                            1 if cache_hit else 0,
                            client_ip,
                            "",
                        )
                    ],
                )
            except Exception as exc:
                logger.warning("ch_request_log_failed", extra={"error": str(exc)})

        asyncio.create_task(_log_to_ch())

    return response


# =====================================================================
# SYSTEM ENDPOINTS
# =====================================================================


@app.get("/", tags=["System"])
def read_root():
    return {
        "service": "asn-api",
        "version": API_VERSION,
        "endpoints": [
            "/v1/asn/{asn}",
            "/v1/asn/{asn}/history",
            "/v1/asn/{asn}/upstreams",
        ],
    }


@app.get("/health", tags=["System"])
async def health_check():
    """Combined Health Check - returns status of all dependencies."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": API_VERSION,
        "dependencies": {"postgres": "down", "clickhouse": "down", "redis": "down"},
    }

    try:
        async with pg_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
            health["dependencies"]["postgres"] = "up"
        await _ch_execute("SELECT 1")
        health["dependencies"]["clickhouse"] = "up"
        import redis as sync_redis

        sync_r = sync_redis.Redis(host=settings.redis_host, port=6379, socket_timeout=1)
        sync_r.ping()
        sync_r.close()
        health["dependencies"]["redis"] = "up"
    except Exception as e:
        health["status"] = "degraded"
        logger.error("health_check_failed", extra={"error": str(e)})

    if all(v == "up" for v in health["dependencies"].values()):
        return health
    return Response(
        content=orjson.dumps(health), status_code=503, media_type="application/json"
    )


# =====================================================================
# V1 API ENDPOINTS
# =====================================================================


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
            "Consider acquiring transit from a Tier-1 provider.",
        )

    return details


@app.get("/v1/asn/{asn}", response_model=RiskScoreResponse, tags=["Scoring"])
async def get_asn_score(
    asn: int, response: Response, request: Request, api_key: str = Depends(get_api_key)
):
    """Get the detailed risk score card for a specific ASN."""
    _validate_asn(asn)
    trace_id = getattr(request.state, "trace_id", "")

    cache_key = f"score:v3:{asn}"
    
    # Check L1 cache (In-memory)
    cached_l1 = l1_cache.get(cache_key)
    if cached_l1:
        request.state.cache_hit = True
        response.headers["X-Cache-Tier"] = "L1"
        etag = _stable_etag(cached_l1["last_updated"])
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304)
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = f"public, max-age={settings.cache_ttl}"
        return cached_l1

    try:
        # Check L2 cache (Redis)
        cached = await redis_client.get(cache_key)
        if cached:
            request.state.cache_hit = True
            response.headers["X-Cache-Tier"] = "L2"
            data = orjson.loads(cached)
            # Hydrate L1
            l1_cache[cache_key] = data
            
            etag = _stable_etag(data["last_updated"])
            if request.headers.get("if-none-match") == etag:
                return Response(status_code=304)
            response.headers["ETag"] = etag
            response.headers["Cache-Control"] = f"public, max-age={settings.cache_ttl}"
            return data
        request.state.cache_hit = False
    except Exception as e:
        logger.error(
            "cache_read_error",
            extra={"asn": asn, "trace_id": trace_id, "error": str(e)},
        )
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

    cache_key_total = "stats:asn_total_count"
    try:
        total_count_cached = await redis_client.get(cache_key_total)
    except Exception:
        total_count_cached = None

    async def _fetch_db_data():
        async with pg_engine.begin() as conn:
            result = await conn.execute(query, {"asn": asn})
            row = result.mappings().fetchone()
            if not row:
                return None
            
            r_dict = dict(row)
            score = r_dict["total_score"]
            
            if total_count_cached:
                t_count = int(total_count_cached)
            else:
                t_count_res = await conn.execute(text("SELECT count(*) FROM asn_registry"))
                t_count = t_count_res.scalar()
            
            c_lower_res = await conn.execute(
                text("SELECT count(*) FROM asn_registry WHERE total_score < :score"),
                {"score": score},
            )
            c_lower = c_lower_res.scalar()
            
            return r_dict, t_count, c_lower

    db_res = await _fetch_db_data()
    
    if not db_res:
        raise HTTPException(status_code=404, detail="ASN not found or not yet scored")
        
    result, total_count, count_lower = db_res
    score = result["total_score"]

    if not total_count_cached and total_count:
        try:
            await redis_client.setex(cache_key_total, 300, total_count)
        except Exception:
            pass

    percentile = (count_lower / total_count * 100.0) if total_count > 0 else 0.0

    level = result["risk_level"]
    if level == "UNKNOWN":
        level = (
            "CRITICAL"
            if score < 50
            else "HIGH" if score < 75 else "MEDIUM" if score < 90 else "LOW"
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
                "rpki_invalid_percent": float(result["rpki_invalid_percent"] or 0),
                "rpki_unknown_percent": float(result["rpki_unknown_percent"] or 0),
                "has_route_leaks": result["has_route_leaks"] or False,
                "has_bogon_ads": result["has_bogon_ads"] or False,
                "is_stub_but_transit": result["is_stub_but_transit"] or False,
                "prefix_granularity_score": result["prefix_granularity_score"],
            },
            "threats": {
                "spamhaus_listed": result["spamhaus_listed"] or False,
                "spam_emission_rate": float(result["spam_emission_rate"] or 0),
                "botnet_c2_count": result["botnet_c2_count"] or 0,
                "phishing_hosting_count": result["phishing_hosting_count"] or 0,
                "malware_distribution_count": result["malware_distribution_count"]
                or 0,
            },
            "metadata": {
                "has_peeringdb_profile": result["has_peeringdb_profile"] or False,
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
        await redis_client.setex(
            cache_key, settings.cache_ttl, orjson.dumps(response_data)
        )
        # Sync to L1 Memory Cache
        l1_cache[cache_key] = response_data
    except Exception as e:
        logger.error("cache_write_error", extra={"asn": asn, "error": str(e)})

    etag = _stable_etag(response_data["last_updated"])
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = f"public, max-age={settings.cache_ttl}"

    return response_data


@app.get("/v1/asn/{asn}/history", response_model=PaginatedHistory, tags=["Analytics"])
async def get_asn_history(
    asn: int,
    days: int = 30,
    offset: int = 0,
    limit: int = 200,
    api_key: str = Depends(get_api_key),
):
    """
    **Get the historical score trend with pagination.**

    Parameters:
    * `days`: Number of days of history (default: 30, max: 365)
    * `offset`: Skip first N records (default: 0)
    * `limit`: Max records to return (default: 200, max: 1000)
    """
    _validate_asn(asn)
    days = min(days, 365)
    limit = min(limit, 1000)
    offset = max(offset, 0)

    count_query = """
    SELECT count(*)
    FROM asn_score_history
    WHERE asn = %(asn)s AND timestamp > now() - INTERVAL %(days)s DAY
    """
    data_query = """
    SELECT timestamp, score
    FROM asn_score_history
    WHERE asn = %(asn)s AND timestamp > now() - INTERVAL %(days)s DAY
    ORDER BY timestamp DESC
    LIMIT %(limit)s OFFSET %(offset)s
    """
    params = {"asn": asn, "days": days, "limit": limit, "offset": offset}

    try:
        total_res = await _ch_execute(count_query, {"asn": asn, "days": days})
        total = total_res[0][0]
        data = await _ch_execute(data_query, params)
        return {
            "asn": asn,
            "total": total,
            "offset": offset,
            "limit": limit,
            "data": [{"timestamp": str(ts), "score": int(score)} for ts, score in data],
        }
    except Exception as e:
        logger.error("history_query_error", extra={"asn": asn, "error": str(e)})
        raise HTTPException(status_code=503, detail="Metrics database unavailable")


@app.post("/v1/whitelist", tags=["System"])
async def add_to_whitelist(
    req: WhitelistRequest, request: Request, api_key: str = Depends(get_api_key)
):
    """Whitelist an ASN to exclude it from risk scoring."""
    trace_id = getattr(request.state, "trace_id", "")
    try:
        async with pg_engine.begin() as conn:
            await conn.execute(
                text("""
                INSERT INTO asn_whitelist (asn, reason)
                VALUES (:asn, :reason)
                ON CONFLICT (asn) DO UPDATE SET reason = :reason
            """),
                {"asn": req.asn, "reason": req.reason},
            )
            # pg_engine.begin() auto-commits on context exit — explicit commit removed

        # Invalidate cache for this ASN
        await redis_client.delete(f"score:v3:{req.asn}")

        logger.info(
            "whitelist_add",
            extra={"asn": req.asn, "reason": req.reason, "trace_id": trace_id},
        )
        return {"status": "success", "message": f"ASN {req.asn} added to whitelist."}
    except Exception as e:
        logger.error(
            "whitelist_error",
            extra={"asn": req.asn, "error": str(e), "trace_id": trace_id},
        )
        raise HTTPException(status_code=500, detail="Failed to update whitelist")


@app.get("/v1/tools/compare", tags=["Scoring"])
async def compare_asns(
    asn_a: int = Query(..., description="First ASN to compare"),
    asn_b: int = Query(..., description="Second ASN to compare"),
    api_key: str = Depends(get_api_key)
):
    """
    Compare two ASNs side-by-side to understand relative risk profiles.
    Returns a delta indicating which ASN is safer across different dimensions.
    """
    if asn_a <= 0 or asn_a > 4294967295 or asn_b <= 0 or asn_b > 4294967295:
        raise HTTPException(status_code=400, detail="Invalid ASN number")

    query = text("""
        SELECT r.asn, r.name, r.country_code,
               r.total_score, r.risk_level, 
               r.hygiene_score, r.threat_score, r.stability_score
        FROM asn_registry r
        WHERE r.asn IN (:asn_a, :asn_b)
    """)

    async with pg_engine.begin() as conn:
        result = await conn.execute(query, {"asn_a": asn_a, "asn_b": asn_b})
        rows = result.mappings().fetchall()
    
    if len(rows) != 2:
        found_asns = [r["asn"] for r in rows]
        missing = [a for a in (asn_a, asn_b) if a not in found_asns]
        raise HTTPException(status_code=404, detail=f"ASNs not found: {missing}")

    # Map results
    data_a = next(r for r in rows if r["asn"] == asn_a)
    data_b = next(r for r in rows if r["asn"] == asn_b)

    return {
        "asn_a": dict(data_a),
        "asn_b": dict(data_b),
        "comparison": {
            "safer_overall": asn_a if data_a["total_score"] > data_b["total_score"] else (asn_b if data_b["total_score"] > data_a["total_score"] else None),
            "score_diff": abs(data_a["total_score"] - data_b["total_score"]),
            "better_hygiene": asn_a if data_a["hygiene_score"] > data_b["hygiene_score"] else (asn_b if data_b["hygiene_score"] > data_a["hygiene_score"] else None),
            "better_threat_profile": asn_a if data_a["threat_score"] > data_b["threat_score"] else (asn_b if data_b["threat_score"] > data_a["threat_score"] else None),
            "more_stable": asn_a if data_a["stability_score"] > data_b["stability_score"] else (asn_b if data_b["stability_score"] > data_a["stability_score"] else None),
        }
    }


@app.post("/v1/tools/bulk-risk-check", tags=["Scoring"])
async def bulk_risk_check(
    req: BulkAnalysisRequest, api_key: str = Depends(get_api_key)
):
    """Bulk check multiple ASNs at once. Max 1000 ASNs per request."""
    if len(req.asns) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 ASNs per request")

    query = text("""
        SELECT asn, total_score, risk_level, name
        FROM asn_registry
        WHERE asn = ANY(:asns)
    """)

    results = []
    async with pg_engine.begin() as conn:
        result = await conn.execute(query, {"asns": req.asns})
        rows = result.mappings().fetchall()
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

    return {"results": results, "total": len(results)}


@app.get(
    "/v1/asn/{asn}/upstreams", response_model=PeerPressureResponse, tags=["Scoring"]
)
async def get_peer_pressure(asn: int, api_key: str = Depends(get_api_key)):
    """Upstream Risk Assessment - evaluates the risk of upstream providers."""
    _validate_asn(asn)

    query_upstreams = """
    SELECT upstream_as, count(*) as c
    FROM bgp_events
    WHERE asn = %(asn)s AND upstream_as != 0 AND timestamp > now() - INTERVAL 30 DAY
    GROUP BY upstream_as ORDER BY c DESC LIMIT 5
    """
    try:
        upstreams_raw = await _ch_execute(query_upstreams, {"asn": asn})
    except Exception as e:
        logger.error("upstream_query_error", extra={"asn": asn, "error": str(e)})
        raise HTTPException(status_code=503, detail="Metrics database unavailable")

    upstream_ids = [u[0] for u in upstreams_raw]

    if not upstream_ids:
        return {"asn": asn, "risk_score": 0, "avg_upstream_score": 0, "upstreams": []}

    upstreams_data = []
    async with pg_engine.begin() as conn:
        result = await conn.execute(
            text("SELECT total_score FROM asn_registry WHERE asn = :asn"), {"asn": asn}
        )
        my_score_res = result.fetchone()
        my_score = my_score_res[0] if my_score_res else 0

        _res = await conn.execute(
            text(
                "SELECT asn, name, total_score, risk_level FROM asn_registry WHERE asn = ANY(:asns)"
            ),
            {"asns": upstream_ids},
        )
        res = _res.mappings().fetchall()

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


# =====================================================================
# CACHE INVALIDATION ENDPOINT (internal, used by scorer)
# =====================================================================


@app.delete("/v1/internal/cache/{asn}", tags=["System"], include_in_schema=False)
async def invalidate_cache(asn: int, api_key: str = Depends(get_api_key)):
    """Called by the scoring engine after score updates to bust stale cache."""
    deleted = await redis_client.delete(f"score:v3:{asn}")
    return {"invalidated": bool(deleted)}


# =====================================================================
# BACKWARD COMPATIBILITY (hidden from docs)
# =====================================================================


@app.get(
    "/asn/{asn}",
    response_model=RiskScoreResponse,
    tags=["Scoring"],
    include_in_schema=False,
)
async def get_asn_score_compat(
    asn: int, response: Response, request: Request, api_key: str = Depends(get_api_key)
):
    return await get_asn_score(asn, response, request, api_key)


@app.get("/asn/{asn}/history", tags=["Analytics"], include_in_schema=False)
async def get_asn_history_compat(
    asn: int,
    days: int = 30,
    offset: int = 0,
    limit: int = 200,
    api_key: str = Depends(get_api_key),
):
    return get_asn_history(asn, days, offset, limit, api_key)


@app.post("/whitelist", tags=["System"], include_in_schema=False)
async def add_to_whitelist_compat(
    req: WhitelistRequest, request: Request, api_key: str = Depends(get_api_key)
):
    return await add_to_whitelist(req, request, api_key)


@app.post("/tools/bulk-risk-check", tags=["Scoring"], include_in_schema=False)
def bulk_risk_check_compat(
    req: BulkAnalysisRequest, api_key: str = Depends(get_api_key)
):
    return bulk_risk_check(req, api_key)


@app.get(
    "/asn/{asn}/upstreams",
    response_model=PeerPressureResponse,
    tags=["Scoring"],
    include_in_schema=False,
)
def get_peer_pressure_compat(asn: int, api_key: str = Depends(get_api_key)):
    return get_peer_pressure(asn, api_key)

@app.get("/feeds/edl", tags=["Integrations"])
async def get_edl_feed(max_score: float = Query(50.0, ge=0.0, le=100.0)):
    """
    Feed for Firewalls (Palo Alto EDL, Fortinet, etc).
    Returns a plaintext list of ASNs (ASXXXX) below the maximum given risk score.
    """
    try:
        from fastapi.responses import PlainTextResponse
        
        async def _fetch_edl():
            async with pg_engine.begin() as conn:
                result = await conn.execute(
                    text("SELECT asn FROM asn_registry WHERE total_score <= :max_score ORDER BY asn ASC"),
                    {"max_score": max_score}
                )
                rows = result.fetchall()
                return [f"AS{row[0]}" for row in rows]
                
        edl_lines = await _fetch_edl()
        return PlainTextResponse("\n".join(edl_lines))
    except Exception as e:
        logger.error(f"edl_generation_error: {e}")
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("", status_code=500)
@app.websocket("/v1/stream")
async def websocket_firehose(websocket: WebSocket, api_key: str = Query(...)):
    """
    Real-time firehose of ASN score updates over WebSocket.

    Architecture: bounded asyncio.Queue + producer/consumer task split.
    - QUEUE_MAX: max messages buffered per connection; excess drops the client (OOM guard).
    - SEND_TIMEOUT: force-disconnect stalled clients that can't drain their TCP buffer in time.
    - HEARTBEAT_INTERVAL: periodic ping to reap zombie connections (silent disconnects).
    """
    await websocket.accept()
    if not api_key:
        await websocket.close(code=1008)
        return

    QUEUE_MAX = 100
    SEND_TIMEOUT = 5.0
    HEARTBEAT_INTERVAL = 30.0

    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("events:asn_updates")

    async def _producer() -> None:
        """Read from Redis pubsub and push into the bounded queue."""
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    if queue.full():
                        # Client cannot keep up — poison the queue so consumer exits.
                        await queue.put(None)
                        return
                    await queue.put(message["data"])
        except Exception:
            await queue.put(None)

    async def _consumer() -> None:
        """Drain the queue to the WebSocket with per-send timeout and heartbeat."""
        loop = asyncio.get_event_loop()
        last_ping = loop.time()
        while True:
            now = loop.time()
            if now - last_ping >= HEARTBEAT_INTERVAL:
                await asyncio.wait_for(
                    websocket.send_json({"type": "ping"}), timeout=SEND_TIMEOUT
                )
                last_ping = now
            try:
                data = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
            except asyncio.TimeoutError:
                continue  # nothing in queue; loop back to send heartbeat
            if data is None:
                # Poison pill from producer (overflow or error) — close cleanly.
                await websocket.close(code=1008)
                return
            await asyncio.wait_for(
                websocket.send_text(data), timeout=SEND_TIMEOUT
            )

    producer_task = asyncio.create_task(_producer())
    try:
        await _consumer()
    except (WebSocketDisconnect, asyncio.TimeoutError):
        logger.info("ws_firehose_disconnect")
    finally:
        producer_task.cancel()
        await pubsub.unsubscribe("events:asn_updates")


@app.get("/v1/asn/{asn}/peeringdb", tags=["Enrichment"])
async def get_peeringdb_info(asn: int, api_key: str = Depends(get_api_key)):
    """
    Fetch and cache PeeringDB metadata for a given ASN.
    Provides business context like ASN Type (ISP, Content), IXP presence, and Facilities.
    """
    cache_key = f"peeringdb:asn:{asn}"
    try:
        # Check cache First
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            return orjson.loads(cached_data)

        # Fetch from PeeringDB (no auth required for public data)
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://www.peeringdb.com/api/net?asn={asn}")
            
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Upstream PeeringDB error")
                
            data = resp.json()
            
            if not data.get("data"):
                result = {"asn": asn, "found": False, "peeringdb_data": None}
            else:
                pdb = data["data"][0]
                result = {
                    "asn": asn,
                    "found": True,
                    "peeringdb_data": {
                        "name": pdb.get("name"),
                        "type": pdb.get("info_type"),
                        "website": pdb.get("website"),
                        "ix_count": pdb.get("ix_count", 0),
                        "fac_count": pdb.get("fac_count", 0),
                        "peering_policy": pdb.get("policy_general")
                    }
                }
            
            # Cache for 24 hours
            await redis_client.setex(cache_key, 86400, orjson.dumps(result))
            return result
            
    except httpx.RequestError as e:
        logger.error(f"peeringdb_fetch_error_log", extra={"asn": asn, "error": str(e)})
        raise HTTPException(status_code=503, detail="Failed to reach PeeringDB")

@app.get("/v1/tools/domain-risk", tags=["Scoring", "Enrichment"])
async def get_domain_risk(domain: str = Query(..., description="Domain to analyze (e.g. example.com)"), api_key: str = Depends(get_api_key)):
    """
    Given a domain, this endpoint resolves its IP, finds the hosting ASN, and returns the infrastructure risk score.
    Critical for Phishing/Malware analysis and SOC investigations.
    """
    try:
        # Step 1: Resolve Domain to IP
        answers = await dns.asyncresolver.resolve(domain, 'A')
        ip_address = answers[0].to_text()
        
        # SSRF Protection
        ip_obj = ipaddress.ip_address(ip_address)
        if not ip_obj.is_global:
            raise HTTPException(status_code=400, detail="Domain resolves to a local or private IP")
            
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=400, detail=f"Could not resolve domain: {domain}")

    # Step 2: Resolve IP to ASN via Cymru
    reversed_ip = '.'.join(reversed(ip_address.split('.')))
    query_str = f"{reversed_ip}.origin.asn.cymru.com"
    
    asn = None
    try:
        answers = await dns.asyncresolver.resolve(query_str, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            # Extract ASN, handle multiple ASNs like "13335 13335" by picking the first
            asn_str = txt.split('|')[0].strip()
            asn = int(asn_str.split()[0])
            break
    except Exception as e:
        logger.warning("cymru_resolution_failed", extra={"ip": ip_address, "error": str(e)})
        
    if not asn:
        return {
            "domain": domain,
            "resolved_ip": ip_address,
            "asn": None,
            "error": "Could not map IP to an ASN"
        }

    # Step 3: Fetch Risk Data from our DB
    query_db = text("""
        SELECT r.asn, r.name, r.country_code,
               r.total_score, r.risk_level, 
               r.hygiene_score, r.threat_score, r.stability_score
        FROM asn_registry r
        WHERE r.asn = :asn
    """)

    async with pg_engine.begin() as conn:
        result = await conn.execute(query_db, {"asn": asn})
        row = result.mappings().fetchone()
    
    asn_data = dict(row) if row else {"asn": asn, "status": "Not scored yet"}

    return {
        "domain": domain,
        "resolved_ip": ip_address,
        "asn": asn,
        "infrastructure_risk": asn_data
    }
