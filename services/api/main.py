import os
import json
import time
import logging
from datetime import datetime
from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from clickhouse_driver import Client
from typing import List, Optional, Dict, Any
import redis

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ASN Risk API", 
    version="1.0.0",
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
        {"name": "System", "description": "Health checks and metadata."}
    ]
)

# Security
API_KEY_NAME = "X-API-Key"
API_KEY = os.getenv("API_SECRET_KEY", "dev-secret") # In prod, use .env
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def get_api_key(api_key_header: str = Security(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    # Enforce security for production readiness
    raise HTTPException(status_code=403, detail="Invalid or Missing API Key")

# Database Connections
PG_USER = os.getenv('POSTGRES_USER', 'asn_admin')
PG_PASS = os.getenv('POSTGRES_PASSWORD', 'secure_password')
PG_HOST = os.getenv('DB_HOST', 'db-metadata')
PG_DB = os.getenv('POSTGRES_DB', 'asn_registry')
CH_HOST = os.getenv('CLICKHOUSE_HOST', 'db-timeseries') # Note: Check docker-compose env var
CH_USER = os.getenv('CLICKHOUSE_USER', 'default')
CH_PASS = os.getenv('CLICKHOUSE_PASSWORD', '')

# Ensure connection strings are valid
pg_engine = create_engine(f'postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}/{PG_DB}')
ch_client = Client(host=CH_HOST, user=CH_USER, password=CH_PASS)

# Redis Cache
REDIS_HOST = os.getenv('REDIS_HOST', 'broker-cache')
redis_client = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True, socket_timeout=1)
CACHE_TTL = int(os.getenv('CACHE_TTL', 60))  # 60 seconds default

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

class AllSignals(BaseModel):
    hygiene: HygieneSignals
    threats: ThreatSignals
    metadata: MetadataSignals

class RiskScoreResponse(BaseModel):
    asn: int
    name: Optional[str] = "Unknown"
    country_code: Optional[str] = None
    registry: Optional[str] = None
    risk_score: int
    risk_level: str
    last_updated: str
    breakdown: Dict[str, int]
    signals: AllSignals
    details: List[str] = []  # Human-readable explanation of penalties

class HistoryPoint(BaseModel):
    timestamp: str
    score: int

class WhitelistRequest(BaseModel):
    asn: int
    reason: str

class BulkAnalysisRequest(BaseModel):
    asns: List[int]

# --- Routes ---

# Middleware for response time tracking and logging
@app.middleware("http")
async def add_response_time(request: Request, call_next):
    start_time = time.time()
    cache_hit = False
    error_msg = ""
    
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000  # Convert to ms
    response.headers["X-Response-Time"] = f"{process_time:.2f}ms"
    
    # Extract cache hit info from context if available
    if hasattr(request.state, 'cache_hit'):
        cache_hit = request.state.cache_hit
    
    # Log to ClickHouse asynchronously (non-blocking)
    try:
        client_ip = request.client.host if request.client else "unknown"
        endpoint = request.url.path
        method = request.method
        status_code = response.status_code
        
        # Only log API endpoints (not health checks or static)
        if endpoint.startswith("/asn"):
            ch_client.execute(
                """INSERT INTO api_requests 
                (timestamp, endpoint, method, status_code, response_time_ms, cache_hit, client_ip, error_message) 
                VALUES""",
                [(datetime.now(), endpoint, method, status_code, process_time, 1 if cache_hit else 0, client_ip, error_msg)]
            )
    except Exception as e:
        logger.error(f"Failed to log API request: {e}")
    
    return response

@app.get("/", tags=["System"])
def read_root():
    return {
        "service": "asn-api", 
        "version": "1.0.0", 
        "endpoints": [
            "/asn/{asn}",
            "/asn/{asn}/history"
        ]
    }

@app.get("/health", tags=["System"])
def health_check():
    # Simple check, ideally check DB connections
    return {"status": "healthy"}

def generate_penalty_details(result: dict) -> List[str]:
    """Generate human-readable explanations for detected risk signals."""
    details = []
    
    # Hygiene penalties
    rpki_invalid = float(result.get('rpki_invalid_percent') or 0)
    if rpki_invalid > 0:
        details.append(f"RPKI: {rpki_invalid:.1f}% of routes have INVALID RPKI status")
    
    rpki_unknown = float(result.get('rpki_unknown_percent') or 0)
    if rpki_unknown > 50:
        details.append(f"RPKI: {rpki_unknown:.1f}% of routes have UNKNOWN RPKI status (no ROA)")
    
    if result.get('has_route_leaks'):
        details.append("ROUTING: Valley-free violation detected (possible route leak)")
    
    if result.get('has_bogon_ads'):
        details.append("ROUTING: Advertising bogon/reserved prefixes")
    
    if result.get('is_stub_but_transit'):
        details.append("ROUTING: Stub ASN acting as transit (suspicious behavior)")
    
    # Threat penalties
    if result.get('spamhaus_listed'):
        details.append("THREAT: Listed on Spamhaus DROP/EDROP")
    
    spam_rate = float(result.get('spam_emission_rate') or 0)
    if spam_rate > 0.01:
        details.append(f"THREAT: High spam emission rate ({spam_rate:.3f})")
    
    botnet_count = result.get('botnet_c2_count') or 0
    if botnet_count > 0:
        details.append(f"THREAT: {botnet_count} known Botnet C2 servers hosted")
    
    phishing_count = result.get('phishing_hosting_count') or 0
    if phishing_count > 0:
        details.append(f"THREAT: {phishing_count} phishing domains hosted")
    
    malware_count = result.get('malware_distribution_count') or 0
    if malware_count > 0:
        details.append(f"THREAT: {malware_count} malware distribution points detected")
    
    # Metadata warnings
    if result.get('is_whois_private'):
        details.append("METADATA: WHOIS information is private/hidden")
    
    if not result.get('has_peeringdb_profile'):
        details.append("METADATA: No PeeringDB profile (reduces transparency)")
    
    tier1_count = result.get('upstream_tier1_count') or 0
    if tier1_count == 0:
        details.append("METADATA: No direct Tier-1 upstream (single-homed risk)")
    
    return details


@app.get("/asn/{asn}", response_model=RiskScoreResponse, tags=["Scoring"])
def get_asn_score(asn: int, request: Request, api_key: str = Depends(get_api_key)):
    """
    **Get the detailed risk score card for a specific ASN.**
    Requires API Key.
    
    Returns:
    * `risk_score`: The aggregate trust score (0-100).
    * `breakdown`: Detailed points per category (hygiene, threat, stability).
    * `signals`: Complete signal breakdown organized by category.
    * `details`: Human-readable explanation of all detected issues.
    """
    # Check cache first
    cache_key = f"score:{asn}"
    try:
        cached = redis_client.get(cache_key)
        if cached:
            logger.info(f"Cache HIT for AS{asn}")
            request.state.cache_hit = True
            return json.loads(cached)
        logger.info(f"Cache MISS for AS{asn}")
        request.state.cache_hit = False
    except Exception as e:
        logger.error(f"Cache read error for AS{asn}: {e}")
        request.state.cache_hit = False
    
    query = text("""
        SELECT r.asn, r.name, r.country_code, r.registry,
               r.total_score, r.risk_level, r.last_scored_at,
               r.hygiene_score, r.threat_score, r.stability_score,
               s.rpki_invalid_percent, s.rpki_unknown_percent,
               s.has_route_leaks, s.has_bogon_ads, s.is_stub_but_transit,
               s.prefix_granularity_score,
               s.spamhaus_listed, s.spam_emission_rate,
               s.botnet_c2_count, s.phishing_hosting_count, s.malware_distribution_count,
               s.has_peeringdb_profile, s.upstream_tier1_count, s.is_whois_private
        FROM asn_registry r
        LEFT JOIN asn_signals s ON r.asn = s.asn
        WHERE r.asn = :asn
    """)
    
    with pg_engine.connect() as conn:
        result = conn.execute(query, {'asn': asn}).mappings().fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="ASN not found or not yet scored")
        
        # Convert to dict for easier access
        result = dict(result)
        
        # Determine risk level if not set
        score = result['total_score']
        level = result['risk_level']
        if level == 'UNKNOWN':
            level = "CRITICAL" if score < 50 else "HIGH" if score < 75 else "MEDIUM" if score < 90 else "LOW"
        
        # Generate human-readable details
        details = generate_penalty_details(result)
        
        # Build response
        response_data = {
            "asn": result['asn'],
            "name": result['name'],
            "country_code": result['country_code'],
            "registry": result['registry'],
            "risk_score": score,
            "risk_level": level,
            "last_updated": str(result['last_scored_at']),
            "breakdown": {
                "hygiene": result['hygiene_score'],
                "threat": result['threat_score'],
                "stability": result['stability_score']
            },
            "signals": {
                "hygiene": {
                    "rpki_invalid_percent": float(result['rpki_invalid_percent'] or 0),
                    "rpki_unknown_percent": float(result['rpki_unknown_percent'] or 0),
                    "has_route_leaks": result['has_route_leaks'] or False,
                    "has_bogon_ads": result['has_bogon_ads'] or False,
                    "is_stub_but_transit": result['is_stub_but_transit'] or False,
                    "prefix_granularity_score": result['prefix_granularity_score']
                },
                "threats": {
                    "spamhaus_listed": result['spamhaus_listed'] or False,
                    "spam_emission_rate": float(result['spam_emission_rate'] or 0),
                    "botnet_c2_count": result['botnet_c2_count'] or 0,
                    "phishing_hosting_count": result['phishing_hosting_count'] or 0,
                    "malware_distribution_count": result['malware_distribution_count'] or 0
                },
                "metadata": {
                    "has_peeringdb_profile": result['has_peeringdb_profile'] or False,
                    "upstream_tier1_count": result['upstream_tier1_count'] or 0,
                    "is_whois_private": result['is_whois_private'] or False
                }
            },
            "details": details
        }
        
        # Cache the response
        try:
            redis_client.setex(cache_key, CACHE_TTL, json.dumps(response_data))
            logger.info(f"Cached score for AS{asn} with TTL {CACHE_TTL}s")
        except Exception as e:
            logger.error(f"Failed to cache score for AS{asn}: {e}")
        
        return response_data

@app.get("/asn/{asn}/history", response_model=List[HistoryPoint], tags=["Analytics"])
def get_asn_history(asn: int, days: int = 30, api_key: str = Depends(get_api_key)):
    """
    **Get the historical score trend for charting.**
    Requires API Key.
    
    Fetches actual score history from ClickHouse `asn_score_history` table.
    Shows how the ASN's risk score has evolved over time.
    
    Parameters:
    * `days`: Number of days of history to retrieve (default: 30, max: 365)
    """
    if days > 365:
        days = 365
    
    # Query real score history from ClickHouse
    query = f"""
    SELECT 
        timestamp,
        score
    FROM asn_score_history
    WHERE asn = {asn}
    ORDER BY timestamp DESC
    LIMIT {days * 24}  -- Allow multiple entries per day
    """
    try:
        data = ch_client.execute(query)
        history = []
        for row in data:
            ts, score = row
            history.append({
                "timestamp": str(ts),
                "score": int(score)
            })
        
        return history
    except Exception as e:
        print(f"History Error: {e}")
        # Fallback: return empty list
        return []

@app.post("/whitelist", tags=["System"])
def add_to_whitelist(req: WhitelistRequest, api_key: str = Depends(get_api_key)):
    """
    **Whitelist an ASN to ignore it.**
    Requires API Key.
    """
    try:
        with pg_engine.connect() as conn:
            # Ensure table exists (Lazy Init - matching Scorer logic)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS asn_whitelist (
                    asn BIGINT PRIMARY KEY,
                    reason TEXT,
                    added_at TIMESTAMP DEFAULT NOW()
                )
            """))
            conn.execute(text("""
                INSERT INTO asn_whitelist (asn, reason) 
                VALUES (:asn, :reason)
                ON CONFLICT (asn) DO UPDATE SET reason = :reason
            """), {'asn': req.asn, 'reason': req.reason})
            conn.commit()
        return {"status": "success", "message": f"ASN {req.asn} added to whitelist."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/tools/bulk-risk-check", tags=["Scoring"])
def bulk_risk_check(req: BulkAnalysisRequest, api_key: str = Depends(get_api_key)):
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
        rows = conn.execute(query, {'asns': req.asns}).mappings().fetchall()
        row_map = {r['asn']: r for r in rows}
        
        for asn in req.asns:
            if asn in row_map:
                r = row_map[asn]
                results.append({
                    "asn": asn,
                    "score": r['total_score'],
                    "level": r['risk_level'],
                    "name": r['name']
                })
            else:
                results.append({
                    "asn": asn,
                    "score": None,
                    "level": "UNKNOWN",
                    "name": "Unknown"
                })
                
    return {"results": results}

