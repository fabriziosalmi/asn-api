# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import time
import urllib.parse
import logging
import threading
from datetime import datetime
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

import requests as http_requests
import redis
from sqlalchemy import create_engine, text
from clickhouse_driver import Client
from pythonjsonlogger.json import JsonFormatter as JsonLogFormatter

from engine_settings import EngineSettings

# --- Configuration (validated) ---
settings = EngineSettings()

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
logger = logging.getLogger("engine.scorer")

# --- DB Config ---
PG_PASS_SAFE = urllib.parse.quote_plus(settings.postgres_password)


class RiskScorer:
    def __init__(self) -> None:
        self.pg_engine = create_engine(
            f"postgresql://{settings.postgres_user}:{PG_PASS_SAFE}@{settings.db_meta_host}/{settings.postgres_db}",
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
        )
        self.ch_client = Client(
            host=settings.db_ts_host,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
        )
        self.redis_client = redis.Redis.from_url(
            settings.broker_url, decode_responses=True
        )
        self.executor = ThreadPoolExecutor(max_workers=5)
        self._cb_lock = threading.Lock()
        self._cb_state = {"failures": 0, "last_failure": 0, "open": False}

    def calculate_score(self, asn: int, trace_id: str = "") -> int:
        """Orchestrates the scoring process for a single ASN."""
        extra = {"asn": asn, "trace_id": trace_id}
        logger.info("scoring_start", extra=extra)

        if self._check_whitelist(asn):
            logger.info("scoring_skip", extra={**extra, "reason": "whitelisted"})
            self._save_score(
                asn, 100, {"hygiene": 0, "threat": 0, "stability": 0}, "LOW"
            )
            return 100

        signals = self._get_or_create_signals(asn)
        temporal_metrics = self._calculate_temporal_metrics(asn)
        final_score, breakdown, details, risk_level = self._apply_scoring_rules(
            signals, temporal_metrics
        )
        self._save_score(asn, final_score, breakdown, risk_level, temporal_metrics)

        # Invalidate API cache for this ASN
        self._invalidate_cache(asn)

        return final_score

    def _invalidate_cache(self, asn: int) -> None:
        """Bust the API response cache after score update."""
        try:
            self.redis_client.delete(f"score:v3:{asn}")
        except Exception as e:
            logger.warning(
                "cache_invalidation_failed", extra={"asn": asn, "error": str(e)}
            )

    def _get_or_create_signals(self, asn: int) -> dict:
        query = text("SELECT * FROM asn_signals WHERE asn = :asn")
        with self.pg_engine.connect() as conn:
            result = conn.execute(query, {"asn": asn}).mappings().fetchone()
            self._enrich_asn_metadata(asn, conn)

            if not result:
                conn.execute(
                    text(
                        "INSERT INTO asn_registry (asn, total_score) VALUES (:asn, 100) ON CONFLICT DO NOTHING"
                    ),
                    {"asn": asn},
                )
                conn.execute(
                    text("""
                    INSERT INTO asn_signals (
                        asn, rpki_invalid_percent, rpki_unknown_percent,
                        has_route_leaks, has_bogon_ads, prefix_granularity_score,
                        is_stub_but_transit, spamhaus_listed, spam_emission_rate,
                        botnet_c2_count, phishing_hosting_count, malware_distribution_count,
                        has_peeringdb_profile, upstream_tier1_count, is_whois_private
                    )
                    VALUES (
                        :asn, 0.0, 0.0,
                        FALSE, FALSE, 0,
                        FALSE, FALSE, 0.0,
                        0, 0, 0,
                        TRUE, 1, FALSE
                    )
                """),
                    {"asn": asn},
                )
                conn.commit()
                return {
                    "rpki_invalid_percent": 0.0,
                    "rpki_unknown_percent": 0.0,
                    "has_route_leaks": False,
                    "has_bogon_ads": False,
                    "prefix_granularity_score": 0,
                    "is_stub_but_transit": False,
                    "spamhaus_listed": False,
                    "spam_emission_rate": 0.0,
                    "botnet_c2_count": 0,
                    "phishing_hosting_count": 0,
                    "malware_distribution_count": 0,
                    "has_peeringdb_profile": True,
                    "upstream_tier1_count": 1,
                    "is_whois_private": False,
                }
            return result

    def _check_whitelist(self, asn: int) -> bool:
        try:
            with self.pg_engine.connect() as conn:
                res = conn.execute(
                    text("SELECT asn FROM asn_whitelist WHERE asn = :asn"), {"asn": asn}
                ).fetchone()
                return res is not None
        except Exception as e:
            logger.error("whitelist_check_failed", extra={"asn": asn, "error": str(e)})
            return False

    def _calculate_temporal_metrics(self, asn: int) -> dict:
        params = {"asn": asn}

        upstream_churn_90d = self._ch_scalar(
            "SELECT uniq(upstream_as) FROM bgp_events WHERE asn = %(asn)s AND event_type = 'announce' AND timestamp > now() - INTERVAL 90 DAY",
            params,
        )
        recent_withdrawals = self._ch_scalar(
            "SELECT sum(withdraw_count) FROM daily_metrics WHERE asn = %(asn)s AND date > now() - INTERVAL 7 DAY",
            params,
        )
        current_prefix_count = self._ch_scalar(
            "SELECT uniq(prefix) FROM bgp_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 2 DAY",
            params,
        )
        recent_threat_count = self._ch_scalar(
            "SELECT count(*) FROM threat_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 30 DAY",
            params,
        )

        upstreams = self.ch_client.execute(
            """SELECT upstream_as, count(*) as c FROM bgp_events
            WHERE asn = %(asn)s AND upstream_as != 0 AND timestamp > now() - INTERVAL 30 DAY
            GROUP BY upstream_as ORDER BY c DESC LIMIT 3""",
            params,
        )

        avg_upstream_score = 100.0
        if upstreams:
            upstream_asns = [u[0] for u in upstreams]
            with self.pg_engine.connect() as conn:
                res = conn.execute(
                    text("SELECT total_score FROM asn_registry WHERE asn = ANY(:asns)"),
                    {"asns": upstream_asns},
                ).fetchall()
                if res:
                    avg_upstream_score = sum(r[0] for r in res) / len(res)

        oracle_stats = self.ch_client.execute(
            """SELECT avg(c) as u, stddevPop(c) as s FROM (
                SELECT toDate(timestamp) as d, count(*) as c FROM bgp_events
                WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 14 DAY GROUP BY d
            )""",
            params,
        )
        is_predictive_unstable = False
        if oracle_stats and oracle_stats[0][0]:
            mean_daily = oracle_stats[0][0]
            std_dev = oracle_stats[0][1]
            if mean_daily > 10 and (std_dev / mean_daily) > 1.5:
                is_predictive_unstable = True

        return {
            "upstream_churn_90d": upstream_churn_90d,
            "recent_withdrawals": recent_withdrawals,
            "current_prefix_count": current_prefix_count,
            "recent_threat_count": recent_threat_count,
            "avg_upstream_score": avg_upstream_score,
            "is_predictive_unstable": is_predictive_unstable,
            "downstream_score": self._analyze_downstreams(asn),
            "zombie_status": current_prefix_count == 0,
            "ddos_blackhole_count": self._analyze_bgp_communities(asn),
            "excessive_prepending_count": self._analyze_traffic_engineering(asn),
        }

    def _ch_scalar(self, query: str, params: dict, default: int = 0) -> int:
        try:
            result = self.ch_client.execute(query, params)
            if result and result[0][0] is not None:
                return result[0][0]
        except Exception as e:
            logger.error("ch_query_error", extra={"query": query[:80], "error": str(e)})
        return default

    def _analyze_bgp_communities(self, asn: int) -> int:
        return self._ch_scalar(
            "SELECT count() FROM bgp_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 7 DAY AND has(community, 4294902426)",
            {"asn": asn},
        )

    def _analyze_traffic_engineering(self, asn: int) -> int:
        return self._ch_scalar(
            "SELECT sum(prepends_count) FROM forensic_metrics WHERE asn = %(asn)s AND date > now() - INTERVAL 7 DAY",
            {"asn": asn},
        )

    def _analyze_downstreams(self, asn: int) -> float:
        downstreams = self.ch_client.execute(
            """SELECT asn, count(*) as c FROM bgp_events
            WHERE upstream_as = %(asn)s AND timestamp > now() - INTERVAL 30 DAY
            GROUP BY asn ORDER BY c DESC LIMIT 20""",
            {"asn": asn},
        )
        if not downstreams:
            return 100.0
        downstream_asns = [d[0] for d in downstreams]
        with self.pg_engine.connect() as conn:
            res = conn.execute(
                text("SELECT total_score FROM asn_registry WHERE asn = ANY(:asns)"),
                {"asns": downstream_asns},
            ).fetchall()
            if not res:
                return 100.0
            return sum(r[0] for r in res) / len(res)

    def _apply_scoring_rules(self, s: dict, t: dict) -> tuple[int, dict, list, str]:
        score = 100
        breakdown = {"hygiene": 0, "threat": 0, "stability": 0}
        details: list[str] = []

        def penalize(cat: str, pts: int, msg: str) -> None:
            nonlocal score
            score -= pts
            breakdown[cat] -= pts
            details.append(msg)

        def bonus(cat: str, pts: int) -> None:
            nonlocal score
            score += pts
            breakdown[cat] += pts

        # --- CATEGORY A: ROUTING HYGIENE ---
        if s.get("rpki_invalid_percent", 0) > 1.0:
            penalize("hygiene", 20, "RPKI Invalid > 1%")
        if s.get("has_route_leaks"):
            penalize("hygiene", 20, "Active Route Leaks detected")
        if s.get("has_bogon_ads"):
            penalize("hygiene", 10, "Advertising Bogon Space")
        if s.get("prefix_granularity_score", 0) > 50:
            penalize("hygiene", 10, "High Prefix Fragmentation")
        if s.get("is_stub_but_transit"):
            penalize("hygiene", 10, "Stub ASN acting as transit provider")

        # --- CATEGORY B: THREAT INTEL ---
        if s.get("spamhaus_listed"):
            penalize("threat", 30, "Listed on Spamhaus DROP")
        c2_count = s.get("botnet_c2_count", 0)
        if c2_count > 0:
            penalize(
                "threat",
                min(40, c2_count * 20),
                f"Hosting {c2_count} Botnet C2 servers",
            )
        phishing_count = s.get("phishing_hosting_count", 0)
        if phishing_count > 0:
            penalize(
                "threat",
                min(20, phishing_count * 5),
                f"Hosting {phishing_count} phishing domains",
            )
        malware_count = s.get("malware_distribution_count", 0)
        if malware_count > 0:
            penalize(
                "threat",
                min(30, malware_count * 10),
                f"Hosting {malware_count} malware distribution points",
            )
        if s.get("spam_emission_rate", 0) > 0.1:
            penalize("threat", 15, "High Spambot emission rate")
        if t["recent_threat_count"] > 5:
            penalize("threat", 10, "Persistent Threat Activity (Recidivism)")

        # --- CATEGORY C: STABILITY & IDENTITY ---
        if t["upstream_churn_90d"] > 2:
            penalize(
                "stability",
                25,
                f"High Upstream Churn ({t['upstream_churn_90d']} providers in 90d)",
            )
        if t.get("is_predictive_unstable"):
            penalize(
                "stability", 15, "Statistical Analysis: High Probability of Instability"
            )
        if t["recent_withdrawals"] > 100:
            penalize("stability", 5, "Significant Route Flapping")
        if s.get("has_peeringdb_profile"):
            bonus("stability", 5)
        if s.get("upstream_tier1_count", 0) > 1:
            bonus("stability", 5)

        # --- CATEGORY D: CONNECTIVITY RISK ---
        avg_upstream = t.get("avg_upstream_score", 100)
        if avg_upstream < 50:
            penalize(
                "stability",
                15,
                f"Bad Neighborhood (Avg Upstream Score: {int(avg_upstream)})",
            )
        elif avg_upstream < 70:
            penalize("stability", 5, "Suspicious Upstreams")

        # --- PHASE 4: SOTA INTELLIGENCE ---
        downstream_score = t.get("downstream_score", 100)
        if downstream_score < 70:
            penalize(
                "stability",
                20,
                f"Toxic Downstream Clientele (Avg Score: {int(downstream_score)})",
            )
        if t.get("zombie_status"):
            penalize("hygiene", 15, "Zombie ASN: Active Registration but Zero Routes")
        entropy = s.get("whois_entropy", 0.0)
        if entropy > 4.5:
            penalize(
                "threat",
                10,
                f"High WHOIS Entropy ({entropy:.2f}): Possible generated name",
            )

        # --- PHASE 5: BGP FORENSICS ---
        if t.get("ddos_blackhole_count", 0) > 5:
            penalize("stability", 15, "DDoS Sponge: Frequent Blackholing detected")
        if t.get("excessive_prepending_count", 0) > 10:
            penalize(
                "stability", 10, "Traffic Engineering Chaos: Excessive BGP Prepending"
            )

        final_score = max(0, min(100, score))
        if final_score >= 90:
            risk_level = "LOW"
        elif final_score >= 70:
            risk_level = "MEDIUM"
        elif final_score >= 50:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return final_score, breakdown, details, risk_level

    def _save_score(
        self,
        asn: int,
        score: int,
        breakdown: dict,
        risk_level: str,
        metrics: Optional[dict] = None,
    ) -> None:
        timestamp = datetime.now()
        downstream_score = 100
        is_zombie = False
        ddos_bh = 0
        excessive_prepend = 0

        if metrics:
            downstream_score = metrics.get("downstream_score", 100)
            is_zombie = metrics.get("zombie_status", False)
            ddos_bh = metrics.get("ddos_blackhole_count", 0)
            excessive_prepend = metrics.get("excessive_prepending_count", 0)

        # Clamp component scores: base is 100, penalties subtract — floor at 0, cap at 100
        hygiene_score = max(0, min(100, 100 + breakdown["hygiene"]))
        threat_score = max(0, min(100, 100 + breakdown["threat"]))
        stability_score = max(0, min(100, 100 + breakdown["stability"]))

        with self.pg_engine.connect() as conn:
            conn.execute(
                text("""
                UPDATE asn_registry
                SET total_score = :score, hygiene_score = :h, threat_score = :t,
                    stability_score = :s, risk_level = :risk_level,
                    downstream_score = :ds, last_scored_at = :now
                WHERE asn = :asn
            """),
                {
                    "score": score,
                    "h": hygiene_score,
                    "t": threat_score,
                    "s": stability_score,
                    "risk_level": risk_level,
                    "ds": downstream_score,
                    "now": timestamp,
                    "asn": asn,
                },
            )
            conn.execute(
                text("""
                UPDATE asn_signals
                SET is_zombie_asn = :zombie, ddos_blackhole_count = :bh, excessive_prepending_count = :ep
                WHERE asn = :asn
            """),
                {
                    "zombie": is_zombie,
                    "bh": ddos_bh,
                    "ep": excessive_prepend,
                    "asn": asn,
                },
            )
            conn.commit()

        try:
            self.ch_client.execute(
                "INSERT INTO asn_score_history (timestamp, asn, score) VALUES",
                [{"timestamp": datetime.now(), "asn": asn, "score": score}],
            )
        except Exception as e:
            logger.error("history_log_failed", extra={"asn": asn, "error": str(e)})

        logger.info(
            "scoring_complete", extra={"asn": asn, "score": score, "level": risk_level}
        )

    def _enrich_asn_metadata(self, asn: int, conn) -> None:
        def run_enrichment():
            with self._cb_lock:
                if self._cb_state["open"]:
                    if (
                        time.time() - self._cb_state["last_failure"]
                        > settings.circuit_breaker_cooldown
                    ):
                        self._cb_state["open"] = False
                        self._cb_state["failures"] = 0
                    else:
                        return

            try:
                url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
                resp = http_requests.get(url, timeout=settings.enrichment_timeout)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    holder = data.get("holder", "Unknown")
                    with self.pg_engine.connect() as local_conn:
                        local_conn.execute(
                            text(
                                "UPDATE asn_registry SET name = :name WHERE asn = :asn"
                            ),
                            {"name": holder, "asn": asn},
                        )
                        local_conn.commit()
                else:
                    raise Exception(f"RIPE error: {resp.status_code}")

                pdb_url = f"https://www.peeringdb.com/api/net?asn={asn}"
                pdb_resp = http_requests.get(
                    pdb_url, timeout=settings.enrichment_timeout
                )
                if pdb_resp.status_code == 200:
                    data = pdb_resp.json().get("data", [])
                    has_pdb = len(data) > 0
                    with self.pg_engine.connect() as local_conn:
                        local_conn.execute(
                            text(
                                "UPDATE asn_signals SET has_peeringdb_profile = :pdb WHERE asn = :asn"
                            ),
                            {"pdb": has_pdb, "asn": asn},
                        )
                        local_conn.commit()

                with self._cb_lock:
                    self._cb_state["failures"] = 0

            except Exception as e:
                logger.warning("enrichment_failed", extra={"asn": asn, "error": str(e)})
                with self._cb_lock:
                    self._cb_state["failures"] += 1
                    self._cb_state["last_failure"] = time.time()
                    if self._cb_state["failures"] >= settings.circuit_breaker_threshold:
                        self._cb_state["open"] = True
                        logger.error(
                            "circuit_breaker_open",
                            extra={"reason": "external_api_failures"},
                        )

        self.executor.submit(run_enrichment)
