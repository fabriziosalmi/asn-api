# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import time
import math
import ipaddress
import urllib.parse
import logging
import threading
from collections import Counter
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

ASN_MIN = 1
ASN_MAX = 4294967295


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
        if not ASN_MIN <= asn <= ASN_MAX:
            logger.warning("invalid_asn", extra={"asn": asn, "trace_id": trace_id})
            raise ValueError(f"ASN must be between {ASN_MIN} and {ASN_MAX}, got {asn}")

        extra = {"asn": asn, "trace_id": trace_id}
        logger.info("scoring_start", extra=extra)

        if self._check_whitelist(asn):
            logger.info("scoring_skip", extra={**extra, "reason": "whitelisted"})
            self._save_score(
                asn, 100, {"hygiene": 0, "threat": 0, "stability": 0}, "LOW"
            )
            return 100

        signals = dict(self._get_or_create_signals(asn))
        derived = self._derive_signals_from_events(asn)  # threat intel
        derived.update(self._derive_bgp_signals(asn))  # bogon + stub-transit
        derived.update(self._derive_rpki(asn))  # RPKI validity (cached)
        if derived:
            signals.update(derived)
            self._persist_derived_signals(asn, derived)
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

    # How far back detections feed the discrete threat signals.
    THREAT_SIGNAL_WINDOW_DAYS = 30
    # BGP-derived signals
    PREFIX_LOOKBACK_DAYS = 7
    PREFIX_SCAN_LIMIT = 200
    STUB_MAX_ORIGINATED_PREFIXES = 5
    # RPKI validation (external, cached)
    RPKI_CACHE_TTL = 21600  # 6h
    RPKI_MAX_PREFIXES = 8

    # Columns this class is allowed to materialize into asn_signals. Used both to
    # build the partial UPDATE and to keep it injection-safe (keys are code-owned).
    _DERIVED_COLUMNS = (
        "spamhaus_listed",
        "malware_distribution_count",
        "has_route_leaks",
        "has_bogon_ads",
        "is_stub_but_transit",
        "prefix_granularity_score",
        "spam_emission_rate",
        "whois_entropy",
        "rpki_invalid_percent",
        "rpki_unknown_percent",
    )

    def _derive_signals_from_events(self, asn: int) -> dict:
        """Materialize discrete threat signals in Postgres from the detection
        stream in ClickHouse (threat_events). Without this, asn_signals stays at
        insert-time defaults and the entire Category-B / route-leak scoring is
        dead — the whole point of the ingestor never reaches the score.

        Threat signals derived here: spamhaus_listed, malware_distribution_count,
        has_route_leaks. Routing-hygiene signals (bogon, stub-transit, RPKI) are
        derived separately in _derive_bgp_signals / _derive_rpki. spam-rate and
        whois-entropy still have no feed and are intentionally left untouched."""
        try:
            rows = self.ch_client.execute(
                """SELECT category, uniqExact(target_ip) AS ips, count() AS n
                   FROM threat_events
                   WHERE asn = %(asn)s AND timestamp > now() - INTERVAL %(days)s DAY
                   GROUP BY category""",
                {"asn": asn, "days": self.THREAT_SIGNAL_WINDOW_DAYS},
            )
        except Exception as e:
            logger.warning(
                "signal_derivation_failed", extra={"asn": asn, "error": str(e)}
            )
            return {}

        by_cat = {row[0]: {"ips": row[1], "n": row[2]} for row in rows}
        return {
            "spamhaus_listed": by_cat.get("spamhaus", {}).get("n", 0) > 0,
            "malware_distribution_count": int(by_cat.get("malware", {}).get("ips", 0)),
            "has_route_leaks": by_cat.get("route_leak", {}).get("n", 0) > 0,
        }

    def _get_originated_prefixes(self, asn: int, limit: int) -> list:
        """Distinct prefixes this ASN originated (was last hop for) recently."""
        try:
            rows = self.ch_client.execute(
                """SELECT prefix, count() AS n FROM bgp_events
                   WHERE asn = %(asn)s AND event_type = 'announce'
                   AND timestamp > now() - INTERVAL %(days)s DAY
                   GROUP BY prefix ORDER BY n DESC LIMIT %(lim)s""",
                {"asn": asn, "days": self.PREFIX_LOOKBACK_DAYS, "lim": limit},
            )
            return [r[0] for r in rows]
        except Exception as e:
            logger.warning("prefix_fetch_failed", extra={"asn": asn, "error": str(e)})
            return []

    @staticmethod
    def _is_bogon(prefix: str) -> bool:
        """True if the prefix should never appear in the global routing table
        (private/reserved/loopback/link-local/multicast/unspecified)."""
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return False
        return (
            net.is_private
            or net.is_reserved
            or net.is_loopback
            or net.is_link_local
            or net.is_multicast
            or net.is_unspecified
        )

    @classmethod
    def _classify_stub_transit(
        cls, transit_hops: int, originated_prefixes: int
    ) -> bool:
        """A small operator (originates few prefixes) that is nonetheless used as
        a mid-path transit hop for others — a classic misconfiguration / leak
        risk. Pure transit providers (0 originated) are excluded."""
        return (
            transit_hops > 0
            and 0 < originated_prefixes <= cls.STUB_MAX_ORIGINATED_PREFIXES
        )

    @staticmethod
    def _shannon_entropy(name: str) -> float:
        """Shannon entropy (bits/char) of a string. Random/generated org names
        score high (~4.5+); ordinary names lower."""
        if not name:
            return 0.0
        counts = Counter(name)
        n = len(name)
        return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 2)

    @staticmethod
    def _prefix_granularity(prefixes: list) -> int:
        """Percentage (0-100) of the ASN's own prefixes that are more-specifics
        of another prefix it also announces — i.e. self de-aggregation. 0 when
        there is nothing to score. Penalised above 50."""
        nets = []
        for p in prefixes:
            try:
                nets.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                continue
        if not nets:
            return 0
        covered = 0
        for a in nets:
            for b in nets:
                if (
                    a != b
                    and a.version == b.version
                    and a.prefixlen > b.prefixlen
                    and a.subnet_of(b)
                ):
                    covered += 1
                    break
        return round(100 * covered / len(nets))

    def _whois_entropy(self, asn: int):
        """Entropy of the ASN's holder name (populated by enrichment). Returns
        None when the name is not yet known, so the signal is left untouched."""
        try:
            with self.pg_engine.connect() as conn:
                name = conn.execute(
                    text("SELECT name FROM asn_registry WHERE asn = :asn"),
                    {"asn": asn},
                ).scalar()
        except Exception as e:
            logger.warning("whois_entropy_failed", extra={"asn": asn, "error": str(e)})
            return None
        if not name or name == "Unknown":
            return None
        return self._shannon_entropy(name)

    def _derive_bgp_signals(self, asn: int) -> dict:
        """Derive routing-hygiene / identity signals from the local BGP view in
        ClickHouse plus the enriched holder name — no fabricated data:
        has_bogon_ads, is_stub_but_transit, prefix_granularity_score,
        spam_emission_rate (fraction of prefixes on Spamhaus), whois_entropy."""
        derived = {}
        entropy = self._whois_entropy(asn)
        if entropy is not None:
            derived["whois_entropy"] = entropy

        prefixes = self._get_originated_prefixes(asn, self.PREFIX_SCAN_LIMIT)
        if not prefixes:
            return derived

        derived["has_bogon_ads"] = any(self._is_bogon(p) for p in prefixes)
        derived["prefix_granularity_score"] = self._prefix_granularity(prefixes)

        # transit_hops: events where this ASN is in the path but NOT the origin.
        transit_hops = self._ch_scalar(
            """SELECT count() FROM bgp_events
               WHERE has(path, %(asn)s) AND length(path) > 0
               AND path[length(path)] != %(asn)s
               AND timestamp > now() - INTERVAL 30 DAY""",
            {"asn": asn},
        )
        originated_30d = self._ch_scalar(
            """SELECT uniqExact(prefix) FROM bgp_events
               WHERE asn = %(asn)s AND event_type = 'announce'
               AND timestamp > now() - INTERVAL 30 DAY""",
            {"asn": asn},
        )
        derived["is_stub_but_transit"] = self._classify_stub_transit(
            transit_hops, originated_30d
        )

        # spam_emission_rate: fraction of the ASN's prefixes flagged by Spamhaus.
        spam_flagged = self._ch_scalar(
            """SELECT uniqExact(target_ip) FROM threat_events
               WHERE asn = %(asn)s AND category = 'spamhaus'
               AND timestamp > now() - INTERVAL 30 DAY""",
            {"asn": asn},
        )
        total_prefixes = originated_30d or len(prefixes)
        if total_prefixes > 0:
            derived["spam_emission_rate"] = round(
                min(1.0, spam_flagged / total_prefixes), 5
            )
        return derived

    @staticmethod
    def _rpki_percentages(statuses: list):
        """Turn a list of per-prefix RPKI statuses into (invalid%, unknown%).
        RIPE Stat reports invalids as 'invalid_asn' / 'invalid_length' (not a
        bare 'invalid'), so any status starting with 'invalid' counts as invalid;
        'valid' counts as valid; everything else (incl. 'unknown', '') is unknown.
        Returns None when there is nothing to score."""
        total = len(statuses)
        if not total:
            return None
        invalid = sum(1 for s in statuses if s.startswith("invalid"))
        valid = sum(1 for s in statuses if s == "valid")
        unknown = total - invalid - valid
        return round(invalid / total * 100, 2), round(unknown / total * 100, 2)

    def _derive_rpki(self, asn: int) -> dict:
        """Validate the ASN's prefixes against RPKI via RIPE Stat and compute
        invalid/unknown percentages. Cached in Redis (6h) and gated by the same
        circuit breaker as enrichment so a RIPE outage can't stall scoring."""
        cache_key = f"rpki:v1:{asn}"
        try:
            cached = self.redis_client.get(cache_key)
            if cached:
                inv, unk = cached.split(",")
                return {
                    "rpki_invalid_percent": float(inv),
                    "rpki_unknown_percent": float(unk),
                }
        except Exception:
            pass

        with self._cb_lock:
            if self._cb_state["open"]:
                if (
                    time.time() - self._cb_state["last_failure"]
                    <= settings.circuit_breaker_cooldown
                ):
                    return {}
                self._cb_state["open"] = False
                self._cb_state["failures"] = 0

        prefixes = self._get_originated_prefixes(asn, self.RPKI_MAX_PREFIXES)
        if not prefixes:
            return {}

        statuses = []
        for prefix in prefixes:
            try:
                resp = http_requests.get(
                    "https://stat.ripe.net/data/rpki-validation/data.json",
                    params={"resource": asn, "prefix": prefix},
                    timeout=settings.enrichment_timeout,
                )
                if resp.status_code != 200:
                    continue
                status = (resp.json().get("data") or {}).get("status", "").lower()
                statuses.append(status)
                with self._cb_lock:
                    self._cb_state["failures"] = 0
            except Exception as e:
                logger.warning(
                    "rpki_check_failed",
                    extra={"asn": asn, "prefix": prefix, "error": str(e)},
                )
                with self._cb_lock:
                    self._cb_state["failures"] += 1
                    self._cb_state["last_failure"] = time.time()
                    if self._cb_state["failures"] >= settings.circuit_breaker_threshold:
                        self._cb_state["open"] = True
                        logger.error(
                            "circuit_breaker_open", extra={"reason": "rpki_failures"}
                        )
                break

        pct = self._rpki_percentages(statuses)
        if pct is None:
            return {}
        inv_pct, unk_pct = pct
        try:
            self.redis_client.setex(
                cache_key, self.RPKI_CACHE_TTL, f"{inv_pct},{unk_pct}"
            )
        except Exception:
            pass
        return {"rpki_invalid_percent": inv_pct, "rpki_unknown_percent": unk_pct}

    def _persist_derived_signals(self, asn: int, derived: dict) -> None:
        """Write the derived signals back to asn_signals so both the score and
        the API's penalty breakdown reflect them. Handles partial dicts (e.g.
        RPKI absent when RIPE is unreachable) via a code-owned column whitelist."""
        updates = {k: v for k, v in derived.items() if k in self._DERIVED_COLUMNS}
        if not updates:
            return
        set_clause = ", ".join(f"{col} = :{col}" for col in updates)
        params = dict(updates)
        params["asn"] = asn
        try:
            with self.pg_engine.connect() as conn:
                conn.execute(
                    text(f"UPDATE asn_signals SET {set_clause} WHERE asn = :asn"),
                    params,
                )
                conn.commit()
        except Exception as e:
            logger.warning("signal_persist_failed", extra={"asn": asn, "error": str(e)})

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
            "scoring_complete",
            extra={"asn": asn, "score": score, "risk_level": risk_level},
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

        # Skip external enrichment when we already know this ASN's holder name.
        # Previously RIPE + PeeringDB were hit on EVERY re-score (up to 50 ASNs
        # every 10s from the scanner) — a self-inflicted DoS on external APIs.
        # A NULL/'Unknown' name means still-unenriched, so we let it through.
        try:
            existing_name = conn.execute(
                text("SELECT name FROM asn_registry WHERE asn = :asn"), {"asn": asn}
            ).scalar()
            if existing_name and existing_name != "Unknown":
                return
        except Exception:
            pass

        self.executor.submit(run_enrichment)
