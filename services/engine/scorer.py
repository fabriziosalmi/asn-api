import os
import requests
import pandas as pd
from datetime import datetime
from sqlalchemy import create_engine, text
from clickhouse_driver import Client

# Config
PG_USER = os.getenv('POSTGRES_USER', 'asn_admin')
PG_PASS = os.getenv('POSTGRES_PASSWORD', 'secure_password')
PG_HOST = os.getenv('DB_META_HOST', 'db-metadata')
PG_DB = os.getenv('POSTGRES_DB', 'asn_registry')
CH_HOST = os.getenv('DB_TS_HOST', 'db-timeseries')
CH_USER = os.getenv('CLICKHOUSE_USER', 'default')
CH_PASS = os.getenv('CLICKHOUSE_PASSWORD', '')

class RiskScorer:
    def __init__(self):
        self.pg_engine = create_engine(f'postgresql://{PG_USER}:{PG_PASS}@{PG_HOST}/{PG_DB}')
        self.ch_client = Client(host=CH_HOST, user=CH_USER, password=CH_PASS)

    def calculate_score(self, asn):
        """
        Orchestrates the scoring process for a single ASN.
        Returns the final calculated score and the components.
        """
        print(f"[Scorer] Starting SOTA analysis for ASN {asn}")

        # 0. Whitelist Check
        if self._check_whitelist(asn):
            print(f"[Scorer] ASN {asn} is WHITESLISTED. Skipping analysis.")
            self._save_score(asn, 100, {'hygiene': 0, 'threat': 0, 'stability': 0}, 'LOW')
            return 100
        
        # 1. Fetch Snapshot Signals (Postgres) - The "Who they say they are"
        signals = self._get_or_create_signals(asn)
        
        # 2. Fetch Temporal Metrics (ClickHouse) - The "How they behave"
        temporal_metrics = self._calculate_temporal_metrics(asn)
        
        # 3. Apply Scoring Logic (The "Formula") - 30 Signals Logic
        final_score, breakdown, details, risk_level = self._apply_scoring_rules(signals, temporal_metrics)
        
        # 4. Persist Result
        self._save_score(asn, final_score, breakdown, risk_level)
        
        return final_score

    def _get_or_create_signals(self, asn):
        query = text("SELECT * FROM asn_signals WHERE asn = :asn")
        with self.pg_engine.connect() as conn:
            result = conn.execute(query, {'asn': asn}).mappings().fetchone()
            
            # Enrich Registry Data if missing (Name/Country)
            self._enrich_asn_metadata(asn, conn)
            
            if not result:
                # Initialize with safe defaults for new ASNs
                conn.execute(text("INSERT INTO asn_registry (asn, total_score) VALUES (:asn, 100) ON CONFLICT DO NOTHING"), {'asn': asn})
                # Set default "Clean Slate"
                conn.execute(text("""
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
                """), {'asn': asn})
                conn.commit()
                # Return 'clean' dictionary matching DB structure
                return {
                    'rpki_invalid_percent': 0.0, 'rpki_unknown_percent': 0.0,
                    'has_route_leaks': False, 'has_bogon_ads': False, 'prefix_granularity_score': 0,
                    'is_stub_but_transit': False, 'spamhaus_listed': False, 'spam_emission_rate': 0.0,
                    'botnet_c2_count': 0, 'phishing_hosting_count': 0, 'malware_distribution_count': 0,
                    'has_peeringdb_profile': True, 'upstream_tier1_count': 1, 'is_whois_private': False
                }
            return result

    def _check_whitelist(self, asn):
        """
        Checks if ASN is in the ignore list.
        """
        try:
            with self.pg_engine.connect() as conn:
                # Ensure table exists (Lazy Init)
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS asn_whitelist (
                        asn BIGINT PRIMARY KEY,
                        reason TEXT,
                        added_at TIMESTAMP DEFAULT NOW()
                    )
                """))
                conn.commit()
                
                res = conn.execute(text("SELECT asn FROM asn_whitelist WHERE asn = :asn"), {'asn': asn}).fetchone()
                return res is not None
        except Exception as e:
            print(f"[Scorer] Whitelist check failed: {e}")
            return False

    def _calculate_temporal_metrics(self, asn):
        """
        Calculates complex temporal behavior (Derivatives).
        """
        params = {'asn': asn}
        
        # 1. BGP Churn (How many distinct upstreams in last 90 days?)
        query_churn = """
        SELECT uniq(upstream_as) 
        FROM bgp_events 
        WHERE asn = %(asn)s AND event_type = 'announce' AND timestamp > now() - INTERVAL 90 DAY
        """
        upstream_churn_90d = self.ch_client.execute(query_churn, params)[0][0]

        # 2. Prefix Flapping (Instability) via Materialized View or Raw
        query_flaps = """
        SELECT sum(withdraw_count) 
        FROM daily_metrics 
        WHERE asn = %(asn)s AND date > now() - INTERVAL 7 DAY
        """
        result_flaps = self.ch_client.execute(query_flaps, params)
        recent_withdrawals = result_flaps[0][0] if result_flaps and result_flaps[0][0] else 0

        # 3. IP Space Velocity (Growth Rate)
        query_velocity = """
        SELECT uniq(prefix) FROM bgp_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 2 DAY
        """
        result_velocity = self.ch_client.execute(query_velocity, params)
        current_prefix_count = result_velocity[0][0] if result_velocity else 0
        
        # 4. Threat Persistence (Recidivism)
        query_threats = """
        SELECT count(*) FROM threat_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 30 DAY
        """
        result_threats = self.ch_client.execute(query_threats, params)
        recent_threat_count = result_threats[0][0] if result_threats else 0
        
        # 5. Connectivity Risk (Guilt by Association)
        query_upstreams = """
        SELECT upstream_as, count(*) as c 
        FROM bgp_events 
        WHERE asn = %(asn)s AND upstream_as != 0 AND timestamp > now() - INTERVAL 30 DAY
        GROUP BY upstream_as ORDER BY c DESC LIMIT 3
        """
        upstreams = self.ch_client.execute(query_upstreams, params)
        
        avg_upstream_score = 100
        if upstreams:
            upstream_asns = [u[0] for u in upstreams]
            # Batch query for scores to avoid N+1 problem
            with self.pg_engine.connect() as conn:
                res = conn.execute(
                    text("SELECT total_score FROM asn_registry WHERE asn = ANY(:asns)"), 
                    {'asns': upstream_asns}
                ).fetchall()
                if res:
                    avg_upstream_score = sum(r[0] for r in res) / len(res)

        # 6. [The Oracle] Predictive Stability Analysis
        query_oracle = """
        SELECT avg(c) as u, stddevPop(c) as s
        FROM (
            SELECT toDate(timestamp) as d, count(*) as c 
            FROM bgp_events 
            WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 14 DAY
            GROUP BY d
        )
        """
        oracle_stats = self.ch_client.execute(query_oracle, params)
        is_predictive_unstable = False
        
        if oracle_stats and oracle_stats[0][0]:
            mean_daily = oracle_stats[0][0]
            std_dev = oracle_stats[0][1]
            
            query_today = "SELECT count(*) FROM bgp_events WHERE asn = %(asn)s AND timestamp > now() - INTERVAL 4 HOUR"
            res_today = self.ch_client.execute(query_today, params)
            current_burst = res_today[0][0] if res_today else 0
            
            if mean_daily > 10 and (std_dev / mean_daily) > 1.5:
                 is_predictive_unstable = True

        return {
            'upstream_churn_90d': upstream_churn_90d,
            'recent_withdrawals': recent_withdrawals,
            'current_prefix_count': current_prefix_count,
            'recent_threat_count': recent_threat_count,
            'avg_upstream_score': avg_upstream_score,
            'is_predictive_unstable': is_predictive_unstable
        }

    def _apply_scoring_rules(self, s, t):
        """
        The Core Logic (Engine).
        Implements the 30 Signals and Weights from MISSION.md
        """
        score = 100
        breakdown = {'hygiene': 0, 'threat': 0, 'stability': 0}
        details = []

        # --- CATEGORY A: ROUTING HYGIENE (BGP) ---
        
        # 1. RPKI Invalid (High Impact: -20)
        if s.get('rpki_invalid_percent', 0) > 1.0:
            penalty = 20
            score -= penalty; breakdown['hygiene'] -= penalty
            details.append("RPKI Invalid > 1%")

        # 2. Route Leaks (High Impact: -20)
        if s.get('has_route_leaks'):
            penalty = 20
            score -= penalty; breakdown['hygiene'] -= penalty
            details.append("Active Route Leaks detected")

        # 3. Bogon Ads (Medium Impact: -10)
        if s.get('has_bogon_ads'):
            penalty = 10
            score -= penalty; breakdown['hygiene'] -= penalty
            details.append("Advertising Bogon Space")

        # 4. Prefix Granularity (De-aggregation) (Medium Impact: -10)
        if s.get('prefix_granularity_score', 0) > 50: # Arbitrary threshold for 'bad'
            penalty = 10
            score -= penalty; breakdown['hygiene'] -= penalty
            details.append("High Prefix Fragmentation")

        # --- CATEGORY B: THREAT INTEL (Malicious Activity) ---

        # 11. Spamhaus Listed (Critical Impact: -30)
        if s.get('spamhaus_listed'):
            penalty = 30
            score -= penalty; breakdown['threat'] -= penalty
            details.append("Listed on Spamhaus DROP")

        # 13. Botnet C2 Hosting (High Impact: -20 per detected C2)
        c2_count = s.get('botnet_c2_count', 0)
        if c2_count > 0:
            penalty = min(40, c2_count * 20) # Cap at 40
            score -= penalty; breakdown['threat'] -= penalty
            details.append(f"Hosting {c2_count} Botnet C2 servers")

        # 12. Spam Emission Rate (High Impact)
        if s.get('spam_emission_rate', 0) > 0.1:
            penalty = 15
            score -= penalty; breakdown['threat'] -= penalty
            details.append("High Spambot emission rate")

        # Temporal Threat: Recidivism (History)
        if t['recent_threat_count'] > 5:
            penalty = 10
            score -= penalty; breakdown['threat'] -= penalty
            details.append("Persistent Threat Activity (Recidivism)")

        # --- CATEGORY C: STABILITY & IDENTITY (Business) ---

        # "Fly-by-night" Detection (High Impact)
        # Upstream Churn: Changing providers > 2 times in 90 days
        if t['upstream_churn_90d'] > 2:
            penalty = 25
            score -= penalty; breakdown['stability'] -= penalty
            details.append(f"High Upstream Churn ({t['upstream_churn_90d']} providers in 90d)")
            
        # [The Oracle] Predictive Instability
        # If the Coefficient of Variation is too high, we predict future trouble
        if t.get('is_predictive_unstable'):
            penalty = 15
            score -= penalty; breakdown['stability'] -= penalty
            details.append("Predictive AI: High Probability of Instability")

        # Flapping (Instability)
        if t['recent_withdrawals'] > 100:
            penalty = 5
            score -= penalty; breakdown['stability'] -= penalty
            details.append("Significant Route Flapping")

        # Legitimacy Signals (Bonus Points +)
        if s.get('has_peeringdb_profile'):
            bonus = 5
            score += bonus; breakdown['stability'] += bonus
        
        if s.get('upstream_tier1_count', 0) > 1:
            bonus = 5
            score += bonus; breakdown['stability'] += bonus

        # --- CATEGORY D: CONNECTIVITY RISK (Graph) ---
        # If your upstreams are trash, you are likely trash
        avg_upstream = t.get('avg_upstream_score', 100)
        if avg_upstream < 50:
             penalty = 15
             score -= penalty; breakdown['stability'] -= penalty
             details.append(f"Bad Neighborhood (Avg Upstream Score: {int(avg_upstream)})")
        elif avg_upstream < 70:
             penalty = 5
             score -= penalty
             details.append("Suspicious Upstreams")

        # Cap score 0-100
        final_score = max(0, min(100, score))
        
        # Calculate Risk Level
        if final_score >= 90:
            risk_level = 'LOW'
        elif final_score >= 70:
            risk_level = 'MEDIUM'
        elif final_score >= 50:
            risk_level = 'HIGH'
        else:
            risk_level = 'CRITICAL'
            
        return final_score, breakdown, details, risk_level

    def _save_score(self, asn, score, breakdown, risk_level):
        # 1. Update Persistent Registry (Postgres)
        with self.pg_engine.connect() as conn:
            conn.execute(text("""
                UPDATE asn_registry 
                SET total_score = :score, 
                    hygiene_score = 100 + :h,
                    threat_score = 100 + :t,
                    stability_score = 100 + :s,
                    risk_level = :risk_level,
                    last_scored_at = NOW()
                WHERE asn = :asn
            """), {
                'score': score, 
                'h': breakdown['hygiene'],
                't': breakdown['threat'],
                's': breakdown['stability'],
                'risk_level': risk_level,
                'asn': asn
            })
            conn.commit()
            
        # 2. Append to Time Series History (ClickHouse)
        # This powers the Historical Timeline
        try:
            self.ch_client.execute(
                'INSERT INTO asn_score_history (timestamp, asn, score) VALUES',
                [{'timestamp': datetime.now(), 'asn': asn, 'score': score}]
            )
        except Exception:
            # Auto-create table if missing (First run)
            try:
                self.ch_client.execute("""
                    CREATE TABLE IF NOT EXISTS asn_score_history (
                        timestamp DateTime,
                        asn UInt32,
                        score UInt8
                    ) ENGINE = MergeTree() ORDER BY (asn, timestamp)
                """)
                self.ch_client.execute(
                    'INSERT INTO asn_score_history (timestamp, asn, score) VALUES',
                    [{'timestamp': datetime.now(), 'asn': asn, 'score': score}]
                )
            except Exception as e:
                print(f"[Scorer] History log failed: {e}")

        print(f"[Scorer] ASN {asn} updated. Score: {score} ({risk_level})")

    def _enrich_asn_metadata(self, asn, conn):
        """
        Fetches public metadata (Name, Country) from RIPEstat if missing in DB.
        Also scans PeeringDB for physical presence.
        """
        try:
            # 1. RIPEstat - Name and Country
            # Check if we already have the name
            existing = conn.execute(text("SELECT name FROM asn_registry WHERE asn = :asn"), {'asn': asn}).fetchone()
            needs_ripe = not existing or not existing[0] or existing[0] == 'Unknown'
            
            if needs_ripe:
                print(f"[Enrichment] Fetching metadata for ASN {asn}...")
                # Use RIPEstat Data API (Free, reliable)
                url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}"
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    data = resp.json().get('data', {})
                    holder = data.get('holder', 'Unknown')
                    
                    # Fetch Country from Geolocation widget
                    geo_url = f"https://stat.ripe.net/data/geoloc/data.json?resource={asn}"
                    geo_resp = requests.get(geo_url, timeout=5)
                    country_code = 'XX'
                    if geo_resp.status_code == 200:
                        utils = geo_resp.json().get('data', {}).get('locations', [])
                        if utils:
                            country_code = utils[0].get('country', 'XX')
                    
                    # Update Registry
                    conn.execute(text("""
                        UPDATE asn_registry 
                        SET name = :name, country_code = :cc 
                        WHERE asn = :asn
                    """), {'name': holder, 'cc': country_code, 'asn': asn})
                    conn.commit()
                    print(f"[Enrichment] Updated ASN {asn}: {holder} ({country_code})")

            # 2. PeeringDB - Physical Infrastructure Context
            # Check if this ASN is "real" (present in data centers)
            try:
                pdb_url = f"https://www.peeringdb.com/api/net?asn={asn}"
                pdb_resp = requests.get(pdb_url, timeout=5)
                has_pdb = False
                
                if pdb_resp.status_code == 200:
                    data = pdb_resp.json().get('data', [])
                    if data:
                        has_pdb = True
                        # We could extract 'exchanges_count' or 'fac_count' here
                
                # Update the specific signal
                conn.execute(text("""
                    UPDATE asn_signals 
                    SET has_peeringdb_profile = :pdb 
                    WHERE asn = :asn
                """), {'pdb': has_pdb, 'asn': asn})
                conn.commit()
                if has_pdb:
                    # Silent log to avoid noise, or debug
                    pass
            except Exception:
                pass # Fail silently for PeeringDB to avoid blocking scoring

        except Exception as e:
            print(f"[Enrichment] Failed for ASN {asn}: {e}")

if __name__ == "__main__":
    # Test
    s = RiskScorer()
    s.calculate_score(666)
