# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import sys
import os
from unittest.mock import patch

# Ensure engine path is available for scorer import
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/engine"))
)

# Mock DB connections before importing scorer
with patch("sqlalchemy.create_engine"), patch("clickhouse_driver.Client"), patch(
    "redis.Redis"
):
    from scorer import RiskScorer


class MockScorer(RiskScorer):
    def __init__(self):
        pass


def test_score_calculation_high_risk():
    """spamhaus listed (-30) + rpki_invalid > 1% (-20) => 100 - 50 = 50."""
    scorer = MockScorer()
    signals = {
        "rpki_invalid_percent": 5.0,
        "spamhaus_listed": True,
        "has_route_leaks": False,
        "has_bogon_ads": False,
        "prefix_granularity_score": 0,
        "is_stub_but_transit": False,
        "spam_emission_rate": 0.0,
        "botnet_c2_count": 0,
        "phishing_hosting_count": 0,
        "malware_distribution_count": 0,
        "has_peeringdb_profile": True,
        "upstream_tier1_count": 1,
        "is_whois_private": False,
    }
    temporal = {
        "upstream_churn_90d": 0,
        "recent_withdrawals": 0,
        "recent_threat_count": 0,
        "avg_upstream_score": 100.0,
        "is_predictive_unstable": False,
        "downstream_score": 100.0,
        "zombie_status": False,
        "ddos_blackhole_count": 0,
        "excessive_prepending_count": 0,
    }
    final_score, breakdown, details, risk_level = scorer._apply_scoring_rules(signals, temporal)
    # spamhaus(-30) + rpki_invalid>1%(-20) + peeringdb bonus(+5) = 100 - 30 - 20 + 5 = 55
    assert final_score == 55
    assert risk_level == "HIGH"
    assert final_score <= 74


def test_score_calculation_clean():
    """No negative signals => score 100 + peeringdb/tier1 bonuses, capped at 100."""
    scorer = MockScorer()
    signals = {
        "rpki_invalid_percent": 0.0,
        "spamhaus_listed": False,
        "has_route_leaks": False,
        "has_bogon_ads": False,
        "prefix_granularity_score": 0,
        "is_stub_but_transit": False,
        "spam_emission_rate": 0.0,
        "botnet_c2_count": 0,
        "phishing_hosting_count": 0,
        "malware_distribution_count": 0,
        "has_peeringdb_profile": True,
        "upstream_tier1_count": 2,
        "is_whois_private": False,
    }
    temporal = {
        "upstream_churn_90d": 0,
        "recent_withdrawals": 0,
        "recent_threat_count": 0,
        "avg_upstream_score": 100.0,
        "is_predictive_unstable": False,
        "downstream_score": 100.0,
        "zombie_status": False,
        "ddos_blackhole_count": 0,
        "excessive_prepending_count": 0,
    }
    final_score, breakdown, details, risk_level = scorer._apply_scoring_rules(signals, temporal)
    assert final_score == 100
    assert risk_level == "LOW"
