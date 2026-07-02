# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import sys
import os
import pytest
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
    """spamhaus listed (-30) + rpki_invalid > 1% (-20) + peeringdb bonus (+5) => 100 - 45 = 55."""
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


# ---------------------------------------------------------------------------
# Table-driven coverage of _apply_scoring_rules — the product's core logic.
# `_base_*` produce a neutral input (score would be 100, no bonuses) so each
# test isolates exactly one rule.
# ---------------------------------------------------------------------------


def _base_signals(**over):
    s = {
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
        "has_peeringdb_profile": False,
        "upstream_tier1_count": 0,
        "is_whois_private": False,
        "whois_entropy": 0.0,
    }
    s.update(over)
    return s


def _base_temporal(**over):
    t = {
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
    t.update(over)
    return t


def _score(signals=None, temporal=None):
    scorer = MockScorer()
    return scorer._apply_scoring_rules(
        signals if signals is not None else _base_signals(),
        temporal if temporal is not None else _base_temporal(),
    )


def test_neutral_input_scores_100_low():
    fs, bd, _det, lvl = _score()
    assert fs == 100
    assert lvl == "LOW"
    assert bd == {"hygiene": 0, "threat": 0, "stability": 0}


@pytest.mark.parametrize(
    "field,val,delta,cat",
    [
        ("rpki_invalid_percent", 5.0, -20, "hygiene"),
        ("has_route_leaks", True, -20, "hygiene"),
        ("has_bogon_ads", True, -10, "hygiene"),
        ("prefix_granularity_score", 51, -10, "hygiene"),
        ("is_stub_but_transit", True, -10, "hygiene"),
        ("spamhaus_listed", True, -30, "threat"),
        ("spam_emission_rate", 0.2, -15, "threat"),
        ("whois_entropy", 5.0, -10, "threat"),
    ],
)
def test_signal_penalty_isolated(field, val, delta, cat):
    fs, bd, _det, _lvl = _score(_base_signals(**{field: val}))
    assert fs == 100 + delta
    assert bd[cat] == delta


@pytest.mark.parametrize(
    "field,val,delta,cat",
    [
        ("upstream_churn_90d", 3, -25, "stability"),
        ("is_predictive_unstable", True, -15, "stability"),
        ("recent_withdrawals", 101, -5, "stability"),
        ("recent_threat_count", 6, -10, "threat"),
        ("ddos_blackhole_count", 6, -15, "stability"),
        ("excessive_prepending_count", 11, -10, "stability"),
        ("downstream_score", 60, -20, "stability"),
        ("zombie_status", True, -15, "hygiene"),
    ],
)
def test_temporal_penalty_isolated(field, val, delta, cat):
    fs, bd, _det, _lvl = _score(temporal=_base_temporal(**{field: val}))
    assert fs == 100 + delta
    assert bd[cat] == delta


@pytest.mark.parametrize(
    "count,expected",
    [(1, -20), (2, -40), (10, -40)],  # min(40, count*20)
)
def test_botnet_c2_penalty_capped(count, expected):
    _fs, bd, _det, _lvl = _score(_base_signals(botnet_c2_count=count))
    assert bd["threat"] == expected


@pytest.mark.parametrize(
    "count,expected",
    [(1, -5), (4, -20), (10, -20)],  # min(20, count*5)
)
def test_phishing_penalty_capped(count, expected):
    _fs, bd, _det, _lvl = _score(_base_signals(phishing_hosting_count=count))
    assert bd["threat"] == expected


@pytest.mark.parametrize(
    "count,expected",
    [(1, -10), (3, -30), (10, -30)],  # min(30, count*10)
)
def test_malware_penalty_capped(count, expected):
    _fs, bd, _det, _lvl = _score(_base_signals(malware_distribution_count=count))
    assert bd["threat"] == expected


@pytest.mark.parametrize(
    "avg,delta",
    [(40.0, -15), (60.0, -5), (100.0, 0)],
)
def test_bad_neighborhood_tiers(avg, delta):
    fs, _bd, _det, _lvl = _score(temporal=_base_temporal(avg_upstream_score=avg))
    assert fs == 100 + delta


def test_bonuses_capped_at_100():
    # peeringdb (+5) + tier1>1 (+5) on an otherwise clean ASN cannot exceed 100.
    fs, bd, _det, lvl = _score(
        _base_signals(has_peeringdb_profile=True, upstream_tier1_count=2)
    )
    assert fs == 100
    assert bd["stability"] == 10
    assert lvl == "LOW"


def test_score_floored_at_zero():
    # Pile on penalties well past -100; result clamps to 0 / CRITICAL.
    fs, _bd, _det, lvl = _score(
        _base_signals(
            spamhaus_listed=True,
            botnet_c2_count=10,
            malware_distribution_count=10,
            has_route_leaks=True,
            rpki_invalid_percent=5.0,
        ),
        _base_temporal(upstream_churn_90d=5, downstream_score=10),
    )
    assert fs == 0
    assert lvl == "CRITICAL"


@pytest.mark.parametrize(
    "signals,expected_level",
    [
        (_base_signals(has_bogon_ads=True), "LOW"),        # 90
        (_base_signals(spam_emission_rate=0.2), "MEDIUM"), # 85
        (_base_signals(spamhaus_listed=True), "MEDIUM"),   # 70 (boundary)
        (_base_signals(spamhaus_listed=True, has_bogon_ads=True), "HIGH"),  # 60
    ],
)
def test_risk_level_thresholds(signals, expected_level):
    _fs, _bd, _det, lvl = _score(signals)
    assert lvl == expected_level


# ---------------------------------------------------------------------------
# Signal-derivation helpers (bogon / stub-transit / RPKI) — pure logic.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prefix,is_bogon",
    [
        ("192.0.2.0/24", True),    # TEST-NET-1 documentation range → bogon
        ("10.0.0.0/24", True),     # RFC1918 private
        ("192.168.1.0/24", True),  # RFC1918 private
        ("172.16.0.0/12", True),   # RFC1918 private
        ("127.0.0.0/8", True),     # loopback
        ("224.0.0.0/4", True),     # multicast
        ("8.8.8.0/24", False),     # globally routable
        ("1.1.1.0/24", False),     # globally routable
        ("not-a-prefix", False),   # malformed → not a bogon (ignored)
        ("2001:db8::/32", True),   # IPv6 documentation → reserved
    ],
)
def test_is_bogon(prefix, is_bogon):
    assert RiskScorer._is_bogon(prefix) is is_bogon


@pytest.mark.parametrize(
    "transit_hops,originated,expected",
    [
        (0, 3, False),    # not transiting → not stub-transit
        (5, 0, False),    # pure transit (originates nothing) → excluded
        (5, 3, True),     # small originator acting as transit → flagged
        (5, 5, True),     # boundary (<= STUB_MAX)
        (5, 6, False),    # too many prefixes → a real network, not a stub
    ],
)
def test_classify_stub_transit(transit_hops, originated, expected):
    assert RiskScorer._classify_stub_transit(transit_hops, originated) is expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("", 0.0),
        ("aaaa", 0.0),  # single distinct char → zero entropy
        ("ab", 1.0),  # two equally-likely chars → 1 bit
        ("abcd", 2.0),  # four equally-likely chars → 2 bits
    ],
)
def test_shannon_entropy(name, expected):
    assert RiskScorer._shannon_entropy(name) == expected


def test_shannon_entropy_generated_vs_real():
    # A random-looking string should out-score an ordinary org name.
    assert RiskScorer._shannon_entropy("x7Qp2Zk9Lm4Rb") > RiskScorer._shannon_entropy(
        "Google LLC"
    )


@pytest.mark.parametrize(
    "prefixes,expected",
    [
        ([], 0),
        (["1.0.0.0/8"], 0),  # single prefix, nothing more-specific
        (["10.0.0.0/24", "10.0.1.0/24"], 0),  # siblings, not nested
        (["1.0.0.0/8", "1.1.0.0/16"], 50),  # /16 is a more-specific of /8 → 1 of 2
        (["1.0.0.0/8", "1.1.0.0/16", "2.0.0.0/8"], 33),  # 1 of 3
        (["1.0.0.0/8", "bad", "1.1.0.0/16"], 50),  # malformed ignored → 1 of 2
    ],
)
def test_prefix_granularity(prefixes, expected):
    assert RiskScorer._prefix_granularity(prefixes) == expected


def test_rpki_percentages():
    assert RiskScorer._rpki_percentages([]) is None
    assert RiskScorer._rpki_percentages(["valid", "valid"]) == (0.0, 0.0)
    # RIPE Stat uses invalid_asn / invalid_length, not a bare "invalid"
    assert RiskScorer._rpki_percentages(["invalid_asn", "valid"]) == (50.0, 0.0)
    assert RiskScorer._rpki_percentages(["invalid_asn", "invalid_length"]) == (
        100.0,
        0.0,
    )
    # anything not valid/invalid* (e.g. "unknown", "") counts as unknown
    assert RiskScorer._rpki_percentages(["unknown", "valid", "", "invalid_asn"]) == (
        25.0,
        50.0,
    )
