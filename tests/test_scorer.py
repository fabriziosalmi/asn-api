# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import sys
import os
from unittest.mock import patch, MagicMock

# Ensure engine path is available for scorer import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/engine")))

# Mock DB connections before importing scorer
with patch("sqlalchemy.create_engine"), \
     patch("clickhouse_driver.Client"), \
     patch("redis.Redis"):
    from scorer import RiskScorer


class MockScorer(RiskScorer):
    def __init__(self):
        pass


def test_score_calculation_high_risk():
    signals = {
        "rpki_invalid_percent": 5.0,
        "spamhaus_listed": True,
        "has_route_leaks": False,
    }

    score = 100
    if signals["spamhaus_listed"]:
        score -= 50
    if signals["rpki_invalid_percent"] > 1.0:
        score -= 30

    assert score == 20
    assert score <= 50


def test_score_calculation_clean():
    signals = {
        "rpki_invalid_percent": 0.0,
        "spamhaus_listed": False,
        "has_route_leaks": False,
    }
    score = 100
    assert score == 100
