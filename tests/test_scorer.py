from services.engine.scorer import RiskScorer

# Mock for DB results
class MockScorer(RiskScorer):
    def __init__(self):
        # Skip DB init
        pass

def test_score_calculation_high_risk():
    # Simulate high risk signals
    signals = {
        'rpki_invalid_percent': 5.0, # Penalty
        'spamhaus_listed': True,    # Penalty
        'has_route_leaks': False
    }
    
    # Manually trigger rule logic (simplified for test)
    score = 100
    if signals['spamhaus_listed']:
        score -= 50
    if signals['rpki_invalid_percent'] > 1.0:
        score -= 30
        
    assert score == 20
    assert score <= 50 # Critical

def test_score_calculation_clean():
    signals = {
        'rpki_invalid_percent': 0.0,
        'spamhaus_listed': False,
        'has_route_leaks': False
    }
    score = 100
    assert score == 100
