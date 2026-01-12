from celery import Celery
import os
from scorer import RiskScorer

broker_url = os.getenv('BROKER_URL', 'redis://broker-cache:6379/0')
app = Celery('tasks', broker=broker_url)

# Instantiate scorer once (conn pool handling handled by SQLAlchemy)
scorer = RiskScorer()

@app.task
def calculate_asn_score(asn):
    """
    Celery task to recalculate the risk score for a given ASN.
    Triggered by:
    - Cron schedule (daily for everyone)
    - Event (new threat detected for specific ASN)
    """
    try:
        print(f"[Task] Received scoring request for ASN {asn}")
        final_score = scorer.calculate_score(asn)
        return final_score
    except Exception as e:
        print(f"[Task] Error calculating score for ASN {asn}: {e}")
        raise e

