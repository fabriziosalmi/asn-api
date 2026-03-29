# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import os
import logging

from celery import Celery
from scorer import RiskScorer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("engine.tasks")

broker_url = os.getenv("BROKER_URL", "redis://broker-cache:6379/0")
app = Celery("tasks", broker=broker_url)

scorer = RiskScorer()


@app.task
def calculate_asn_score(asn: int) -> int:
    """
    Celery task to recalculate the risk score for a given ASN.
    Triggered by:
    - Cron schedule (daily for everyone)
    - Event (new threat detected for specific ASN)
    """
    try:
        logger.info("task_received asn=%s", asn)
        final_score = scorer.calculate_score(asn)
        return final_score
    except Exception as e:
        logger.error("task_failed asn=%s error=%s", asn, e)
        raise
