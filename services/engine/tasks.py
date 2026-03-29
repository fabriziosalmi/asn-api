# Copyright by Fabrizio Salmi (fabrizio.salmi@gmail.com)

import logging

from celery import Celery
from pythonjsonlogger.json import JsonFormatter as JsonLogFormatter

from engine_settings import EngineSettings
from scorer import RiskScorer

# --- Config ---
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
logger = logging.getLogger("engine.tasks")

app = Celery("tasks", broker=settings.broker_url)
scorer = RiskScorer()


@app.task(bind=True)
def calculate_asn_score(self, asn: int, trace_id: str = "") -> int:
    """
    Celery task to recalculate the risk score for a given ASN.
    Accepts an optional trace_id for distributed tracing correlation.
    """
    extra = {"asn": asn, "trace_id": trace_id, "task_id": self.request.id}
    try:
        logger.info("task_received", extra=extra)
        final_score = scorer.calculate_score(asn, trace_id=trace_id)
        logger.info("task_complete", extra={**extra, "score": final_score})
        return final_score
    except Exception as e:
        logger.error("task_failed", extra={**extra, "error": str(e)})
        raise
