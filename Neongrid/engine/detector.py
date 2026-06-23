import time
import json
import logging
from Neongrid.engine.rules import run_and_store

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 30

def run_continuous():
    logger.info(json.dumps({
        "event": "Detection Engine Started",
        "interval_seconds": INTERVAL_SECONDS
    }))

    while True:
        new_alerts = run_and_store()
        if new_alerts:
            logger.info(json.dumps({
                "event": "New Alerts Detected",
                "count": len(new_alerts)
            }))
        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    run_continuous()