from datetime import datetime, timezone

def build_event(event_type: str, data: dict) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source": "Neongrid",
        **data
    }