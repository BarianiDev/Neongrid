import os 
import requests

# Webhook URL comes from an environment variable, never hardcoded
WEBHOOK_URL = os.environ.get("NEONGRID_WEBHOOK_URL")

def send_alert(alert):
    """Sends a critical alert to a configured webhook (Discord, Slack, etc)"""
    if not WEBHOOK_URL:
        return # no webhook configured, skip silently
    
    message = (
        f"[{alert['severity']}] {alert['rule']}\n"
        f"{alert['detail']}\n"
        f"MITRE: {alert.get('mitre_id', 'N/A')} - {alert.get('mitre_technique', 'N/A')}"
    )

    try:
        requests.post(WEBHOOK_URL, json={"content": message}, timeout=5)
    
    except Exception:
        pass # a notification failure must never break detection