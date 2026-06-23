import os 
import requests

# Webhook URL comes from an environment variable, never hardcoded
WEBHOOK_URL = os.environ.get("NEONGRID_WEBHOOK_URL")

def send_alert(alert):
    """Sends a critical alert to a configured webhook (Discord, Slack, etc)"""
    if not WEBHOOK_URL:
        return # no webhook configured, skip silently

    colors = {"CRITICAL": 0xE74C3C, "HIGH": 0xE67E22, "MEDIUM": 0xF1C40F, "LOW": 0x3498DB}
    embed = {
        "title": f"[{alert['severity']}] {alert['rule']}",
        "description": alert["detail"],
        "color": colors.get(alert["severity"], 0x95A5A6),
        "fields": [
            {"name": "MITRE", "value": f"{alert.get('mitre_id', 'N/A')} - {alert.get('mitre_technique', 'N/A')}"}
        ],
     }

    try:
        requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
    
    except Exception:
        pass # a notification failure must never break detection