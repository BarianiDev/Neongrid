import re
from collections import Counter
from Neongrid.storage.db import get_events, save_event
from Neongrid.normalizer.event_schema import build_event



def rule_critical_port():
    """Detects if a critical port is being accessed."""
    events = get_events(event_type="port_scan_result")
    alerts = []
    for e in events:
        if e.get("risk") == "CRITICAL":
            alerts.append({
                "rule": "Critical Port Exposed",
                "severity": "CRITICAL",
                "detail": f"{e.get('service')} port {e.get('port')} in {e.get('target_ip')}",
            })
    return alerts

def rule_ssh_brute_force(threshold=5):
    """Detects SSH brute force attempts based on failed login attempts."""
    events = get_events(event_type="syslog_message")
    ip_counter = Counter()

    for e in events:
        msg = e.get("message", "")
        if "Failed password" in msg or "authentication failure" in msg:
            # try to get the source IP from the message
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
            ip = match.group(1) if match else e.get("source_ip", "unknown")
            ip_counter[ip] += 1
    
    alerts = []
    for ip, count in ip_counter.items():
        if count >= threshold:
            alerts.append({
                "rule": "SSH Brute Force Detected",
                "severity": "HIGH",
                "detail": f"Detected {count} failed SSH login attempts from IP {ip}",
            })
    return alerts

def run_rules():
    """Runs all defined rules and returns a list of alerts."""
    alerts = []
    alerts.extend(rule_critical_port())
    alerts.extend(rule_ssh_brute_force())
    return alerts


def run_and_store():
    """Runs all rules and stores the alerts that don't already exist."""
    new_alerts = run_rules()

    existing = get_events(event_type="alert")
    seen = {(e.get("rule"), e.get("detail")) for e in existing}

    stored = []
    for a in new_alerts:
        signature = (a["rule"], a["detail"])
        if signature not in seen:
            save_event(build_event("alert", a))
            stored.append(a)
            seen.add(signature)  # Add to seen to avoid duplicates in the same run

    return stored