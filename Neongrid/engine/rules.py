import re
from collections import Counter
from Neongrid.storage.db import get_events, save_event
from Neongrid.normalizer.event_schema import build_event
from Neongrid.notifier.webhook import send_alert
from Neongrid.enrichment.threat_intel import load_knowbn_bad_ips



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
                "mitre_ide": "T1133",
                "mitre_technique": "External Remote Services"
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
                "mitre_id": "T1110",
                "mitre_technique": "Brute Force"
            })
    return alerts

def run_rules():
    """Runs all defined rules and returns a list of alerts."""
    alerts = []
    alerts.extend(rule_critical_port())
    alerts.extend(rule_ssh_brute_force())
    alerts.extend(rule_port_scan_detected())
    alerts.extend(rule_brute_force_success())
    alerts.extend(rule_cleartext_service())
    alerts.extend(rule_high_attack_surface())
    alerts.extend(rule_known_malicious_ip())
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
            if a["severity"] == "CRITICAL":
                send_alert(a) # notify critical alerts
            stored.append(a)
            seen.add(signature)  # Add to seen to avoid duplicates in the same run

    return stored

def rule_port_scan_detected(threshold=10):
    """Detects por scanning: many distrinct ports found on the same target."""
    events = get_events(event_type="port_scan_result")
    ports_per_target = {}

    for e in events:
        target = e.get("target_ip", "unknown")
        port = e.get("port")
        ports_per_target.setdefault(target, set()).add(port)
    
    alerts = []
    for target, ports in ports_per_target.items():
        if len(ports) >= threshold:
            alerts.append({
                "rule": "Port Scan Detected",
                "severity": "MEDIUM",
                "detail": f"{len(ports)} distinct ports in {target}",
                "mitre_id": "T1046",
                "mitre_technique": "Network Service Discovery"

            })

    return alerts


def rule_brute_force_success(threshold=5):
    """Detects a successful login from an IP that had many failed attempts."""
    events = get_events(event_type="syslog_message")
    failed = Counter()
    succeeded = set()

    for e in events:
        msg = e.get("message", "")
        ip_match = re.search(r"from(\d+\.\d+\.\d+\.\d+)", msg)
        ip = ip_match.group(1) if ip_match else e.get("source_ip", "unknown")

        if "Failed password" in msg or "authentication failure" in msg:
            failed[ip] += 1
        
        elif "Accepted password" in msg or "session opened" in msg:
            succeeded.add(ip)

    alerts = []
    for ip in succeeded:
        if failed[ip] >= threshold:
            alerts.append({
                "rule": "Brute Force Succeeded",
                "severity": "CRITICAL",
                "detail": f"Succeeded login from {ip} after {failed[ip]} times",
                "mitre_id": "T1110",
                "mitre_technique": "Brute Force"
            })
    
    return alerts

def rule_cleartext_service():
    """Detects services that transmit data/credentials without encryption"""
    events = get_events(event_type="port_scan_result")
    cleartext_ports = {21: "FTP", 23: "Telenet", 25: "SMTP"}
    alerts = []
    seen = set()

    for e in events:
        port = e.get("port")
        target = e.get("target_ip")
        if port in cleartext_ports and (port, target) not in seen:
            seen.add((port, target))
            alerts.append({
                "rule": "Cleartext Service Exposed",
                "severity": "HIGH",
                "detail": f"{cleartext_ports[port]} (port {port}) in {target} send data without cryptography",
                "mitre_id": "T1040",
                "mitre_technique": "Network Sniffing"
            })
    
    return alerts

def rule_high_attack_surface(threshold=3):
    """Detects hosts exposing several high-risk services at once."""
    events = get_events(event_type="port_scan_result")
    risky_per_target = {}

    for e in events:
        if e.get("risk") in ("HIGH", "CRITICAL"):
            target = e.get("target_ip", "unknown")
            risky_per_target.setdefault(target, set()).add(e.get("port"))
    
    alerts = []
    for target, ports in risky_per_target.items():
        if len(ports) >= threshold:
            alerts.append({
                "rule": "High Attack Surface",
                "severity": "HIGH",
                "detail": f"{target} expose {len(ports)} services high risk rate"
            })

    return alerts


def rule_known_malicious_ip():
    """Flags activity from IPs present in the threat intelligence feed."""
    events = get_events(event_type="syslog_message")
    known_bad = load_knowbn_bad_ips()
    alerts = []
    seen = set()

    for e in events:
        msg = e.get("message", "")
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", msg)
        ip = ip_match.group(1) if ip_match else e.get("source_ip")

        if ip in known_bad and ip not in seen:
            seen.add(ip)
            alerts.append({
                "rule": "Known Malicious IP",
                "severity": "CRITICAL",
                "detail": f"Suspicious activity from known ips {ip}"
            })
    
    return alerts