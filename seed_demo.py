from Neongrid.normalizer.event_schema import build_event
from Neongrid.storage.db import init_db, save_event

init_db()
TARGET = "192.0.2.10" # fake documentation IP

# vulnerable host: FTP + Telnet + MySQL + SSH
fake_ports = [
    {"port": 21, "service": "FTP", "risk": "HIGH", "description": "FTP transmits credentials in plaintext" },
    {"port": 23, "service": "Telnet", "risk": "CRITICAL", "description": "Telnet exposes credentials in plaintext"},
    {"port": 3306, "service": "MySQL", "risk": "HIGH", "description": "MySQL database exposed"},
    {"port": 22, "service": "SSH", "risk": "MEDIUM", "description": "SSH exposed for remote access"},
]

for p in fake_ports:
    save_event(build_event("port_scan_result", {
        "target_ip": TARGET, "port": p["port"], "service": p["service"],
        "banner": None, "risk": p["risk"], "description": p["description"],
    }))

# Brute force success scenario (failures + one accepted)
ATTACKER = "198.51.100.50"

for _ in range(6):
    save_event(build_event("syslog_message", {
        "source_ip": ATTACKER, "severity": "INFO",
        "message": f"Failed password for root from {ATTACKER}",
    }))

save_event(build_event("syslog_message", {
    "source_ip": ATTACKER, "severity": "INFO",
    "message": f"Accepted password for root from {ATTACKER}",
}))

print("Demo data injected.")