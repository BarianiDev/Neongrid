import socket
import json
import logging
from Neongrid.normalizer.event_schema import build_event
from Neongrid.storage.db import init_db, save_event

logger = logging.getLogger(__name__)

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = 5140 

SEVERITY_LEVELS = {
    0: "EMERGENCY",
    1: "ALERT",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG"
}


def parse_priority(message: str):

    if message.startswith("<"):
        end = message.find(">")
        if end != -1:
            try:
                priority = int(message[1:end])
                facility = priority // 8
                severity = priority % 8
                rest = message[end + 1:]
                return facility, severity, rest
            except ValueError:
                pass
    return None, None, message


def start_syslog_server():

    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_HOST, SYSLOG_PORT))

    logger.info(json.dumps({
        "event": "Syslog Receiver Started",
        "host": SYSLOG_HOST,
        "port": SYSLOG_PORT
    }))

    while True:
        data, addr = sock.recvfrom(4096)
        raw_message = data.decode(errors="replace").strip()
        facility, severity, message = parse_priority(raw_message)

        event = build_event("syslog_message", {
            "source_ip": addr[0],
            "facility": facility,
            "severity": SEVERITY_LEVELS.get(severity, "UNKNOWN"),
            "message": message,
            "raw": raw_message
        })

        save_event(event)

        logger.info(json.dumps({
            "event": "Syslog Received",
            "source_ip": addr[0],
            "severity": SEVERITY_LEVELS.get(severity, "UNKNOWN")
        }))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    start_syslog_server()
