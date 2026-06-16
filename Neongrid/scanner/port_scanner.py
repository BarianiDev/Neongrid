import socket
import threading
import time
import json
import logging
from Neongrid.analyzer.risk_engine import analyze_port
from queue import Queue
from Neongrid.normalizer.event_schema import build_event
from Neongrid.storage.db import init_db, save_event
from Neongrid.enrichment.cve_lookup import enrich_with_cves


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
) 

logger = logging.getLogger(__name__)

max_threads = 100
semaphore = threading.BoundedSemaphore(value=max_threads)


PORT_SERVICES = { 
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    25: "SMTP",
    21: "FTP",
    3306: "MySQL",
}


def scan_port(ip, port, result_queue):

    with semaphore:
        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((ip, port))

            if result == 0:

                service = PORT_SERVICES.get(port, "Unknown")

                logger.info(json.dumps({
                    "event": "Port Open",
                    "port": port,
                    "service": service

                }))

                banner = get_banner(ip, port)

                analysis = analyze_port(port)

                if banner:
                    logger.info(json.dumps({
                        "event": "Banner Retrieved", 
                        "port": port, 
                        "banner": banner
                        }))

                cves = enrich_with_cves(service, banner)

                event = build_event("port_scan_result", {
                    "target_ip": ip,
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "risk": analysis["risk"],
                    "description": analysis["description"],
                    "cves": cves
                })

                save_event(event)
                result_queue.put({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "risk": analysis["risk"],
                    "description": analysis["description"],
                    "cves": cves
                    })

            sock.close()

        except socket.error:
            pass


def get_banner(ip, port):

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        sock.connect((ip, port))

        banner = sock.recv(1024).decode().strip()

        sock.close()

        return banner
    
    except Exception:
        return None


def run_scan(target_ip, start_port, end_port):
    init_db()
    result_queue = Queue()
    threads = []

    start_time = time.time()

    

    for port in range(start_port, end_port +1):

        thread = threading.Thread(
            target=scan_port,
            args=(target_ip, port, result_queue)
        )

        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    scan_duration = round(time.time() - start_time, 2)

    results = list(result_queue.queue)

    risk_score_total = calculate_risk_score(results)

    attack_surface = build_attack_surface(results)

    

    return {
        "target_ip": target_ip,
        "scan_duration": scan_duration,
        "risk_score_total": risk_score_total,
        "attack_surface_summary": attack_surface,
        "open_ports": results,
    }


def calculate_risk_score(results):

    score = 0

    for r in results:

        risk = r.get("risk", "UNKNOWN")

        if risk == "CRITICAL":
            score += 5
        
        elif risk == "HIGH":
            score += 4

        elif risk == "MEDIUM":
            score += 2

        elif risk == "LOW":
            score += 1
    
    return round(score, 2)



def build_attack_surface(results):

    exposed = []
    risks = []
    recommendations = []


    for r in results:

        service = r.get("service", "Unknown")
        port = r.get("port")

        exposed.append(f"{service} exposed on port {port}")

        risk = r.get("risk", "UNKNOWN")

        if risk in ["CRITICAL", "HIGH"]:
            risks.append(f"{service} on port {port} has {risk} risk rating")

        if service == "SSH":
            recommendations.append("Consider using a VPN or firewall to restrict SSH access")

        elif service == "MySQL":
            recommendations.append("Do not expose database to the public internet")

        elif service == "FTP":
            recommendations.append("Use SFTP")

    return {
        "exposed_services": exposed,
        "main_risks": risks,
        "recommendations": recommendations
    }