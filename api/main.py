from fastapi import FastAPI
from Neongrid.scanner.port_scanner import run_scan
from Neongrid.engine.rules import run_rules
from Neongrid.storage.db import get_events
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],

)


@app.get("/")
def home():
    return {"message": "NeonGrid API is running"}


@app.get("/scan")
def scan(target: str, start_port: int, end_port: int):

    results = run_scan(
        target,
        start_port,
        end_port
    )

    return results

@app.get("/alerts")
def alerts():
    return {"alerts": run_rules()}


@app.get("/api/alerts")
def api_alerts():
    return get_events(event_type="alert")

@app.get("/api/scans")
def api_scans():
    return get_events(event_type="port_scan_result")