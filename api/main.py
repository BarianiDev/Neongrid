from fastapi import FastAPI
from Neongrid.scanner.port_scanner import run_scan
from Neongrid.engine.rules import run_rules

app = FastAPI()


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

