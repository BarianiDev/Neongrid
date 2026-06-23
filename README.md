# NeonGrid

![CI](https://github.com/BarianiDev/Neongrid/actions/workflows/ci.yml/badge.svg)

A modular purple-team security platform built in Python. It covers the full SIEM
cycle: collect, normalize, store, detect, notify and visualize.

## Features

- TCP port scanning with multithreading
- Risk profiling per service (CRITICAL / HIGH / MEDIUM / LOW)
- Banner grabbing and CVE enrichment via the NVD (NIST) API
- Syslog log ingestion over UDP
- Detection engine with event correlation, mapped to MITRE ATT&CK
- Real-time alert notifications (Discord / Slack webhook)
- Continuous, autonomous detection
- Live dashboard (Streamlit) with auto-refresh
- Fully containerized with Docker Compose
- Automated tests running in CI (GitHub Actions)

## Detection Rules

| Rule                      | Severity | MITRE ATT&CK              |
|---------------------------|----------|---------------------------|
| SSH Brute Force           | HIGH     | T1110 Brute Force         |
| Brute Force Succeeded     | CRITICAL | T1110 Brute Force         |
| Port Scan Detected        | MEDIUM   | T1046 Network Service Discovery |
| Cleartext Service Exposed | HIGH     | T1040 Network Sniffing    |
| Critical Port Exposed     | CRITICAL | T1133 External Remote Services |
| High Attack Surface       | HIGH     | exposure (not a technique)|

## Project Structure

NeonGrid/

├── .github/workflows/   # CI pipeline (GitHub Actions)

├── api/                 # FastAPI REST interface

├── dashboard/           # Streamlit dashboard

├── Neongrid/

│   ├── scanner/         # Port scanning engine

│   ├── analyzer/        # Risk profiling

│   ├── enrichment/      # CVE lookup (NVD API)

│   ├── collector/       # Syslog receiver

│   ├── engine/          # Detection rules + continuous detector

│   ├── notifier/        # Webhook notifications

│   ├── normalizer/      # Event schema standardization

│   └── storage/         # SQLite persistence

├── tests/               # Automated tests

└── results/             # Generated database

## How to Run

Configure a webhook (optional, for notifications) in a `.env` file:
NEONGRID_WEBHOOK_URL=https://discord.com/api/webhooks/...

Start the whole platform:

```bash
docker compose up --build
```

- API:       http://localhost:8000/docs
- Dashboard: http://localhost:8501

## Running Tests

```bash
pytest tests/ -v
```

## Roadmap

- [x] CVE enrichment, syslog ingestion, detection engine, dashboard
- [x] Notifications, continuous detection, Docker, CI
- [ ] PostgreSQL backend
- [ ] Threat intelligence enrichment
- [ ] React frontend
