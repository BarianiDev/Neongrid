# What is NeonGrid?
NeonGrid is a security tool focused on port scanning with risk analysis,
currently evolving into a full SIEM (Security Information and Event Management)
platform with penetration testing capabilities — a purple team approach.

It covers the full SIEM cycle: collect → normalize → store → detect → visualize.

## Features
- TCP port scanning with multithreading
- Risk profiling per service (CRITICAL / HIGH / MEDIUM / LOW)
- Banner grabbing for service fingerprinting
- CVE enrichment via the NVD (NIST) API
- Attack surface analysis with recommendations
- Syslog log ingestion over UDP
- Detection rules engine with event correlation (e.g. SSH brute force)
- Alert persistence with deduplication
- Structured JSON logging
- Event persistence with SQLite
- REST API via FastAPI
- Streamlit dashboard for visualization

# Project Structure 
NeonGrid/

├── api/                  # FastAPI REST interface

├── dashboard/            # Streamlit dashboard

├── Neongrid/

│   ├── scanner/          # Port scanning engine

│   ├── analyzer/         # Risk profiling per port/service

│   ├── enrichment/       # CVE lookup via NVD API

│   ├── collector/        # Syslog receiver (log ingestion)

│   ├── engine/           # Detection rules engine

│   ├── normalizer/       # Event schema standardization

│   └── storage/          # SQLite persistence

├── tests/                # Automated tests

└── results/              # Generated database


## How to Run
# Install dependencies
Install dependencies:

```bash
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn api.main:app --reload
```

Start the syslog receiver (separate terminal):

```bash
python -m Neongrid.collector.syslog_receiver
```

Open the dashboard (separate terminal, from project root):

```bash
streamlit run dashboard/app.py
```

## API Usage
GET /scan?target=scanme.nmap.org&start_port=1&end_port=100

GET /alerts

## Running Tests
pytest tests/ -v

## Roadmap

- [x] CVE lookup via NVD API
- [x] Syslog receiver
- [x] Detection rules engine
- [x] Dashboard
- [ ] Continuous detection (scheduled rule evaluation)
- [ ] More detection rules
- [ ] React frontend
- [ ] Docker deployment