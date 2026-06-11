import os
import sqlite3
import json

DB_PATH = "results/neongrid.db"

def init_db():
    os.makedirs("results", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
                 CREATE TABLE IF NOT EXISTS events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp TEXT,
                 event_type TEXT,
                 source TEXT,
                 data TEXT
                 )
                 """)
    conn.commit()
    conn.close()

def save_event(event: dict):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO events (timestamp, event_type, source, data) VALUES (?, ?, ?, ?)",
        (event["timestamp"], event["event_type"], event["source"], json.dumps(event))
    )
    conn.commit()
    conn.close()