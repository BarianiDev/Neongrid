import os 
import sqlite3
from Neongrid.storage.db import init_db, save_event

TEST_DB = "results/test_results.db"
def setup_function():
    
    import Neongrid.storage.db as db_module
    db_module.DB_PATH = TEST_DB
    init_db()

def teardown_function():

    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    
def test_save_and_retrieve_event():
    import Neongrid.storage.db as db_module
    db_module.DB_PATH = TEST_DB
    event = {
        "timestamp": "2026-06-09T00:00:00+00:00",
        "event_type": "port_scan_result",
        "source": "Neongrid",
        "port": 22
    }

    save_event(event)
    conn = sqlite3.connect(TEST_DB)
    row = conn.execute("SELECT event_type FROM events").fetchone()
    conn.close()
    assert row[0] == "port_scan_result"