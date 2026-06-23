import sqlite3

conn = sqlite3.connect("results/neongrid.db")
conn.execute("DELETE FROM events") # DEleteeverything: scans, syslog and alerts
conn.commit()
conn.close()
print("Database reset.")