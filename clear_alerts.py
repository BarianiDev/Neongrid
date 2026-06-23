import sqlite3

conn = sqlite3.connect("results/neongrid.db")
conn.execute("DELETE FROM events WHERE event_type = 'alert'")
conn.commit()
conn.close()
print("Old alerts removed.")