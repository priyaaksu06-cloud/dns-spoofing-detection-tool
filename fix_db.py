import sqlite3

conn = sqlite3.connect("database/trusted_dns.db")
cursor = conn.cursor()

# STEP 1: check if table exists and recreate safely
cursor.execute("DROP TABLE IF EXISTS dns_history")

cursor.execute("""
CREATE TABLE dns_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    domain TEXT,
    google_ip TEXT,
    cloudflare_ip TEXT,
    status TEXT
)
""")

conn.commit()
conn.close()

print("Database fixed successfully.")