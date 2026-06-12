import sqlite3
conn = sqlite3.connect('database/trusted_dns.db')
cursor = conn.cursor()
cursor.execute("SELECT timestamp, domain, status FROM dns_history WHERE domain NOT LIKE '%protechts%' ORDER BY id DESC LIMIT 20")
rows = cursor.fetchall()
for r in rows:
    print(r)
conn.close()