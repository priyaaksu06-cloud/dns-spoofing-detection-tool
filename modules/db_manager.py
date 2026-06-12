import sqlite3
from config import DATABASE_FILE


def create_database():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trusted_dns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        ip TEXT,
        UNIQUE(domain, ip)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dns_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        response TEXT,
        status TEXT,
        org_info TEXT,
        reason TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_dns_record(domain, ip):

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR IGNORE INTO trusted_dns(domain, ip)
    VALUES (?, ?)
    """, (domain, ip))

    conn.commit()
    conn.close()


def get_trusted_ips(domain):

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip
    FROM trusted_dns
    WHERE domain = ?
    """, (domain,))

    results = cursor.fetchall()

    conn.close()

    return [row[0] for row in results]


def save_history(timestamp, domain, response, status, org_info="", reason=""):

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO dns_history (
        timestamp,
        domain,
        response,
        status,
        org_info,
        reason
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, domain, response, status, org_info, reason))

    conn.commit()
    conn.close()


def get_history():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp, domain, response, status, org_info, reason
    FROM dns_history
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_alerts():

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp, domain, response, status, org_info, reason
    FROM dns_history
    WHERE status='SUSPICIOUS'
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows