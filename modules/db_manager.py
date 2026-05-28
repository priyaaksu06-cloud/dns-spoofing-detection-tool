import sqlite3
from config import DATABASE_FILE


def create_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS trusted_dns (
        domain TEXT PRIMARY KEY,
        ip TEXT
    )
    ''')

    conn.commit()
    conn.close()


def save_dns_record(domain, ip):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute('''
    INSERT OR REPLACE INTO trusted_dns(domain, ip)
    VALUES(?, ?)
    ''', (domain, ip))

    conn.commit()
    conn.close()


def get_trusted_ip(domain):
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()

    cursor.execute('''
    SELECT ip FROM trusted_dns
    WHERE domain=?
    ''', (domain,))

    result = cursor.fetchone()

    conn.close()

    if result:
        return result[0]

    return None