"""
auth/user_db.py
----------------
Stand-alone user store for authentication.

Stored in a SEPARATE SQLite database (auth/users.db) so that it is
completely independent of database/trusted_dns.db used by the DNS
detection modules. No existing tables, files, or detection logic
are touched.

Uses Werkzeug's password hashing (already a Flask dependency -
no new packages required).
"""

import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB_PATH = os.path.join(BASE_DIR, "users.db")


def init_user_db():
    """Create the users table and seed a default admin account if empty."""
    conn = sqlite3.connect(USER_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer'
        )
    """)
    conn.commit()

    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        _create_user(conn, "admin", "admin123", "admin")
        _create_user(conn, "viewer", "viewer123", "viewer")
        print("[auth] Default accounts created: admin/admin123 (admin), viewer/viewer123 (viewer)")
        print("[auth] CHANGE THESE PASSWORDS BEFORE ANY REAL DEPLOYMENT.")

    conn.close()


def _create_user(conn, username, plain_password, role):
    password_hash = generate_password_hash(plain_password)
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role),
    )
    conn.commit()


def get_user_by_username(username):
    """Return (id, username, password_hash, role) or None."""
    conn = sqlite3.connect(USER_DB_PATH)
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return row


def verify_password(plain_password, password_hash):
    return check_password_hash(password_hash, plain_password)


def add_user(username, plain_password, role="viewer"):
    """Helper for creating additional users (run manually via a script)."""
    conn = sqlite3.connect(USER_DB_PATH)
    try:
        _create_user(conn, username, plain_password, role)
        return True
    finally:
        conn.close()


def change_password(username, new_password):
    """Helper for updating a user's password."""
    conn = sqlite3.connect(USER_DB_PATH)
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (generate_password_hash(new_password), username),
    )
    conn.commit()
    conn.close()
