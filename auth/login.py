"""
auth/login.py
--------------
Validates a username/password pair against auth/users.db.
"""

from auth.user_db import get_user_by_username, verify_password


def authenticate(username, password):
    """
    Return {"id", "username", "role"} on success, or None on failure.
    """
    if not username or not password:
        return None

    row = get_user_by_username(username)
    if row is None:
        return None

    user_id, db_username, password_hash, role = row

    if not verify_password(password, password_hash):
        return None

    return {"id": user_id, "username": db_username, "role": role}
