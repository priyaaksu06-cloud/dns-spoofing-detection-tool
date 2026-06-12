"""
auth/session.py
-----------------
Session lifecycle helpers built on Flask's signed-cookie session.
"""

import time
from flask import session

# Auto-logout after this many seconds of inactivity (15 minutes)
SESSION_TIMEOUT_SECONDS = 15 * 60


def create_session(user):
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["last_activity"] = time.time()
    session.permanent = True


def destroy_session():
    session.clear()


def touch_session():
    session["last_activity"] = time.time()


def is_session_valid():
    if "user_id" not in session:
        return False

    last_activity = session.get("last_activity", 0)
    if time.time() - last_activity > SESSION_TIMEOUT_SECONDS:
        session.clear()
        return False

    return True


def get_current_user():
    if not is_session_valid():
        return None
    return {
        "id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("role"),
    }
