"""
auth/middleware.py
--------------------
Decorators for protecting routes.

- @login_required      -> for HTML page routes (redirects to /login)
- @api_login_required  -> for JSON API endpoints (401 JSON response)
- @role_required(role) -> restrict to a specific role (e.g. "admin")
"""

from functools import wraps
from flask import redirect, url_for, jsonify
from auth.session import is_session_valid, get_current_user, touch_session


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not is_session_valid():
            return redirect(url_for("login_page"))
        touch_session()
        return view_func(*args, **kwargs)
    return wrapped


def api_login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not is_session_valid():
            return jsonify({"error": "Unauthorized access"}), 401
        touch_session()
        return view_func(*args, **kwargs)
    return wrapped


def role_required(required_role):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is None:
                return redirect(url_for("login_page"))
            if user["role"] != required_role:
                return jsonify({"error": "Forbidden: insufficient privileges"}), 403
            return view_func(*args, **kwargs)
        return wrapped
    return decorator
