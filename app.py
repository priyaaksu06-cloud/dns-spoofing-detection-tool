from flask import Flask, render_template, request, redirect, url_for
import sqlite3

from auth.user_db import init_user_db
from auth.login import authenticate
from auth.session import create_session, destroy_session, get_current_user
from auth.middleware import login_required

app = Flask(__name__)

# Required for signed session cookies (used by the auth module).
# Replace with a strong, random value loaded from an environment
# variable before any real deployment.
app.secret_key = "CHANGE_ME_TO_A_RANDOM_SECRET_KEY"

# Initialize the authentication user database (auth/users.db).
# This is completely separate from database/trusted_dns.db and
# does not affect any existing DNS detection logic or data.
init_user_db()

DATABASE = "database/trusted_dns.db"


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if get_current_user():
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate(username, password)
        if user:
            create_session(user)
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    destroy_session()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def dashboard():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM dns_history"
    )
    total_requests = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM dns_history WHERE status='SAFE'"
    )
    safe_requests = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM dns_history WHERE status='SUSPICIOUS'"
    )
    suspicious_requests = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM dns_history WHERE status='NEW'"
    )
    new_domains = cursor.fetchone()[0]

    cursor.execute("""
    SELECT timestamp,
           domain,
           response,
           status
    FROM dns_history
    ORDER BY id DESC
    LIMIT 100
    """)

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "index.html",
        total_requests=total_requests,
        safe_requests=safe_requests,
        suspicious_requests=suspicious_requests,
        new_domains=new_domains,
        records=records
    )


@app.route("/alerts")
@login_required
def alerts():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT timestamp,
           domain,
           response,
           status
    FROM dns_history
    WHERE status='SUSPICIOUS'
    ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        records=records
    )


if __name__ == "__main__":
    app.run(debug=True)