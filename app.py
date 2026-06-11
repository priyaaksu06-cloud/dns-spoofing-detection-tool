from flask import Flask, render_template
import sqlite3

app = Flask(__name__)

DATABASE = "database/trusted_dns.db"


@app.route("/")
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