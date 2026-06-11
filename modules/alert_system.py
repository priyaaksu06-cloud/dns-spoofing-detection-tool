from datetime import datetime
from config import LOG_FILE


def log_alert(message):
    with open(LOG_FILE, "a") as file:
        file.write(message + "\n")


def generate_alert(domain, trusted_ip, received_ip):

    message = (
        f"[{datetime.now()}] DNS SPOOF DETECTED | "
        f"Domain: {domain} | "
        f"Trusted IP: {trusted_ip} | "
        f"Received IP: {received_ip}"
    )

    print("\n🚨 ALERT 🚨")
    print(message)

    log_alert(message)