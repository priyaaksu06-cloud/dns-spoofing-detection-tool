from colorama import Fore
from datetime import datetime
from config import LOG_FILE


def log_alert(message):
    with open(LOG_FILE, "a") as file:
        file.write(message + "\n")


def generate_alert(domain, real_ip, fake_ip):
    timestamp = datetime.now()

    message = (
        f"[{timestamp}] DNS SPOOF DETECTED | "
        f"Domain: {domain} | "
        f"Trusted IP: {real_ip} | "
        f"Received IP: {fake_ip}"
    )

    print(Fore.RED + message)
    log_alert(message)