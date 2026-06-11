from datetime import datetime
import ipaddress

from scapy.all import DNSRR

from modules.db_manager import (
    get_trusted_ips,
    save_dns_record,
    save_history
)

from modules.alert_system import generate_alert


IGNORE_DOMAINS = [
    "microsoft",
    "openai",
    "cloudflare",
    "akadns",
    "edgekey",
    "bing",
    "msn"
]


def is_ipv4(ip):

    try:
        ipaddress.IPv4Address(str(ip))
        return True
    except:
        return False


def should_ignore(domain):

    domain = domain.lower()

    for word in IGNORE_DOMAINS:
        if word in domain:
            return True

    return False


def analyze_packet(packet):

    if not packet.haslayer(DNSRR):
        return

    try:

        domain = packet[DNSRR].rrname.decode(errors="ignore").rstrip(".")

        response = str(packet[DNSRR].rdata)

        if should_ignore(domain):
            return

        if not is_ipv4(response):
            return

        print("\n====================")
        print(f"Domain: {domain}")
        print(f"Response: {response}")

        current_time = str(datetime.now())

        trusted_ips = get_trusted_ips(domain)

        if len(trusted_ips) == 0:

            save_dns_record(domain, response)

            save_history(
                current_time,
                domain,
                response,
                "NEW"
            )

            print("NEW DOMAIN")

        elif response in trusted_ips:

            save_history(
                current_time,
                domain,
                response,
                "SAFE"
            )

            print("SAFE")

        else:

            save_dns_record(
                domain,
                response
            )

            save_history(
                current_time,
                domain,
                response,
                "SAFE"
            )

            print("NEW VALID IP LEARNED")

    except Exception as e:
        print("Error:", e)