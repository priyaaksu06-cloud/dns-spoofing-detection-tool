from datetime import datetime
import ipaddress

from scapy.all import DNSRR

from modules.db_manager import (
    get_trusted_ips,
    save_dns_record,
    save_history
)

from modules.alert_system import generate_alert
from modules.resolver import verify_domain


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

        domain = packet[DNSRR].rrname.decode(
            errors="ignore"
        ).rstrip(".")

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

            # NEW DOMAIN — verify with multi-resolver before trusting
            print(f"  New domain seen: {domain}. Running verification...")
            result = verify_domain(domain)

            print(f"  Trust Level : {result['trust_level']}")
            print(f"  Orgs Seen   : {result['orgs_seen']}")
            print(f"  Reason      : {result['reason']}")

            if result["trust_level"] in ("HIGH", "MEDIUM"):

                save_dns_record(domain, response)

                save_history(
                    current_time,
                    domain,
                    response,
                    "NEW",
                    org_info=str(result['orgs_seen']),
                    reason=result['reason']
                )

                print("NEW DOMAIN - VERIFIED")

            else:

                generate_alert(domain, "NONE", response)

                save_history(
                    current_time,
                    domain,
                    response,
                    "SUSPICIOUS",
                    org_info=str(result['orgs_seen']),
                    reason=result['reason']
                )

                print("LOW TRUST - ALERT RAISED, NOT SAVED")

        elif response in trusted_ips:

            save_history(
                current_time,
                domain,
                response,
                "SAFE"
            )

            print("SAFE")

        else:

            # KNOWN DOMAIN, NEW IP — verify before learning
            print(f"  Known domain {domain} returned new IP {response}. Verifying...")
            result = verify_domain(domain)

            print(f"  Trust Level : {result['trust_level']}")
            print(f"  Orgs Seen   : {result['orgs_seen']}")
            print(f"  Reason      : {result['reason']}")

            if result["trust_level"] in ("HIGH", "MEDIUM"):

                save_dns_record(domain, response)

                save_history(
                    current_time,
                    domain,
                    response,
                    "SAFE",
                    org_info=str(result['orgs_seen']),
                    reason=result['reason']
                )

                print("NEW VALID IP LEARNED - VERIFIED")

            else:

                generate_alert(domain, str(trusted_ips), response)

                save_history(
                    current_time,
                    domain,
                    response,
                    "SUSPICIOUS",
                    org_info=str(result['orgs_seen']),
                    reason=result['reason']
                )

                print("LOW TRUST - POSSIBLE SPOOFING, ALERT RAISED")

    except Exception as e:

        print("Error:", e)