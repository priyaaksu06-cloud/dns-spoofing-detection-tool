from scapy.all import DNSRR
from modules.db_manager import get_trusted_ip, save_dns_record
from modules.alert_system import generate_alert


def analyze_packet(packet):

    if packet.haslayer(DNSRR):

        try:
            domain = packet[DNSRR].rrname.decode(errors="ignore")

            response = packet[DNSRR].rdata

            if isinstance(response, bytes):
                response = response.decode(errors="ignore")

            print("\n----------------------")
            print(f"Domain: {domain}")
            print(f"Response: {response}")

            trusted_ip = get_trusted_ip(domain)

            if trusted_ip is None:
                save_dns_record(domain, str(response))
                print("New trusted DNS record saved.")

            elif trusted_ip == str(response):
                print("SAFE DNS RESPONSE")

            else:
                generate_alert(domain, trusted_ip, str(response))

        except Exception as e:
            print(f"Error: {e}")