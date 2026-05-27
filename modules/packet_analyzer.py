from scapy.all import DNSRR


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

        except Exception as e:
            print(f"Error: {e}")