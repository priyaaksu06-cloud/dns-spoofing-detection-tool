from scapy.all import sniff, get_if_list

from modules.packet_analyzer import analyze_packet
from modules.db_manager import create_database

print("DNS Sniffer Started...")

create_database()

interfaces = get_if_list()
print(f"Sniffing on interfaces: {interfaces}")

sniff(
    iface=interfaces,
    filter="udp port 53",
    prn=analyze_packet,
    store=0
)