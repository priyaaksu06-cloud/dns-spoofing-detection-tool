from scapy.all import sniff
from modules.packet_analyzer import analyze_packet
from modules.db_manager import create_database

print("DNS Sniffer Started...")

create_database()

sniff(
    filter="udp port 53",
    prn=analyze_packet,
    store=0
)