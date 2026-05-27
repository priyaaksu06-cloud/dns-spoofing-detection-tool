from scapy.all import sniff
from modules.packet_analyzer import analyze_packet

print("DNS Sniffer Started...")

sniff(
    filter="udp port 53",
    prn=analyze_packet,
    store=0
)