from scapy.all import *
from scapy.layers import http, dns
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP, UDP, TCP


class SnifferNetwork:

    @staticmethod
    def sniffing_iface(iface):
        scapy.all.sniff(iface=iface, store=False, prn=SnifferNetwork.callback)

    @staticmethod
    def callback(packet):
        # Capture HTTP traffic
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(f"[HTTP] Visited: {url}")

        # Capture DNS traffic
        elif packet.haslayer(DNSQR):  # DNS Query Record
            domain_name = packet[DNSQR].qname.decode()
            print(f"[DNS] Requested: {domain_name}")

        # Capture HTTPS traffic (only connection details, content is encrypted)
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            if packet.haslayer(IP):
                print(f"[HTTPS] {packet[IP].src}:{packet[TCP].sport} > {packet[IP].dst}:{packet[TCP].dport}")

        # Capture TCP traffic
        elif packet.haslayer(TCP):
            if packet.haslayer(IP):
                print(f"[TCP] {packet[IP].src}:{packet[TCP].sport} > {packet[IP].dst}:{packet[TCP].dport}")

        # Capture UDP traffic
        elif packet.haslayer(UDP):
            if packet.haslayer(IP):
                print(f"[UDP] {packet[IP].src}:{packet[UDP].sport} > {packet[IP].dst}:{packet[UDP].dport}")

        # Capture all other traffic (e.g., ICMP, ARP, etc.)
        else:
            print(f"[Other] {packet.summary()}")

