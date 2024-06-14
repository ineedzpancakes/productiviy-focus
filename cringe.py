import os
import time
from scapy.all import sniff, TCP

# Specify the domain to monitor
SOCIAL_MEDIA_DOMAINS = ["twitter.com"]

def shutdown():
    if os.name == 'nt':  # Windows
        os.system("shutdown /s /t 1")
    elif os.name == 'posix':  # Unix-based
        os.system("shutdown now")

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer('IP'):
        # Check if the packet has a Raw layer
        if packet.haslayer('Raw'):
            # Check the destination IP address
            payload = packet['Raw'].load.decode(errors='ignore')
            for domain in SOCIAL_MEDIA_DOMAINS:
                if domain in payload:
                    shutdown()

print("Starting network monitor. Please run this script with administrative privileges.")
sniff(prn=packet_callback, store=0)
