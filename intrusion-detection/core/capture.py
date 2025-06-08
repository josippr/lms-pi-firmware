from scapy.all import sniff
from core.detection import handle_packet

def start_capture(interface='eth0'):
    sniff(iface=interface, prn=handle_packet, store=0)
