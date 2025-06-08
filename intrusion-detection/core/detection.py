from scapy.layers.inet import IP, TCP, UDP
from core.rules import RuleEngine

rule_engine = RuleEngine()

def handle_packet(packet):
    if IP in packet:
        metadata = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto
        }
        if TCP in packet:
            metadata['dst_port'] = packet[TCP].dport
        rule_engine.evaluate(metadata)
