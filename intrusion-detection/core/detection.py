from scapy.layers.inet import IP, TCP, UDP
from core.rules import RuleEngine

rule_engine = RuleEngine()

def classify_tcp_flags(flags):
    # NULL scan: no flags set
    if flags == 0:
        return 'N'
    # FIN scan: only FIN flag set
    elif flags == 0x01:
        return 'F'
    # XMAS scan: FIN + PSH + URG (0x01 + 0x08 + 0x20 = 0x29)
    elif flags & 0x29 == 0x29:
        return 'X'
    return ''  # not suspicious

def handle_packet(packet):
    if IP in packet:
        metadata = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto
        }

        if TCP in packet:
            metadata['dst_port'] = packet[TCP].dport
            flags = packet[TCP].flags
            metadata['tcp_flags'] = classify_tcp_flags(flags)
        elif UDP in packet:
            metadata['dst_port'] = packet[UDP].dport
        else:
            return  # not TCP or UDP

        rule_engine.evaluate(metadata)
