import time
import yaml
from collections import defaultdict
from core.sender import send_alert

class RuleEngine:
    def __init__(self):
        import os
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'rules.yaml')
        with open(config_path) as f:
            self.rules = yaml.safe_load(f)['rules']
        self.history = defaultdict(list)

    def evaluate(self, metadata):
        now = time.time()

        for rule in self.rules:
            # if rule['type'] == 'port_scan':
            #     src = metadata['src_ip']
            #     self.history[src].append((metadata.get('dst_port'), now))
            #     self.history[src] = [
            #         (p, t) for p, t in self.history[src] if now - t <= rule['time_window']
            #     ]
            #     unique_ports = {p for p, _ in self.history[src]}
            #     if len(unique_ports) > rule['threshold']:
            #         send_alert({
            #             'type': rule['name'],
            #             'method': 'High port volume',
            #             'source': src,
            #             'ports': list(unique_ports),
            #             'timestamp': int(now)
            #         })

            if rule['type'] == 'dns_tunnel' and metadata.get('protocol') == 17:
                query = metadata.get('dns_query', '')
                if len(query) > rule['min_length'] and query.count('.') > rule['dot_count']:
                    send_alert({
                        'type': rule['name'],
                        'query': query,
                        'source': metadata['src_ip'],
                        'timestamp': int(now)
                    })

            # if rule['type'] == 'nmap_signature':
            #     flags = metadata.get('tcp_flags', '')
            #     ttl = metadata.get('ttl', 0)
            #     window_size = metadata.get('window_size', 0)

            #     suspicious_flags = ['S', 'FPU', 'SA', 'SF']  # SYN-only, Xmas scan, etc.
            #     suspicious_ttl = ttl in [255, 128]
            #     suspicious_window = window_size in [1024, 2048, 3072, 31337]

            #     if flags in suspicious_flags or suspicious_ttl or suspicious_window:
            #         send_alert({
            #             'type': rule['name'],
            #             'method': 'Suspicious TCP signature',
            #             'source': metadata['src_ip'],
            #             'dst_port': metadata.get('dst_port'),
            #             'flags': flags,
            #             'ttl': ttl,
            #             'window_size': window_size,
            #             'timestamp': int(now)
            #         })

            # if rule['type'] == 'slow_scan':
            #     src = metadata['src_ip']
            #     self.history[src].append((metadata.get('dst_port'), now))
            #     # Keep last 5 minutes
            #     self.history[src] = [
            #         (p, t) for p, t in self.history[src] if now - t <= 300
            #     ]
            #     unique_ports = {p for p, _ in self.history[src]}
            #     if len(unique_ports) > 10:  # low volume, long window
            #         send_alert({
            #             'type': rule['name'],
            #             'method': 'Slow scan over time',
            #             'source': src,
            #             'ports': list(unique_ports),
            #             'timestamp': int(now)
            #         })
