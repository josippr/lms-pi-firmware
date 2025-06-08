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
            if rule['type'] == 'port_scan':
                src = metadata['src_ip']
                self.history[src].append((metadata.get('dst_port'), now))
                self.history[src] = [
                    (p, t) for p, t in self.history[src] if now - t <= rule['time_window']
                ]
                unique_ports = {p for p, _ in self.history[src]}
                if len(unique_ports) > rule['threshold']:
                    send_alert({
                        'type': rule['name'],
                        'source': src,
                        'ports': list(unique_ports),
                        'timestamp': int(now)
                    })

            if rule['type'] == 'dns_tunnel' and metadata.get('protocol') == 17:
                query = metadata.get('dns_query', '')
                if len(query) > rule['min_length'] and query.count('.') > rule['dot_count']:
                    send_alert({
                        'type': rule['name'],
                        'query': query,
                        'source': metadata['src_ip'],
                        'timestamp': int(now)
                    })
