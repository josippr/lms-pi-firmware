import time
import yaml
from collections import defaultdict
from core.sender import send_alert

import netifaces
import socket

def get_local_ips():
    ips = []
    hostname = socket.gethostname()
    try:
        ips.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            for addr in inet:
                ips.append(addr['addr'])
    return set(ips)

class RuleEngine:
    def __init__(self):
        import os
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'rules.yaml')
        with open(config_path) as f:
            self.rules = yaml.safe_load(f)['rules']
        self.history = defaultdict(list)
        self.last_alert_time = defaultdict(lambda: 0)
        self.local_ips = get_local_ips()  # ✅ Set this here

    def evaluate(self, metadata):
        now = time.time()

        src = metadata['src_ip']
        if src in self.local_ips:
            return

        for rule in self.rules:
            if rule['type'] == 'port_scan':
                # 6 = TCP, 17 = UDP
                if metadata.get('protocol') not in (6, 17): 
                    continue

                dst = metadata['dst_ip']
                dst_port = metadata.get('dst_port')

                if dst.startswith('127.'):
                    continue

                protocol = metadata.get('protocol')
                key = (dst, dst_port, protocol)
                self.history[src].append((key, now))
                self.history[src] = [(k, t) for k, t in self.history[src] if now - t <= rule['time_window']]

                unique_targets = {(dst, port, proto) for (dst, port, proto), _ in self.history[src]}
                if len(unique_targets) > rule['threshold']:
                    last_alert = self.last_alert_time.get(src, 0)
                    if now - last_alert > rule.get('alert_cooldown', 30):
                        send_alert({
                            'type': rule['name'],
                            'method': 'High port volume',
                            'source': src,
                            'ports': [port for _, port, _ in unique_targets],
                            'protocols': list({proto for _, _, proto in unique_targets}),
                            'timestamp': int(now)
                        })
                        self.last_alert_time[src] = now

            if rule['type'] == 'dns_tunnel' and metadata.get('protocol') == 17:
                query = metadata.get('dns_query', '')
                if len(query) > rule['min_length'] and query.count('.') > rule['dot_count']:
                    send_alert({
                        'type': rule['name'],
                        'query': query,
                        'source': metadata['src_ip'],
                        'timestamp': int(now)
                    })