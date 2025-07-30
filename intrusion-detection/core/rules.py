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
        self.local_ips = get_local_ips()

    def evaluate(self, metadata):
        now = time.time()
        src = metadata['src_ip']
        if src in self.local_ips:
            return

        for rule in self.rules:
            if rule['type'] == 'port_scan':
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

            if rule['type'] == 'nmap_scan' and metadata.get('protocol') == 6:  # TCP
                flags = metadata.get('tcp_flags', '')
                dst_port = metadata.get('dst_port')

                is_suspicious_flag = flags in ['F', 'N', 'X']
                
                # If suspicious flag or high-volume SYN connections
                if is_suspicious_flag:
                    self.history[src].append(('nmap_flag', now))
                else:
                    self.history[src].append((('nmap_tcp', dst_port), now))

                self.history[src] = [(k, t) for k, t in self.history[src] if now - t <= rule['time_window']]

                # Count unique TCP ports probed
                unique_ports = {k[1] for k, _ in self.history[src] if isinstance(k, tuple) and k[0] == 'nmap_tcp'}
                scan_events = [k for k, _ in self.history[src] if str(k).startswith('nmap')]

                if len(unique_ports) > rule['threshold'] or len(scan_events) > rule['threshold']:
                    last_alert = self.last_alert_time.get(f"{src}-nmap", 0)
                    if now - last_alert > rule.get('alert_cooldown', 30):
                        send_alert({
                            'type': rule['name'],
                            'method': 'Suspicious TCP port probing (possible Nmap)',
                            'source': src,
                            'flags': flags,
                            'event_count': len(scan_events),
                            'ports': list(unique_ports),
                            'timestamp': int(now)
                        })
                        self.last_alert_time[f"{src}-nmap"] = now
