import os
import time
import threading
import yaml
import requests
from dotenv import load_dotenv
from datetime import datetime
from scapy.all import sniff, IP, TCP
from collections import defaultdict

# === Load environment variables ===
load_dotenv()

CONFIG_FILE = os.getenv("CONFIG_FILE")
CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY = os.getenv("CLIENT_KEY")
API_ENDPOINT = os.getenv("API_ENDPOINT")
CA_CERT = "/etc/ssl/certs/ca-certificates.crt"
SEND_INTERVAL = 300  # 5 minutes
has_sent_once = False

# === Read YAML Config ===
def read_config(path):
    try:
        with open(path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"[ERROR] Could not read config file: {e}")
        return {}

# === Global Stats ===
stats = {
    "start_time": time.time(),
    "bytes_total": 0,
    "packet_count": 0,
    "active_devices": set(),
    "rtts": [],
    "retransmissions": 0,
    "out_of_order": 0,
    "jitter_values": []
}

# === Flow Trackers ===
syn_times = {}  # key: (src, dst, dport)
tcp_seq_map = defaultdict(int)
last_arrival_times = {}

# === Packet Handler ===
def analyze_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    stats["bytes_total"] += len(pkt)
    stats["packet_count"] += 1
    # track only devices with local ip
    for ip in [src, dst]:
        if ip.startswith("192.168.178."):
            stats["active_devices"].add(ip)

    now = time.time()
    flow_key = (src, dst)

    # Jitter estimation
    if flow_key in last_arrival_times:
        delta = now - last_arrival_times[flow_key]
        stats["jitter_values"].append(delta)
    last_arrival_times[flow_key] = now

    # TCP-specific analysis
    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        seq = tcp_layer.seq
        ack = tcp_layer.ack
        flags = tcp_layer.flags
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flow = (src, dst, sport, dport)

        # RTT from SYN → SYN-ACK
        if flags == 'S':
            syn_times[(src, dst, dport)] = now
        elif flags == 'SA':
            key = (dst, src, sport)
            if key in syn_times:
                rtt = (now - syn_times.pop(key)) * 1000
                stats["rtts"].append(rtt)

        # Retransmission and OoO detection
        if flow in tcp_seq_map:
            if seq < tcp_seq_map[flow]:
                stats["out_of_order"] += 1
            elif seq == tcp_seq_map[flow]:
                stats["retransmissions"] += 1
        tcp_seq_map[flow] = seq

# === Send Collected Metrics ===
def send_metrics():
    global stats, has_sent_once

    config = read_config(CONFIG_FILE)
    device_id = config.get("UID", "unknown")
    now = time.time()
    duration = now - stats["start_time"]

    bandwidth_kbps = (stats["bytes_total"] * 8) / duration / 1000 if duration > 0 else 0
    avg_rtt = sum(stats["rtts"]) / len(stats["rtts"]) if stats["rtts"] else None
    jitter = sum(stats["jitter_values"]) / len(stats["jitter_values"]) if stats["jitter_values"] else None
    loss_percent = (stats["retransmissions"] / stats["packet_count"]) * 100 if stats["packet_count"] else 0

    payload = {
        "deviceId": device_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "payload": {
            "networkStatus": {
                "bandwidthKbps": round(bandwidth_kbps, 2),
                "packetCount": stats["packet_count"],
                "deviceCount": len(stats["active_devices"]),
                "activeDevices": list(stats["active_devices"]),
                "avgRttMs": round(avg_rtt, 2) if avg_rtt else None,
                "packetLossPercent": round(loss_percent, 2),
                "outOfOrderCount": stats["out_of_order"],
                "jitterMs": round(jitter * 1000, 2) if jitter else None
            }
        }
    }

    if not has_sent_once:
        print("[MONITOR] Skipping first metrics send to avoid inaccurate zero/null values.")
        has_sent_once = True
    else:
        print("[MONITOR] Preparing to send network metrics...")
        print(f"[MONITOR] Payload: {payload}")

        try:
            print("[MONITOR] Sending network metrics...")
            response = requests.post(
                API_ENDPOINT,
                json=payload,
                headers={
                    'Content-Type': 'application/json',
                    'X-SSL-Client-Verify': 'SUCCESS'
                },
                cert=(CLIENT_CERT, CLIENT_KEY),
                verify=CA_CERT,
                timeout=30
            )
            response.raise_for_status()
            print("[MONITOR] Network metrics sent successfully.")
        except requests.exceptions.SSLError as e:
            print(f"[SSL ERROR] Certificate verification failed: {e}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Failed to send network metrics: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response content: {e.response.text}")

    # Reset stats for the next interval
    stats.update({
        "start_time": time.time(),
        "bytes_total": 0,
        "packet_count": 0,
        "active_devices": set(),
        "rtts": [],
        "retransmissions": 0,
        "out_of_order": 0,
        "jitter_values": []
    })

    # Schedule next run
    threading.Timer(SEND_INTERVAL, send_metrics).start()

# === Start Monitoring ===
if __name__ == "__main__":
    print("[MONITOR] Starting network monitoring...")
    send_metrics()
    sniff(prn=analyze_packet, store=0, iface="eth0")
