import os
import time
import threading
import yaml
import requests
from dotenv import load_dotenv
from datetime import datetime
from scapy.all import sniff, IP
import subprocess
import psutil

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
    "packet_count": 0,
    "active_devices": set(),
}

# === Utility: Ping Latency and Jitter ===
def ping_latency_jitter(target="192.168.178.1", count=10):
    try:
        output = subprocess.check_output(["ping", "-c", str(count), "-W", "1", target], universal_newlines=True)
        times = [float(line.split("time=")[1].split(" ms")[0])
                 for line in output.split("\n") if "time=" in line]
        if times:
            avg = sum(times) / len(times)
            jitter = max(times) - min(times)
            return avg, jitter
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Ping failed: {e.output}")
    return None, None

# === Packet Handler ===
def analyze_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    stats["packet_count"] += 1

    for ip in [src, dst]:
        if ip.startswith("192.168.178."):
            stats["active_devices"].add(ip)

# === Get Max Bandwidth (Kbps) ===
def get_max_bandwidth_kbps(interface="eth0"):
    try:
        output = subprocess.check_output(["ethtool", interface], universal_newlines=True)
        for line in output.splitlines():
            if "Speed:" in line:
                # Example: "Speed: 1000Mb/s"
                speed_str = line.split("Speed:")[1].strip()
                if speed_str.endswith("Mb/s"):
                    mbps = int(speed_str.replace("Mb/s", "").strip())
                    return mbps * 1000  # Convert to Kbps
    except Exception as e:
        print(f"[WARNING] Failed to detect NIC speed: {e}")
    return 1000000  # Fallback: assume 1 Gbps


MAX_BANDWIDTH_KBPS = get_max_bandwidth_kbps("eth0")

# === Send Collected Metrics ===
def send_metrics():
    global stats, has_sent_once

    config = read_config(CONFIG_FILE)
    device_id = config.get("UID", "unknown")
    now = time.time()
    duration = now - stats["start_time"]

    # Bandwidth via psutil (real interface counters)
    net_io = psutil.net_io_counters()
    bandwidth_kbps = ((net_io.bytes_recv + net_io.bytes_sent) * 8) / duration / 1000 if duration > 0 else 0

    # Latency and jitter via ping
    ping_avg_latency, jitter = ping_latency_jitter()

    payload = {
        "deviceId": device_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "payload": {
            "networkStatus": {
                "bandwidthKbps": round(bandwidth_kbps, 2),
                "maxBandwidthKbps": MAX_BANDWIDTH_KBPS,
                "packetCount": stats["packet_count"],
                "deviceCount": len(stats["active_devices"]),
                "activeDevices": list(stats["active_devices"]),
                "avgRttMs": None,
                "packetLossPercent": 0.0,
                "outOfOrderCount": 0,
                "jitterMs": round(jitter, 2) if jitter is not None else None,
                "pingLatencyMs": round(ping_avg_latency, 2) if ping_avg_latency is not None else None
            }
        }
    }

    print(f"[MONITOR] Collected metrics: {payload['payload']['networkStatus']}")

    if not has_sent_once:
        print("[MONITOR] Skipping first metrics send to avoid inaccurate zero/null values.")
        has_sent_once = True
    else:
        try:
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

    # Reset stats for next interval
    stats.update({
        "start_time": time.time(),
        "packet_count": 0,
        "active_devices": set(),
    })

    # Schedule next send
    threading.Timer(SEND_INTERVAL, send_metrics).start()

# === Start Monitoring ===
if __name__ == "__main__":
    print("[MONITOR] Starting network monitoring...")
    send_metrics()
    sniff(prn=analyze_packet, store=0, iface="eth0")
