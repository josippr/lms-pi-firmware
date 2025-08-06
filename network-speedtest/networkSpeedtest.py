import os
import subprocess
import yaml
import requests
import socket
from dotenv import load_dotenv
from datetime import datetime
import re

# === Load environment variables ===
load_dotenv()

CONFIG_FILE = os.getenv("CONFIG_FILE")
CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY = os.getenv("CLIENT_KEY")
API_ENDPOINT = os.getenv("API_ENDPOINT")

def read_config(path):
    try:
        with open(path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"[ERROR-SPEEDTEST] Could not read config file: {e}")
        return {}

def run_speed_test():
    print("[SPEEDTEST] Running speedtest-cli...\n")

    result = subprocess.run(
        ["speedtest-cli"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR-SPEEDTEST] Speedtest failed:")
        print(result.stderr)
        return None

    output = result.stdout
    # Extract server info and ping from 'Hosted by ...' line
    hosted_match = re.search(r"Hosted by (.+?) \([^)]+\) \[[^\]]+\]: ([\d.]+) ms", output)
    if hosted_match:
        server = hosted_match.group(1).strip()
        ping_ms = float(hosted_match.group(2))
    else:
        server = "unknown"
        ping_ms = None

    download_match = re.search(r"Download:\s+([\d.]+)\s+Mbit/s", output)
    upload_match = re.search(r"Upload:\s+([\d.]+)\s+Mbit/s", output)

    if ping_ms is not None and download_match and upload_match:
        return {
            "hostname": socket.gethostname(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ping_ms": ping_ms,
            "download_mbps": float(download_match.group(1)),
            "upload_mbps": float(upload_match.group(1)),
            "server": server
        }
    else:
        print("[ERROR-SPEEDTEST] Failed to parse speedtest-cli output")
        print(output)
        return None

def send_speedtest_data():
    print("[SPEEDTEST] Collecting speedtest data...")

    config = read_config(CONFIG_FILE)
    print("[DEBUG] Loaded config:", config)

    speed_data = run_speed_test()
    if not speed_data:
        print("[ERROR-SPEEDTEST] Speedtest data collection failed.")
        return False

    payload = {
        "deviceId": config.get('UID', 'unknown'),
        "timestamp": speed_data["timestamp"],
        "payload": {
            "speedtest": {
                "hostname": speed_data["hostname"],
                "ping_ms": speed_data["ping_ms"],
                "download_mbps": speed_data["download_mbps"],
                "upload_mbps": speed_data["upload_mbps"],
                "server": speed_data.get("server", "unknown")
            }
        }
    }

    try:
        if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
            print("[ERROR-SPEEDTEST] Client certificate or key not found")
            return False

        session = requests.Session()

        response = session.post(
            API_ENDPOINT,
            json=payload,
            headers={
                'Content-Type': 'application/json',
                'X-SSL-Client-Verify': 'SUCCESS'
            },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify='/etc/ssl/certs/ca-certificates.crt',
            timeout=30
        )

        response.raise_for_status()
        print("[SPEEDTEST] Speedtest data sent successfully.")
        return True

    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR-SPEEDTEST] Certificate verification failed: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR-SPEEDTEST] Failed to send speedtest data: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
    return False

if __name__ == "__main__":
    send_speedtest_data()
