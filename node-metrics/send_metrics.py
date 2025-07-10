import os
import yaml
import platform
import psutil
import socket
import requests
import json
import time
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# Constants
CONFIG_FILE = os.getenv("CONFIG_FILE")
CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY = os.getenv("CLIENT_KEY")
API_ENDPOINT = os.getenv("API_ENDPOINT")

def read_config(path):
    try:
        with open(path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"[ERROR] Could not read config file: {e}")
        return {}

def collect_hardware_info():
    try:
        cpu_temp = None
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                cpu_temp = round(int(f.read()) / 1000, 2)
        except FileNotFoundError:
            cpu_temp = "Unavailable"

        return {
            "flag: ": "diag_BOOT_TEST",
            "hostname": socket.gethostname(),
            "architecture": platform.machine(),
            "platform": platform.platform(),
            "cpu": platform.processor(),
            "cpu_percent": psutil.cpu_percent(),
            "memory_total_mb": round(psutil.virtual_memory().total / 1024 / 1024, 2),
            "memory_used_percent": psutil.virtual_memory().percent,
            "memory_available_percent": psutil.virtual_memory().available * 100 / psutil.virtual_memory().total,
            "disk_total_mb": round(psutil.disk_usage('/').total / 1024 / 1024, 2),
            "cpu_temperature_c": cpu_temp,
            "uptime_sec": int(time.time() - psutil.boot_time()),
            "lastSync": int(time.time()),
        }
    except Exception as e:
        print(f"[ERROR] Collecting hardware info failed: {e}")
        return {}

def send_metrics():
    print("[INFO] Started collecting metrics...")
    
    config = read_config(CONFIG_FILE)
    print("debug: Loaded config: ", config)
    hw_data = collect_hardware_info()
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uid": config.get('UID', 'unknown'),
        "hardware": hw_data
    }

    try:
        # Verify client certificate is readable
        if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
            print("[ERROR] Client certificate or key not found")
            return False

        # Create session with proper SSL configuration
        session = requests.Session()
        
        # Make the request with client certificate
        response = session.post(
            API_ENDPOINT,
            json=payload,
            headers={
                'Content-Type': 'application/json',
                'X-SSL-Client-Verify': 'SUCCESS'  # Explicitly set verification header
            },
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify='/etc/ssl/certs/ca-certificates.crt',  # System CA bundle
            timeout=30
        )
        
        response.raise_for_status()
        print("[INFO] Metrics sent successfully.")
        return True
        
    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR] Certificate verification failed: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send metrics: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
    return False

if __name__ == "__main__":
    send_metrics()