import os
import requests
import yaml
import socket
import platform
import psutil
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Load environment variables
CONFIG_FILE = os.getenv("CONFIG_FILE")
CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY = os.getenv("CLIENT_KEY")
API_ENDPOINT = os.getenv("API_ENDPOINT_INTRUSION")
CA_BUNDLE = os.getenv("CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt")

def read_config(path):
    try:
        with open(path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        print(f"[ERROR] Could not read config file: {e}")
        return {}

def send_alert(alert_data):
    print("[INFO] Preparing to send IDS alert...")

    config = read_config(CONFIG_FILE)

    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uid": config.get('UID', 'unknown'),
        "alert": alert_data
    }

    try:
        if not os.path.exists(CLIENT_CERT) or not os.path.exists(CLIENT_KEY):
            print("[ERROR] Client certificate or key not found")
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
            verify=CA_BUNDLE,
            timeout=30
        )

        response.raise_for_status()
        print("[INFO] IDS alert sent successfully.")
        return True

    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR] Certificate verification failed: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send alert: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")
    return False
