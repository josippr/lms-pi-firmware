import os
import json
import time
import socket
import psutil
import yaml
import ipaddress
import requests
from datetime import datetime
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp
from fritzconnection import FritzConnection
from collections import defaultdict

# === Load environment ===
load_dotenv()
CONFIG_FILE = os.getenv("CONFIG_FILE")
CLIENT_CERT = os.getenv("CLIENT_CERT")
CLIENT_KEY = os.getenv("CLIENT_KEY")
API_ENDPOINT = os.getenv("API_ENDPOINT")
CA_CERT = "/etc/ssl/certs/ca-certificates.crt"
SEND_INTERVAL = 300  # seconds
FRITZ_IP = os.getenv("FRITZ_IP")
FRITZ_USERNAME = os.getenv("FRITZ_USERNAME")
FRITZ_PASSWORD = os.getenv("FRITZ_PASSWORD")

# === Helper functions ===
def read_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

config = read_config(CONFIG_FILE)
uid = config.get("UID", "unknown")

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "unknown"

def get_mac(ip):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except Exception:
        return None

def scan_local_network():
    print("[ANALYSIS] Scanning local network...")
    devices = []
    interfaces = psutil.net_if_addrs()

    for iface in interfaces.values():
        for snic in iface:
            if snic.family.name == 'AF_INET':
                ip = snic.address
                netmask = snic.netmask
                if ip.startswith("127.") or not netmask:
                    continue

                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
                    ans, _ = srp(arp, timeout=2, verbose=0)
                    for snd, rcv in ans:
                        devices.append({
                            'ip': rcv.psrc,
                            'mac': rcv.hwsrc,
                            'hostname': get_hostname(rcv.psrc),
                            'type': "unknown",  # placeholder, can use MAC vendor lookup or ARP flags
                            'active': True,
                            'traffic': {
                                'packets': 0,
                                'bytes': 0
                            }
                        })
                except Exception as e:
                    print(f"[ANALYSIS] Error scanning {ip}: {e}")
    return devices

def get_fritzbox_devices():
    print("[ANALYSIS - FRITZ] Querying Fritz!Box...")
    scan_results = []
    try:
        fc = FritzConnection(address=FRITZ_IP, user=FRITZ_USERNAME, password=FRITZ_PASSWORD)
        count = fc.call_action('Hosts', 'GetHostNumberOfEntries')['NewHostNumberOfEntries']
        for i in range(count):
            device = fc.call_action('Hosts', 'GetGenericHostEntry', NewIndex=i)
            scan_results.append({
                'ip': device.get('NewIPAddress'),
                'mac': device.get('NewMACAddress'),
                'hostname': device.get('NewHostName') or 'unknown',
                'type': device.get('NewInterfaceType', 'unknown'),
                'active': device.get('NewActive', False),
                'traffic': {
                    'packets': 0,
                    'bytes': 0
                }
            })
    except Exception as e:
        print(f"[ANALYSIS - FRITZ] Error: {e}")
    return scan_results

def normalize_devices(devices):
    now = datetime.utcnow().isoformat() + "Z"
    devices_scans = []
    devices_metadata = {}

    for dev in devices:
        mac = dev['mac']
        if not mac:
            continue

        scan_entry = {
            'uid': uid,
            'mac': mac,
            'ip': dev.get('ip'),
            'hostname': dev.get('hostname', 'unknown'),
            'type': dev.get('type', 'unknown'),
            'active': dev.get('active', False),
            'traffic': dev.get('traffic', {'packets': 0, 'bytes': 0})
        }

        metadata_entry = {
            'uid': uid,
            'mac': mac,
            'hostname': dev.get('hostname', 'unknown'),
            'lastIP': dev.get('ip'),
            'trusted': "neutral",
            'notes': '',
            'tags': [],
            'firstSeen': now,
            'lastSeen': now
        }

        devices_scans.append(scan_entry)
        devices_metadata[mac] = metadata_entry

    return devices_scans, list(devices_metadata.values())

def send_payload(devices_scans, devices_metadata):
    payload = {
        "deviceId": uid,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "payload": {
            "deviceScans": devices_scans,
            "deviceMetadata": devices_metadata
        }
    }
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
        print("[ANALYSIS] Devices data sent successfully.")
    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR] Certificate verification failed: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[ANALYSIS - ERROR] Failed to send devices data: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response content: {e.response.text}")

# === Main loop ===
if __name__ == "__main__":
    while True:
        local_devices = scan_local_network()
        fritz_devices = get_fritzbox_devices()

        # Merge results: prioritize active Fritz devices, fall back to local
        merged_devices = {d['mac']: d for d in local_devices}
        for d in fritz_devices:
            if d['mac'] not in merged_devices or d['active']:
                merged_devices[d['mac']] = d

        scans, metadata = normalize_devices(list(merged_devices.values()))
        send_payload(scans, metadata)

        time.sleep(SEND_INTERVAL)
