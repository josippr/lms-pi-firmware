import os
import socket
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp

def get_local_network():
    """Detect the local network subnet using OS commands."""
    try:
        if os.name == "nt":  # Windows
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            lines = result.stdout.split("\n")
            for i, line in enumerate(lines):
                if "IPv4 Address" in line:
                    ip = line.split(":")[-1].strip()
                    subnet = ip.rsplit(".", 1)[0] + ".0/24"
                    return ipaddress.IPv4Network(subnet, strict=False)

        else:  # Linux & macOS
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
            lines = result.stdout.split("\n")
            for line in lines:
                if "inet " in line and "127.0.0.1" not in line:
                    ip = line.split()[1].split("/")[0]
                    subnet = ip.rsplit(".", 1)[0] + ".0/24"
                    return ipaddress.IPv4Network(subnet, strict=False)

    except Exception as e:
        print(f"Error detecting network: {e}")

    return None

def arp_scan(subnet):
    """Use ARP to quickly discover active devices."""
    print(f"Scanning network {subnet} using ARP...\n")
    
    arp_request = ARP(pdst=str(subnet))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    response = srp(broadcast / arp_request, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in response:
        ip = received.psrc
        mac = received.hwsrc
        hostname = get_hostname(ip)
        devices.append((ip, mac, hostname))

    return devices

def get_hostname(ip):
    """Resolve hostname (if possible)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def main():
    subnet = get_local_network()
    if not subnet:
        print("Could not determine local network.")
        return

    devices = arp_scan(subnet)

    if devices:
        print("\nDiscovered Devices:")
        for ip, mac, hostname in devices:
            print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname}")
    else:
        print("No active devices found.")

if __name__ == "__main__":
    main()
