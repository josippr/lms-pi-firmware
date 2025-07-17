import psutil
import time
from scapy.all import sniff
import threading

# Globals for tracking packets
packet_counts = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}

def packet_counter(pkt):
    packet_counts["total"] += 1
    if pkt.haslayer('TCP'):
        packet_counts["tcp"] += 1
    elif pkt.haslayer('UDP'):
        packet_counts["udp"] += 1
    elif pkt.haslayer('ICMP'):
        packet_counts["icmp"] += 1
    else:
        packet_counts["other"] += 1

def start_sniffing(interface=None):
    sniff(prn=packet_counter, store=False, iface=interface)

def monitor_bandwidth(interface=None, interval=1, duration=30):
    print("Monitoring bandwidth usage...")
    io_start = psutil.net_io_counters(pernic=True)
    if interface not in io_start:
        raise ValueError(f"Interface '{interface}' not found. Available: {list(io_start.keys())}")
    start = io_start[interface]

    time.sleep(duration)

    io_end = psutil.net_io_counters(pernic=True)[interface]

    sent = (io_end.bytes_sent - start.bytes_sent) / duration
    recv = (io_end.bytes_recv - start.bytes_recv) / duration

    print("\n[+] Average Bandwidth Over {}s:".format(duration))
    print(f"  Upload  : {sent / 1024:.2f} KB/s | " + f"{sent / 1024 / 1024:.2f} MB/s")
    print(f"  Download: {recv / 1024:.2f} KB/s | " + f"{recv / 1024 / 1024:.2f} MB/s")
    return sent, recv

if __name__ == "__main__":
    INTERFACE = "eth0"  # Change to your actual interface name (e.g., wlan0)

    # Start packet sniffing in background
    t = threading.Thread(target=start_sniffing, kwargs={"interface": INTERFACE})
    t.daemon = True
    t.start()

    # Monitor bandwidth via psutil
    sent, recv = monitor_bandwidth(interface=INTERFACE, interval=1, duration=10)

    # Print captured packet stats
    # print("\n[+] Packet Stats (Scapy Sniffing):")
    # print(packet_counts.items(), headers=["Type", "Count"], tablefmt="grid")
