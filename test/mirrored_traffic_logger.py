from scapy.all import sniff, Raw
import datetime

# Define the network interface for packet capture (adjust as needed)
INTERFACE = "eth0"  # Change if needed (e.g., wlan0)

# Log file to store captured data
LOG_FILE = "network_traffic.log"

def process_packet(packet):
    """Callback function to process each captured packet."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract packet summary
    packet_summary = packet.summary()
    
    # Extract raw payload if available
    payload_data = ""
    if packet.haslayer(Raw):
        payload_data = packet[Raw].load.hex()  # Hex representation of raw data

    # Format the log entry
    log_entry = f"[{timestamp}] {packet_summary}\nPayload: {payload_data}\n{'-'*50}\n"
    
    # Print to console for real-time monitoring
    print(log_entry)

    # Append to log file
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Start sniffing
print(f"[*] Sniffing on {INTERFACE} - Logging packets to {LOG_FILE}")
sniff(iface=INTERFACE, prn=process_packet, store=False)
