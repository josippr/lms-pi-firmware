
### Network scanner

`^0.1.0`

# Network Scanner

This Python script scans the local network for active devices using ARP (Address Resolution Protocol). It retrieves the IP address, MAC address, and hostname (if available) of each device on the network.

## How It Works
- **Detects the local subnet** by checking the system's network configuration.
- **Uses ARP scanning** to find active devices much faster than traditional ping-based methods.
- **Resolves hostnames** where possible using reverse DNS lookup.
- **Prints a list of discovered devices** with their IP addresses, MAC addresses, and hostnames.

## Prerequisites
- Python 3.x
- `scapy` library (install with `pip install scapy`)

## Usage
Run the script with:
```sh
python network_scanner.py
```

### Expected Output
If devices are found, the output will look something like:
```
Scanning network 192.168.1.0/24 using ARP...

Discovered Devices:
IP: 192.168.1.1, MAC: AA:BB:CC:DD:EE:FF, Hostname: router.local
IP: 192.168.1.10, MAC: 11:22:33:44:55:66, Hostname: laptop.local
IP: 192.168.1.20, MAC: 77:88:99:AA:BB:CC, Hostname: Unknown
```
If no devices are detected, it may display:
```
No active devices found.
```

## Potential Issues & Fixes
- **Permission Denied**: ARP scanning requires administrator/root privileges. Run with `sudo` on Linux/macOS:
  ```sh
  sudo python network_scanner.py
  ```
- **No Devices Found**: Ensure your device is connected to a network. Some networks may block ARP scans.
- **Incorrect Subnet Detection**: If the script fails to detect the correct subnet, manually modify the subnet detection function.

## Notes
- This script is designed for **local network scanning only**. It won't detect devices outside the LAN.
- Using this script on a network you do not own or have permission to scan may violate legal and ethical guidelines.