# Intrusion Detection System (IDS)

`^1.0.0`

A lightweight, rule-based intrusion detection system designed for network monitoring on Raspberry Pi devices. This module captures network traffic, analyzes it against configurable rules, and sends alerts to a remote API endpoint.

---

## Features

- **Real-time packet capture** using Scapy
- **Rule-based detection engine** with configurable YAML rules
- **Port scan detection** with customizable thresholds
- **DNS tunneling detection** for suspicious DNS queries
- **Secure alert transmission** using client certificates
- **Cooldown periods** to prevent alert flooding
- **Modular architecture** for easy rule expansion

---

## Architecture

The IDS consists of several core components:

- **[`intrusion.py`](intrusion.py)** - Main entry point
- **[`core/capture.py`](core/capture.py)** - Packet capture using Scapy
- **[`core/detection.py`](core/detection.py)** - Packet analysis and metadata extraction
- **[`core/rules.py`](core/rules.py)** - Rule engine with threat detection logic
- **[`core/sender.py`](core/sender.py)** - Secure alert transmission to remote API
- **[`config/rules.yaml`](config/rules.yaml)** - Detection rules configuration

---

## Detection Rules

### Port Scan Detection
Detects potential port scanning activities by monitoring:
- Number of unique destination ports accessed from a single source
- Time window for activity correlation
- Configurable threshold and alert cooldown

### DNS Tunnel Detection
Identifies suspicious DNS queries that may indicate data exfiltration:
- Query length analysis
- Subdomain count examination
- Pattern-based detection

---

## Configuration

### Rules Configuration
Edit [`config/rules.yaml`](config/rules.yaml) to customize detection rules:

```yaml
rules:
  - name: Port Scan Detection
    type: port_scan
    threshold: 20          # Trigger after 20 unique ports
    time_window: 10        # Within 10 seconds
    alert_cooldown: 30     # Wait 30s between alerts

  - name: DNS Tunnel Detection
    type: dns_tunnel
    min_length: 30         # Minimum query length
    dot_count: 4           # Minimum number of dots
```

### Environment Variables
Required environment variables in [`.env`](../.env):

```bash
# API endpoint for sending alerts
API_ENDPOINT_INTRUSION=https://your-api-endpoint.com/api/network/intrusion

# Client certificates for secure communication
CLIENT_CERT=/path/to/client.crt
CLIENT_KEY=/path/to/client.key
CONFIG_FILE=/path/to/config.yaml

# Alert batching interval
FLUSH_INTERVAL=10
```

---

## Usage

### Standalone Mode
```bash
sudo python intrusion.py
```

### As Part of Main Firmware
The IDS runs automatically when [`app.py`](../app.py) is executed, managed as a background thread.

---

## Requirements

- Python 3.7+
- Root privileges (required for packet capture)
- Network interface access

### Python Dependencies
- `scapy` - Packet capture and analysis
- `pyyaml` - Configuration file parsing
- `requests` - HTTP client for alert transmission
- `psutil` - System information
- `python-dotenv` - Environment variable loading

---

## Alert Format

Alerts are sent as JSON payloads to the configured API endpoint:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "uid": "device-unique-id",
  "alert": {
    "type": "Port Scan Detection",
    "method": "High port volume",
    "source": "192.168.1.100",
    "ports": [22, 23, 80, 443, 8080],
    "protocols": [6, 17],
    "timestamp": 1705312200
  }
}
```

---

## Security Considerations

- **Client Certificate Authentication**: All alerts are transmitted using mutual TLS authentication
- **Rate Limiting**: Built-in cooldown periods prevent alert flooding
- **Local Processing**: All detection logic runs locally to minimize data transmission
- **Privilege Requirements**: Requires root access for packet capture

---

## Extending Detection Rules

To add new detection rules:

1. Define the rule in [`config/rules.yaml`](config/rules.yaml)
2. Implement detection logic in [`core/rules.py`](core/rules.py)
3. Add packet metadata extraction in [`core/detection.py`](core/detection.py) if needed

Example custom rule:
```python
# In core/rules.py
if rule['type'] == 'custom_detection':
    # Your detection logic here
    if suspicious_condition:
        send_alert({
            'type': rule['name'],
            'source': metadata['src_ip'],
            'details': 'Custom detection details',
            'timestamp': int(now)
        })
```

---

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
sudo python intrusion.py
```

**No Network Interface**
Modify the interface in [`core/capture.py`](core/capture.py):
```python
def start_capture(interface='wlan0'):  # Change from 'eth0'
```

**Certificate Errors**
Verify certificate paths in environment variables and ensure proper permissions.

**High CPU Usage**
Adjust detection thresholds in [`config/rules.yaml`](config/rules.yaml) to reduce processing overhead.

---

## Legal Notice

This intrusion detection system is designed for monitoring networks you own or have explicit permission to monitor. Unauthorized network monitoring may violate local laws and regulations. Use responsibly and in compliance with applicable legal requirements.