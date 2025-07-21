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
- **Automatic restart** - Crash-safe execution with automatic recovery

---

## Architecture

The IDS consists of several core components:

- **[`intrusion.py`](intrusion.py)** - Main entry point and crash-safe execution wrapper
- **[`core/capture.py`](core/capture.py)** - Packet capture using Scapy
- **[`core/detection.py`](core/detection.py)** - Packet analysis and metadata extraction
- **[`core/rules.py`](core/rules.py)** - Rule engine with threat detection logic
- **[`core/sender.py`](core/sender.py)** - Secure alert transmission to remote API
- **[`config/rules.yaml`](config/rules.yaml)** - Detection rules configuration

---

## Integration with Main Firmware

This IDS module is integrated into the main LMS Pi firmware ([`../app.py`](../app.py)) and runs as a background thread with the following characteristics:

- **5-minute execution cycles** - Runs continuously with 5-minute intervals
- **Crash-safe operation** - Automatically restarts if the process fails
- **Multi-threaded execution** - Runs alongside other monitoring services:
  - Node metrics collection
  - FritzBox plugin
  - Network status monitoring
- **Virtual environment support** - Executed using `./venv/bin/python`

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
Required environment variables in [`../.env`](../.env):

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

### As Part of Main Firmware (Recommended)
```bash
# From project root directory
python app.py
```

The IDS will automatically start as part of the main firmware suite and run continuously with automatic restart capabilities.

---

## Requirements

- Python 3.7+
- Root privileges (required for packet capture)
- Network interface access
- Virtual environment setup (when using main firmware)

### Python Dependencies
Install via the project's virtual environment:

```bash
# Activate virtual environment
source ../venv/bin/activate

# Install dependencies
pip install scapy pyyaml requests psutil python-dotenv

# Or install from requirements if available
pip install -r ../requirements.txt
```

Required packages:
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
  "timestamp": "2025-07-21T10:30:00Z",
  "uid": "device-unique-id",
  "alert": {
    "type": "Port Scan Detection",
    "method": "High port volume",
    "source": "192.168.1.100",
    "ports": [22, 23, 80, 443, 8080],
    "protocols": [6, 17],
    "timestamp": 1721556600
  }
}
```

---

## Security Considerations

- **Client Certificate Authentication**: All alerts are transmitted using mutual TLS authentication
- **Rate Limiting**: Built-in cooldown periods prevent alert flooding
- **Local Processing**: All detection logic runs locally to minimize data transmission
- **Privilege Requirements**: Requires root access for packet capture
- **Isolated Environment**: Runs in virtual environment for dependency isolation

---

## Monitoring and Logging

When running as part of the main firmware, the IDS provides detailed logging:

```
[INFO] Running script: ./intrusion-detection/intrusion.py
[ERROR] Script ./intrusion-detection/intrusion.py failed: <error details>
[INFO] Waiting for 5 minutes before next run...
```

Monitor system status through the main application logs.

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
# Or when using main firmware, ensure it's run with appropriate privileges
```

**Module Not Found**
```bash
# Ensure virtual environment is set up correctly
source ../venv/bin/activate
pip install -r requirements.txt
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

**Script Failing in Main Firmware**
Check main application logs for specific error details and ensure all dependencies are installed in the virtual environment.

---

## Legal Notice

This intrusion detection system is designed for monitoring networks you own or have explicit permission to monitor. Unauthorized network monitoring may violate local laws and regulations. Use responsibly and in compliance with applicable legal requirements.