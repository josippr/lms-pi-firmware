# LMS Pi Firmware

A modular Python firmware for Raspberry Pi-based network monitoring and telemetry nodes.

---

## Overview

This repository contains the main firmware for the LMS network monitor, designed to run on a Raspberry Pi. It provides network scanning, speed testing, hardware metrics collection, and secure telemetry reporting to a central server.

---

```
lms-pi-firmware/
├── app.py
├── README.md
├── requirements.txt
├── temp.py
├── fritzbox-plugin/
│   ├── fritzbox.py
│   └── README.md
├── intrusion-detection/
│   ├── intrusion.py
│   ├── README.md
│   ├── config/
│   │   └── rules.yaml
│   └── core/
│       ├── capture.py
│       ├── detection.py
│       ├── rules.py
│       ├── sender.py
│       └── __pycache__/
├── network-analysis/
│   └── networkAnalysis.py
├── network-scanner/
│   ├── README.md
│   ├── requirements.txt
│   └── scanner.py
├── network-speedtest/
│   ├── README.md
│   ├── requirements.txt
│   └── speedtest.py
├── network-status/
│   └── network-status.py
├── node-metrics/
│   └── send_metrics.py
├── test/
│   ├── mirrored_traffic_logger.py
│   └── traffic-faker.py
└── utils/
    ├── device_signatures.py
    └── load_env.py
```

## Features

- **Network Scanning:**  
  Detects devices on the local network using ARP and passive sniffing ([network-scanner](network-scanner/)).

- **Speed Testing:**  
  Measures internet connection speed using [speedtest-cli](network-speedtest/).

- **Node Metrics:**  
  Collects hardware and system metrics (CPU, memory, disk, temperature) and sends them securely ([node-metrics](node-metrics/)).

- **Secure Telemetry:**  
  Sends data to a remote API using client certificates for authentication.

- **Modular Design:**  
  Easily extendable with additional monitoring modules.

---

## Requirements

- Raspberry Pi (recommended: Pi 4 or newer)
- Python 3.7+
- [pip](https://pip.pypa.io/en/stable/)
- See [requirements.txt](requirements.txt) for Python dependencies

---

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/lms-pi-firmware.git
   cd lms-pi-firmware
   ```
2. Install dependencies:
    ```
    pip install -r requirements.txt
    ```

3. Set up environment variables

---

## Usage

Run the main firmware:
  ```python
  sudo python app.py
  ```
Run individual modules:

Network Scanner:
Speed Test:
Node Metrics:
Directory Structure
app.py — Main entry point, runs enabled modules in background threads
network-scanner/ — Local network device discovery
network-speedtest/ — Internet speed testing
node-metrics/ — Hardware and system metrics collection
utils/ — Utility scripts and helpers
test — Test scripts and development tools

License
MIT License. See LICENSE for details.

Disclaimer
This project is for educational and research purposes. Use responsibly and only on networks you own or have permission to monitor.