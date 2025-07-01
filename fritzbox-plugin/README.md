# FritzBox Plugin

`^1.0.0`

A Python plugin for monitoring and retrieving information from AVM FritzBox routers. This module connects to FritzBox devices via their TR-064 interface to collect network device information and system metrics.

---

## Features

- **Device Discovery** - List all connected devices on the network
- **Real-time Status** - Monitor active/inactive device states
- **Network Information** - Retrieve IP addresses, MAC addresses, and device names
- **Secure Connection** - Uses TR-064 protocol with authentication
- **Environment Configuration** - Configurable via environment variables

---

## Architecture

The plugin consists of:

- **[`fritzbox.py`](fritzbox.py)** - Main plugin entry point
- **Device listing functionality** using FritzConnection library
- **Environment-based configuration** for credentials and connection details

---

## Configuration

### Environment Variables
Required environment variables in [`.env`](../.env):

```bash
# FritzBox connection details
FRITZ_IP=your_ip_address         # FritzBox IP address
FRITZ_USERNAME=your_username     # FritzBox admin username
FRITZ_PASSWORD=your_password     # FritzBox admin password
```

### FritzBox Setup
1. Enable TR-064 interface in FritzBox settings:
   - Go to `Home Network` → `Network` → `Network Settings`
   - Enable "Allow access for applications" under TR-064
2. Create or use existing admin credentials
3. Note down the FritzBox IP address (usually `192.168.178.1`)

---

## Usage

### Standalone Mode
```bash
python fritzbox.py
```

### As Part of Main Firmware
The plugin runs automatically when [`app.py`](../app.py) is executed, managed as a background thread with 5-minute intervals.

---

## Requirements

- Python 3.7+
- Network access to FritzBox device
- Valid FritzBox admin credentials

### Python Dependencies
- `fritzconnection` - FritzBox TR-064 interface library
- `python-dotenv` - Environment variable loading

### Installation
```bash
pip install fritzconnection python-dotenv
```

---

## Output Format

The plugin outputs device information in the following format:

```
Total devices found: 8

Device #1
  Name      : iPhone
  IP Address: 192.168.178.25
  MAC       : aa:bb:cc:dd:ee:ff
  Active    : True

Device #2
  Name      : Laptop
  IP Address: 192.168.178.30
  MAC       : 11:22:33:44:55:66
  Active    : True
```

---

## Troubleshooting

### Common Issues

**Connection Refused**
- Verify FritzBox IP address is correct
- Ensure TR-064 is enabled in FritzBox settings
- Check network connectivity

**Authentication Failed**
- Verify username and password in `.env` file
- Ensure user has admin privileges on FritzBox
- Try accessing FritzBox web interface with same credentials

**Module Not Found**
```bash
pip install fritzconnection
```

**Permission Denied**
- Check if FritzBox allows TR-064 connections
- Verify firewall settings on both devices

---

## Supported FritzBox Models

This plugin works with most AVM FritzBox models that support TR-064 protocol, including:
- FritzBox 7590
- FritzBox 7530
- FritzBox 7490
- FritzBox 6890 LTE
- FritzBox 6600 Cable

Check your FritzBox documentation for TR-064 support.

---

## Legal Notice

This plugin is designed for monitoring your own FritzBox device. Ensure you have proper authorization before connecting to any network device. Unauthorized access to network equipment may violate local laws and