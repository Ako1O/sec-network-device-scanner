# sec-network-device-scanner

A small security-focused tool that scans your local network for connected devices, identifies likely manufacturers using MAC address lookups, and highlights unknown/new devices in a simple dashboard output.

> Goal: quick visibility into “who is on my network” + basic device attribution for a home / lab environment.

---

## Features

-  Smart subnet auto-detection (handles VPNs / virtual adapters)
-  Windows-friendly fallback scanning (no Npcap required)
-  MAC OUI manufacturer detection
-  Strict allowlist mode (security monitoring)
-  Device baseline database (detect newly seen devices)
-  Gateway role detection (clearly marks network gateway)
-  Watch mode (continuous monitoring)
-  JSON / NDJSON output for scripting & CI
-  Concurrency control (`--max-workers`)
-  Automation-ready exit codes


---

## How it works (high-level)

1. Detects the active network interface + local subnet (example: `192.168.1.0/24`)
2. Scans the subnet to find live hosts
3. Resolves **IP → MAC**
4. Uses the MAC prefix (OUI) to guess the **manufacturer**
5. Compares scan results against your **allowlist** / previously seen devices
6. Prints a dashboard view and optionally saves output files

---

## Installation

### Requirements
- Python **3.11+** recommended (3.12 works great)
- Works best on Linux/macOS; Windows is possible but may require extra permissions

### Setup

```bash
git clone https://github.com/<your-username>/sec-network-device-scanner.git
cd sec-network-device-scanner

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows (PowerShell)
# .\.venv\Scripts\Activate.ps1

pip install -e .
```

---
## Usage
### Basic scan
```bash
sec-network-device-scanner scan
```
### Save results
```bash
sec-network-device-scanner scan --out results.json
```
### Use an allowlist (known devices)
```bash
sec-network-device-scanner scan --allow allowlist.json
```

### Example allowlist.json:
```JSON
{
  "devices": [
    { "mac": "AA:BB:CC:11:22:33", "name": "My Laptop" },
    { "mac": "44:55:66:77:88:99", "name": "Router" }
  ]
}
```

---
## Output example

### Example terminal dashboard output:
```code
Found: 7 devices  |  Unknown: 2

IP             MAC                Manufacturer          Status
192.168.0.1    44:55:66:77:88:99  MikroTik             Known
192.168.0.23   AA:BB:CC:11:22:33  Lenovo               Known
192.168.0.42   10:20:30:40:50:60  (unknown)            ⚠ Unknown
...
```

### JSON Output to sdout:
```JSON
{
  "timestamp_utc": "...",
  "network": "10.175.142.0/24",
  "gateway_ip": "10.175.142.245",
  "counts": {
    "found": 1,
    "new": 0,
    "unknown": 0
  },
  "devices": [...]
}
```

### Exit codes (automation-friendly)
Designed for scripts/CI and security workflows:

| Code | Meaning                                                |
| ---- | ------------------------------------------------------ |
| 0    | No unknown devices found                               |
| 1    | At least one unknown device found                      |
| 2    | Runtime error (permissions, interface not found, etc.) |

---

## Project Structure:
``` Plain text
sec-network-device-scanner/
├─ src/sec_network_device_scanner/
│  ├─ __init__.py
│  ├─ cli.py
│  ├─ scanner.py
│  ├─ oui.py
│  └─ storage.py
├─ tests/
├─ .github/workflows/
├─ pyproject.toml
├─ README.md
└─ requirements.txt
```
---
## Security notes / limitations

This tool is meant for networks you own or have permission to test.
Results depend on local network visibility (VLANs, client isolation, firewall rules, etc.).
Manufacturer detection is best-effort; OUI databases can be incomplete.
Some devices may hide MAC addresses or appear behind NAT.
