# sec-network-device-scanner

A small security-focused tool that scans your local network for connected devices, identifies likely manufacturers using MAC address lookups, and highlights unknown/new devices in a simple dashboard output.

> Goal: quick visibility into “who is on my network” + basic device attribution for a home / lab environment.

---

## Features

- **Local network scan** to discover connected hosts (IP + MAC)
- **Manufacturer detection** via MAC OUI lookup (e.g., Apple, Intel, TP-Link)
- **Flag unknown devices** (not seen before / not on your allowlist)
- **Dashboard-style output** (terminal table first; optional web dashboard later)
- **Export results** to JSON/CSV for tracking and automation

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

pip install -r requirements.txt
