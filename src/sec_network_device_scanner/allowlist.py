from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AllowedDevice:
    mac: str
    name: str | None = None


def normalize_mac(mac: str) -> str:
    # Normalize to uppercase colon-separated where possible
    m = mac.strip().replace("-", ":").upper()
    return m


def load_allowlist(path: str | Path | None) -> dict[str, AllowedDevice]:
    """
    Returns mapping: normalized_mac -> AllowedDevice
    Accepts:
    {
      "devices": [{"mac": "...", "name": "..."}]
    }
    """
    if path is None:
        return {}

    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))

    devices = data.get("devices", [])
    out: dict[str, AllowedDevice] = {}
    for item in devices:
        mac = normalize_mac(str(item["mac"]))
        name = item.get("name")
        out[mac] = AllowedDevice(mac=mac, name=name)
    return out