from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class DeviceRecord:
    mac: str
    manufacturer: str
    first_seen: str
    last_seen: str
    last_ip: str
    seen_count: int = 1
    name: str | None = None


def load_db(path: str | Path) -> dict[str, DeviceRecord]:
    p = Path(path)
    if not p.exists():
        return {}

    raw = json.loads(p.read_text(encoding="utf-8"))
    devices = raw.get("devices", {})

    out: dict[str, DeviceRecord] = {}
    for mac, rec in devices.items():
        out[mac] = DeviceRecord(
            mac=mac,
            manufacturer=rec.get("manufacturer", "(unknown)"),
            first_seen=rec.get("first_seen", utc_now_iso()),
            last_seen=rec.get("last_seen", utc_now_iso()),
            last_ip=rec.get("last_ip", ""),
            seen_count=int(rec.get("seen_count", 1)),
            name=rec.get("name"),
        )
    return out


def save_db(path: str | Path, db: dict[str, DeviceRecord]) -> None:
    p = Path(path)
    payload = {
        "devices": {
            mac: {
                "mac": r.mac,
                "manufacturer": r.manufacturer,
                "first_seen": r.first_seen,
                "last_seen": r.last_seen,
                "last_ip": r.last_ip,
                "seen_count": r.seen_count,
                "name": r.name,
            }
            for mac, r in db.items()
        }
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def upsert_seen(
    db: dict[str, DeviceRecord],
    mac: str,
    ip: str,
    manufacturer: str,
) -> tuple[bool, DeviceRecord]:
    """
    Returns (is_new, record)
    """
    now = utc_now_iso()

    if mac not in db:
        rec = DeviceRecord(
            mac=mac,
            manufacturer=manufacturer,
            first_seen=now,
            last_seen=now,
            last_ip=ip,
            seen_count=1,
        )
        db[mac] = rec
        return True, rec

    rec = db[mac]
    rec.last_seen = now
    rec.last_ip = ip
    rec.seen_count += 1
    if rec.manufacturer in ("(unknown)", "", None) and manufacturer:
        rec.manufacturer = manufacturer
    return False, rec
