from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .allowlist import load_allowlist, normalize_mac
from .oui import OUILookup
from .scanner import resolve_cidr, scan
from .storage import load_db, save_db, upsert_seen


def _build_table() -> Table:
    t = Table(title="sec-network-device-scanner", show_lines=False)
    t.add_column("IP", style="bold")
    t.add_column("MAC")
    t.add_column("Manufacturer")
    t.add_column("Status")
    t.add_column("Name")
    return t


def cmd_scan(args: argparse.Namespace) -> int:
    console = Console()

    allow = load_allowlist(args.allow)
    oui = OUILookup()

    network = resolve_cidr(args.cidr)
    console.print(f"[dim]Scanning:[/dim] {network}")

    devices = scan(network, timeout=args.timeout, method=args.method)

    # Load DB unless disabled
    db = {} if args.no_db else load_db(args.db)

    new_count = 0
    unknown_count = 0

    table = _build_table()
    rows_out: list[dict[str, str]] = []

    for d in devices:
        mac_norm = normalize_mac(d.mac)
        manufacturer = oui.manufacturer(mac_norm) or "(unknown)"

        # Allowlist + DB info
        allowed = allow.get(mac_norm)
        in_allow = allowed is not None

        is_new = False
        if not args.no_db:
            is_new, _rec = upsert_seen(db, mac_norm, d.ip, manufacturer)
            if is_new:
                new_count += 1

        # Decide status
        if args.learn:
            # Learning baseline: show all as Known, but still writes into DB
            status = "Known"
        elif args.strict:
            # Strict mode: allowlist is the source of truth
            if in_allow:
                status = "Allowed"
            else:
                status = "⚠ Unknown"
                unknown_count += 1
        else:
            # Normal mode: DB-based "New" detection + allowlist labeling
            if in_allow:
                status = "Allowed"
            elif not args.no_db and is_new:
                status = "⚠ New"
            elif not args.no_db and (mac_norm in db):
                status = "Known"
            else:
                status = "⚠ Unknown"
                unknown_count += 1

        name = allowed.name if allowed and allowed.name else ""

        table.add_row(d.ip, mac_norm, manufacturer, status, name)

        rows_out.append(
            {
                "ip": d.ip,
                "mac": mac_norm,
                "manufacturer": manufacturer,
                "status": status,
                "name": name,
            }
        )

    # Save DB unless disabled
    if not args.no_db:
        save_db(args.db, db)

    console.print()
    console.print(
        f"Found: [bold]{len(devices)}[/bold] devices  |  "
        f"New: [bold]{new_count}[/bold]  |  "
        f"Unknown: [bold]{unknown_count}[/bold]"
    )
    console.print(table)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(
            json.dumps({"network": str(network), "devices": rows_out}, indent=2),
            encoding="utf-8",
        )
        console.print(f"\n[dim]Saved:[/dim] {out_path}")

    # Exit codes (automation-friendly)
    # Normal mode: 1 if NEW devices detected (unless --learn)
    # Strict mode: 1 if UNKNOWN devices detected (unless --learn)
    if args.learn:
        return 0

    if args.strict:
        return 1 if unknown_count > 0 else 0

    return 1 if new_count > 0 else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sec-network-device-scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan_cmd = sub.add_parser("scan", help="Scan network and list devices")

    scan_cmd.add_argument("--cidr", help="Target network in CIDR, e.g. 192.168.1.0/24")
    scan_cmd.add_argument("--timeout", type=int, default=2, help="Scan timeout seconds (scapy mode)")
    scan_cmd.add_argument("--allow", help="Allowlist JSON file")
    scan_cmd.add_argument("--out", help="Write results to JSON")

    scan_cmd.add_argument("--db", default="devices_db.json", help="Path to device database JSON")
    scan_cmd.add_argument("--no-db", action="store_true", help="Do not load/save device DB")
    scan_cmd.add_argument("--learn", action="store_true", help="Learn baseline: treat all seen devices as known")

    scan_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode: treat allowlist as source of truth; flag anything not in allowlist as Unknown.",
    )

    scan_cmd.add_argument(
        "--method",
        default="auto",
        choices=["auto", "scapy", "windows"],
        help="Scan method: auto (default), scapy (L2 ARP), windows (UDP-probe + arp -a fallback)",
    )

    scan_cmd.set_defaults(func=cmd_scan)
    return p


def main() -> None:
    try:
        parser = build_parser()
        args = parser.parse_args()
        code = args.func(args)
        raise SystemExit(code)
    except KeyboardInterrupt:
        raise SystemExit(2)
    except Exception as e:
        Console().print(f"[red]Error:[/red] {e}")
        raise SystemExit(2)