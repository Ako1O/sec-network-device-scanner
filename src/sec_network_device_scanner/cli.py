from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .allowlist import load_allowlist, normalize_mac
from .oui import OUILookup
from .scanner import get_gateway_for_network, list_ipv4_candidates, resolve_cidr, scan
from .storage import load_db, save_db, upsert_seen


def _build_table() -> Table:
    t = Table(title="sec-network-device-scanner", show_lines=False)
    t.add_column("Role")
    t.add_column("IP", style="bold")
    t.add_column("MAC")
    t.add_column("Manufacturer")
    t.add_column("Status")
    t.add_column("Name")
    return t


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _maybe_show_nets(console: Console, selected: str) -> None:
    console.print("[dim]Network candidates:[/dim]")
    for n in list_ipv4_candidates():
        mark = " [green]<selected>[/green]" if str(n) == selected else ""
        console.print(f"  - {n}{mark}")
    console.print()


def _run_single_scan(args: argparse.Namespace, console: Console) -> tuple[int, dict]:
    allow = load_allowlist(args.allow)
    oui = OUILookup()

    network = resolve_cidr(getattr(args, "cidr", None))
    gateway_ip = get_gateway_for_network(network)

    if args.show_nets and not args.json:
        _maybe_show_nets(console, str(network))

    if not args.json:
        console.print(f"[dim]Scanning:[/dim] {network}")

    devices = scan(
        network,
        timeout=args.timeout,
        method=args.method,
        max_workers=args.max_workers,
    )

    db = {} if args.no_db else load_db(args.db)

    new_count = 0
    unknown_count = 0

    table = _build_table()
    out_devices: list[dict[str, str]] = []

    for d in devices:
        role = "Gateway" if (gateway_ip and d.ip == gateway_ip) else "Client"

        mac_norm = normalize_mac(d.mac)
        manufacturer = oui.manufacturer(mac_norm) or "(unknown)"

        allowed = allow.get(mac_norm)
        in_allow = allowed is not None

        is_new = False
        if not args.no_db:
            is_new, _ = upsert_seen(db, mac_norm, d.ip, manufacturer)
            if is_new:
                new_count += 1

        if args.learn:
            status = "Known"
        elif args.strict:
            if in_allow:
                status = "Allowed"
            else:
                status = "⚠ Unknown"
                unknown_count += 1
        else:
            if in_allow:
                status = "Allowed"
            elif not args.no_db and is_new:
                status = "⚠ New"
            elif not args.no_db and mac_norm in db:
                status = "Known"
            else:
                status = "⚠ Unknown"
                unknown_count += 1

        name = allowed.name if allowed and allowed.name else ""

        if not args.json:
            table.add_row(role, d.ip, mac_norm, manufacturer, status, name)

        out_devices.append(
            {
                "role": role,
                "ip": d.ip,
                "mac": mac_norm,
                "manufacturer": manufacturer,
                "status": status,
                "name": name,
            }
        )

    if not args.no_db:
        save_db(args.db, db)

    payload = {
        "timestamp_utc": _now_iso_utc(),
        "network": str(network),
        "gateway_ip": gateway_ip,
        "counts": {"found": len(devices), "new": new_count, "unknown": unknown_count},
        "devices": out_devices,
        "mode": {
            "strict": bool(args.strict),
            "learn": bool(args.learn),
            "no_db": bool(args.no_db),
            "method": args.method,
            "max_workers": int(args.max_workers),
        },
    }

    # Human output (stderr when --json is set)
    if not args.json:
        console.print()
        console.print(
            f"Found: [bold]{len(devices)}[/bold] devices  |  "
            f"New: [bold]{new_count}[/bold]  |  "
            f"Unknown: [bold]{unknown_count}[/bold]"
        )
        console.print(table)

        if getattr(args, "out", None):
            out_path = Path(args.out)
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"\n[dim]Saved:[/dim] {out_path}")

    # Exit codes:
    # - learn => always 0
    # - strict => 1 if any unknown
    # - normal => 1 if any new
    if args.learn:
        code = 0
    elif args.strict:
        code = 1 if unknown_count > 0 else 0
    else:
        code = 1 if new_count > 0 else 0

    return code, payload


def cmd_scan(args: argparse.Namespace) -> int:
    # If JSON is enabled, print human output to stderr so stdout stays clean JSON.
    console = Console(stderr=args.json)

    code, payload = _run_single_scan(args, console)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False))

    # Optional: also write JSON payload to a file (same schema as stdout)
    if args.out and args.json:
        Path(args.out).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return code


def cmd_watch(args: argparse.Namespace) -> int:
    console = Console(stderr=args.json)
    interval = max(1, int(args.interval))

    if not args.json:
        console.print(
            f"[dim]Watch mode:[/dim] interval={interval}s  "
            f"method={args.method}  "
            f"workers={args.max_workers}  "
            f"{'STRICT' if args.strict else 'NORMAL'}"
        )

    while True:
        if not args.json:
            console.rule(f"[bold]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold]")

        code, payload = _run_single_scan(args, console)

        if args.json:
            # NDJSON: one JSON object per line, perfect for logs/pipes
            print(json.dumps(payload, ensure_ascii=False))

        if code != 0:
            if not args.json:
                console.print("\n[red]Alert condition met.[/red] Exiting watch mode.")
            return code

        time.sleep(interval)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sec-network-device-scanner")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common_flags(cmd: argparse.ArgumentParser) -> None:
        cmd.add_argument("--cidr", help="Target network in CIDR, e.g. 192.168.1.0/24")
        cmd.add_argument("--timeout", type=int, default=2, help="Scan timeout seconds (scapy mode)")
        cmd.add_argument("--allow", help="Allowlist JSON file")
        cmd.add_argument("--db", default="devices_db.json", help="Path to device DB JSON")
        cmd.add_argument("--no-db", action="store_true", help="Do not load/save device DB")
        cmd.add_argument("--learn", action="store_true", help="Learn baseline: treat all seen devices as known")
        cmd.add_argument("--strict", action="store_true", help="Strict mode: not in allowlist => Unknown")
        cmd.add_argument(
            "--method",
            default="auto",
            choices=["auto", "scapy", "windows"],
            help="Scan method: auto/scapy/windows",
        )
        cmd.add_argument(
            "--max-workers",
            type=int,
            default=100,
            help="Windows probing concurrency (windows/auto modes).",
        )
        cmd.add_argument(
            "--show-nets",
            action="store_true",
            help="Print detected IPv4 network candidates and the selected network.",
        )
        cmd.add_argument(
            "--json",
            action="store_true",
            help="Output JSON to stdout (human output goes to stderr).",
        )

    scan_cmd = sub.add_parser("scan", help="Scan network and list devices")
    add_common_flags(scan_cmd)
    scan_cmd.add_argument("--out", help="Write results payload to JSON file")
    scan_cmd.set_defaults(func=cmd_scan)

    watch_cmd = sub.add_parser("watch", help="Continuously scan until alert condition is met")
    add_common_flags(watch_cmd)
    watch_cmd.add_argument("--interval", type=int, default=30, help="Seconds between scans")
    watch_cmd.set_defaults(func=cmd_watch)

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