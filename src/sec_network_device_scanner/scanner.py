from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import psutil

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
except Exception:  # pragma: no cover
    ARP = Ether = srp = None  # type: ignore


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str


# -------------------------------------------------
# Gateway Detection
# -------------------------------------------------

def get_default_gateway() -> str | None:
    """
    Best-effort default gateway detection.
    - Windows: parse `ipconfig`
    - Linux/macOS: parse `ip route`
    """
    system = platform.system().lower()
    try:
        if system.startswith("win"):
            output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            # Example: "Default Gateway . . . . . . . . . : 10.175.142.245"
            match = re.search(r"Default Gateway[ .:]+(\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        else:
            output = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
    except Exception:
        return None
    return None


# -------------------------------------------------
# Network detection
# -------------------------------------------------

def list_ipv4_candidates() -> list[ipaddress.IPv4Network]:
    candidates: list[ipaddress.IPv4Network] = []
    for _, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family.name != "AF_INET":
                continue
            if not a.address or a.address.startswith("127."):
                continue
            if not a.netmask:
                continue

            ip = ipaddress.IPv4Address(a.address)
            net = ipaddress.IPv4Network(f"{ip}/{a.netmask}", strict=False)

            # Avoid tiny networks like /32
            if net.prefixlen <= 30:
                candidates.append(net)

    # De-dup while preserving order
    seen: set[str] = set()
    unique: list[ipaddress.IPv4Network] = []
    for n in candidates:
        key = str(n)
        if key not in seen:
            seen.add(key)
            unique.append(n)
    return unique


def _pick_ipv4_network_smart() -> ipaddress.IPv4Network:
    """
    Smart selection:
    1) detect default gateway
    2) prefer networks that contain gateway
    3) ignore huge networks (/8, /9, /10, etc.)
    4) prefer most specific reasonable network
    """

    candidates = list_ipv4_candidates()
    gw = get_default_gateway()

    # Filter out extremely large networks (e.g. /8)
    reasonable = [n for n in candidates if n.prefixlen >= 16]

    if not reasonable:
        reasonable = candidates

    if gw:
        gw_ip = ipaddress.IPv4Address(gw)
        matches = [n for n in reasonable if gw_ip in n]

        if matches:
            # Prefer most specific (largest prefix)
            matches.sort(key=lambda n: n.prefixlen, reverse=True)
            return matches[0]

    if reasonable:
        # Fallback to most specific reasonable network
        reasonable.sort(key=lambda n: n.prefixlen, reverse=True)
        return reasonable[0]

    raise RuntimeError("Could not auto-detect local IPv4 network. Use --cidr.")


def resolve_cidr(cidr: str | None) -> ipaddress.IPv4Network:
    if cidr:
        return ipaddress.IPv4Network(cidr, strict=False)
    return _pick_ipv4_network_smart()


# -------------------------------------------------
# Device filtering
# -------------------------------------------------

def _is_valid_device(ip: str, mac: str) -> bool:
    mac_u = mac.upper()
    if mac_u in {"FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"}:
        return False

    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False
    except ValueError:
        return False

    return True


# -------------------------------------------------
# Scapy Layer-2 ARP Scan
# -------------------------------------------------

def _arp_scan_scapy(network: ipaddress.IPv4Network, timeout: int = 2) -> list[Device]:
    """
    True ARP sweep using Scapy (Layer 2). Requires Npcap on Windows.
    """
    if ARP is None or Ether is None or srp is None:
        raise RuntimeError("Scapy is not available for L2 scanning.")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(pkt, timeout=timeout, verbose=False)

    devices: list[Device] = []
    for _, recv in answered:
        devices.append(Device(ip=str(recv.psrc), mac=str(recv.hwsrc).upper()))

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices


# -------------------------------------------------
# Windows fallback (UDP-probe + arp -a)
# -------------------------------------------------

def _probe_windows(ip: str) -> None:
    """
    Send a tiny UDP packet to force Windows to ARP-resolve the target IP.
    This can discover hosts even if ICMP ping is blocked.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.05)
            s.sendto(b"\x00", (ip, 1))
    except Exception:
        pass


def _parse_windows_arp(text: str) -> list[Device]:
    pattern = re.compile(
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
    )

    devices: list[Device] = []
    for match in pattern.finditer(text):
        ip = match.group("ip")
        mac = match.group("mac").replace("-", ":").upper()

        if _is_valid_device(ip, mac):
            devices.append(Device(ip=ip, mac=mac))

    devices.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return devices


def _arp_scan_windows(network: ipaddress.IPv4Network) -> list[Device]:
    hosts = [str(ip) for ip in network.hosts()]

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(_probe_windows, ip) for ip in hosts]
        for _ in as_completed(futures):
            pass

    arp_output = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
    devices = _parse_windows_arp(arp_output)

    return [d for d in devices if ipaddress.IPv4Address(d.ip) in network]


# -------------------------------------------------
# Public API
# -------------------------------------------------

def scan(network: ipaddress.IPv4Network, timeout: int = 2, method: str = "auto") -> list[Device]:
    """
    method:
      - auto: Scapy first, fallback on Windows
      - scapy: force Layer 2 ARP scan
      - windows: force Windows UDP-probe + arp -a fallback
    """
    method = method.lower().strip()
    is_windows = platform.system().lower().startswith("win")

    if method == "scapy":
        return _arp_scan_scapy(network, timeout)

    if method == "windows":
        if not is_windows:
            raise RuntimeError("Windows scan method is only available on Windows.")
        return _arp_scan_windows(network)

    # auto
    try:
        return _arp_scan_scapy(network, timeout)
    except Exception:
        if is_windows:
            return _arp_scan_windows(network)
        raise