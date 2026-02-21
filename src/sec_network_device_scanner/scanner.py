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
# Gateway + Network Detection
# -------------------------------------------------

def _get_default_gateway_ipconfig_windows() -> str | None:
    """
    Best-effort fallback gateway detection via ipconfig (can pick VPN gateway).
    """
    try:
        output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        match = re.search(r"Default Gateway[ .:]+(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
    except Exception:
        return None
    return None


def get_gateway_for_network(network: ipaddress.IPv4Network) -> str | None:
    """
    Return the default gateway IP that belongs to the given `network` (best effort).
    On Windows: parse `route.exe print -4` and pick the default route whose Interface IP is in `network`.
    On Linux/macOS: parse `ip route` default via (usually OK because network selection is already sane).
    """
    system = platform.system().lower()

    if system.startswith("win"):
        try:
            out = subprocess.check_output(["route", "print", "-4"], text=True, errors="ignore")
            # Lines look like:
            # 0.0.0.0          0.0.0.0      10.175.142.245   10.175.142.179     25
            pattern = re.compile(
                r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+"
                r"(?P<gw>\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"(?P<iface>\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"(?P<metric>\d+)\s*$"
            )

            candidates: list[tuple[int, str]] = []  # (metric, gateway)
            for line in out.splitlines():
                m = pattern.match(line)
                if not m:
                    continue
                gw = m.group("gw")
                iface_ip = m.group("iface")
                metric = int(m.group("metric"))

                try:
                    if ipaddress.IPv4Address(iface_ip) in network and ipaddress.IPv4Address(gw) in network:
                        candidates.append((metric, gw))
                except ValueError:
                    continue

            if candidates:
                candidates.sort(key=lambda x: x[0])
                return candidates[0][1]

            # Fallback (may be VPN): ipconfig gateway
            return _get_default_gateway_ipconfig_windows()
        except Exception:
            return _get_default_gateway_ipconfig_windows()

    # Linux/macOS
    try:
        out = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            gw = m.group(1)
            if ipaddress.IPv4Address(gw) in network:
                return gw
            return gw
    except Exception:
        return None
    return None


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
            if net.prefixlen <= 30:
                candidates.append(net)

    # de-dup
    seen: set[str] = set()
    unique: list[ipaddress.IPv4Network] = []
    for n in candidates:
        s = str(n)
        if s not in seen:
            seen.add(s)
            unique.append(n)
    return unique


def _pick_ipv4_network_smart() -> ipaddress.IPv4Network:
    """
    Smart selection:
    - prefer "reasonable" networks (>= /16)
    - if there is a gateway, pick the most specific network that contains it
    - fallback to most specific reasonable network
    """
    candidates = list_ipv4_candidates()
    reasonable = [n for n in candidates if n.prefixlen >= 16] or candidates

    # Try to choose by any detected gateway (ipconfig fallback)
    gw_guess = _get_default_gateway_ipconfig_windows() if platform.system().lower().startswith("win") else None
    if gw_guess:
        try:
            gw_ip = ipaddress.IPv4Address(gw_guess)
            matches = [n for n in reasonable if gw_ip in n]
            if matches:
                matches.sort(key=lambda n: n.prefixlen, reverse=True)
                return matches[0]
        except ValueError:
            pass

    if reasonable:
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
    method = method.lower().strip()
    is_windows = platform.system().lower().startswith("win")

    if method == "scapy":
        return _arp_scan_scapy(network, timeout)

    if method == "windows":
        if not is_windows:
            raise RuntimeError("Windows scan method is only available on Windows.")
        return _arp_scan_windows(network)

    try:
        return _arp_scan_scapy(network, timeout)
    except Exception:
        if is_windows:
            return _arp_scan_windows(network)
        raise