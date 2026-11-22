"""Pluggable Local Network Discovery Adapters: mDNS, SSDP/UPnP, and Local ARP Inventory."""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Dict, List, Optional


def read_local_arp_table(arp_path: str = "/proc/net/arp") -> Dict[str, str]:
    """
    Read the local kernel ARP cache to enrich discovered local IPs with MAC addresses.
    Returns a mapping of `{ip_address: mac_address}` for entries on the local link.
    """
    path = Path(arp_path)
    if not path.is_file():
        return {}
    mapping: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip_addr = parts[0].strip()
                mac_addr = parts[3].strip().lower()
                if mac_addr and mac_addr != "00:00:00:00:00:00":
                    mapping[ip_addr] = mac_addr
    except OSError:
        return {}
    return mapping


def discover_ssdp_camera_candidates(timeout_sec: float = 0.8) -> List[Dict[str, str]]:
    """
    Send a low-impact SSDP M-SEARCH multicast query on the local link and filter
    only devices advertising camera/media/ONVIF service descriptions.
    """
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    candidates: Dict[str, Dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(timeout_sec)
        sock.sendto(msearch, ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            text = data.decode("utf-8", errors="ignore")
            lower = text.lower()
            if any(k in lower for k in ("camera", "onvif", "ipcam", "rtsp", "dvr", "nvr")):
                ip = addr[0]
                server_match = re.search(r"SERVER:\s*(.+)", text, re.IGNORECASE)
                candidates[ip] = {
                    "ip_address": ip,
                    "server": server_match.group(1).strip() if server_match else "SSDP Camera Candidate",
                }
    except OSError:
        pass
    finally:
        sock.close()
    return list(candidates.values())
