"""Scoped TCP port scanner and unauthenticated RTSP protocol service identifier."""

from __future__ import annotations

import base64
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from shared.logger import get_logger
from shared.models import RTSPEndpoint
from shared.security import expand_subnet_hosts, sanitize_uri_template

logger = get_logger("discovery.port_scanner")

# Common enterprise IP camera RTSP endpoint templates across vendors
COMMON_RTSP_PATHS: List[Tuple[str, str, str]] = [
    ("/Streaming/Channels/101", "Hikvision", "MainStream-1080p"),
    ("/cam/realmonitor?channel=1&subtype=0", "Dahua", "MainStream-1080p"),
    ("/axis-media/media.amp", "Axis", "H264-Stream"),
    ("/live/ch0", "Ubiquiti/Generic", "Channel-0"),
    ("/h264Preview_01_main", "Reolink", "MainStream"),
    ("/stream1", "ONVIF-Generic", "Stream-1"),
]

RTSP_CANDIDATE_PORTS = (554, 8554)
ONVIF_HTTP_PORTS = (80, 8000, 8080, 8899)


@dataclass
class HostScanResult:
    """Discovered host candidate with open CCTV/RTSP/ONVIF TCP ports."""

    ip_address: str
    open_ports: List[int] = field(default_factory=list)
    latency_ms: float = 0.0
    manufacturer_hint: str = "Generic"
    rtsp_endpoints: List[RTSPEndpoint] = field(default_factory=list)
    onvif_http_port: Optional[int] = None
    rtsp_service_detected: bool = False


def probe_tcp_port(ip_address: str, port: int, timeout_sec: float = 0.8) -> Tuple[bool, float]:
    """Attempt a TCP handshake to (ip_address, port) and return (is_open, latency_ms)."""
    start = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    try:
        result = sock.connect_ex((ip_address, port))
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return (result == 0, round(elapsed_ms, 2))
    except OSError:
        return (False, 0.0)
    finally:
        sock.close()


def verify_rtsp_endpoint(
    ip_address: str,
    port: int = 554,
    path: str = "/stream1",
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout_sec: float = 1.0,
) -> Tuple[bool, Optional[str], str]:
    """
    Perform an RTSP OPTIONS protocol check over TCP.
    During broad discovery, `username` and `password` MUST be None (unauthenticated identification).
    Credentials may only be supplied during explicit single-device enrollment verification.
    """
    target_uri = f"rtsp://{ip_address}:{port}{path}"
    headers = [
        f"OPTIONS {target_uri} RTSP/1.0",
        "CSeq: 1",
        "User-Agent: CCTV-Streamer-Discovery/1.1",
    ]
    if username:
        raw_creds = f"{username}:{password or ''}".encode("utf-8")
        b64_creds = base64.b64encode(raw_creds).decode("ascii")
        headers.append(f"Authorization: Basic {b64_creds}")

    request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_sec)
    try:
        sock.connect((ip_address, port))
        sock.sendall(request_bytes)
        response = sock.recv(4096).decode("utf-8", errors="ignore")
    except OSError:
        return (False, None, "")
    finally:
        sock.close()

    if not response.startswith("RTSP/1.0"):
        return (False, None, "")

    lines = response.splitlines()
    status_line = lines[0].strip() if lines else ""
    parts = status_line.split()
    status_code = parts[1] if len(parts) >= 2 else ""

    server_header = None
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break

    is_valid = status_code in ("200", "401", "403", "454")
    return (is_valid, server_header, status_code)


class NetworkPortScanner:
    """
    Scoped, rate-limited network scanner for RTSP and ONVIF camera ports.
    Strictly non-authenticating: never sends default or configured passwords during subnet scans.
    """

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout_sec: float = 0.8,
        max_workers: int = 64,
    ) -> None:
        self.ports = ports or [554, 8554, 80, 8000, 8080, 8899]
        self.timeout_sec = timeout_sec
        self.max_workers = max(1, min(128, max_workers))

    def scan_subnets(
        self,
        subnets: List[str],
        verify_rtsp: bool = True,
        max_hosts_per_subnet: int = 1024,
    ) -> List[HostScanResult]:
        """Scan hosts in approved private CIDR subnets for open camera ports (unauthenticated)."""
        hosts = expand_subnet_hosts(
            subnets, max_hosts_per_subnet=max_hosts_per_subnet, allow_public=False
        )
        if not hosts:
            return []

        host_ports: Dict[str, List[Tuple[int, float]]] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {
                executor.submit(probe_tcp_port, ip, port, self.timeout_sec): (ip, port)
                for ip in hosts
                for port in self.ports
            }
            for future in as_completed(future_map):
                ip, port = future_map[future]
                try:
                    is_open, latency_ms = future.result()
                except Exception:
                    continue
                if is_open:
                    host_ports.setdefault(ip, []).append((port, latency_ms))

        results: List[HostScanResult] = []
        for ip, open_entries in sorted(host_ports.items()):
            open_entries.sort(key=lambda item: item[0])
            ports_only = [p for p, _ in open_entries]
            avg_latency = round(
                sum(lat for _, lat in open_entries) / len(open_entries), 2
            )
            onvif_port = next(
                (p for p in ports_only if p in ONVIF_HTTP_PORTS), None
            )

            scan_res = HostScanResult(
                ip_address=ip,
                open_ports=ports_only,
                latency_ms=avg_latency,
                onvif_http_port=onvif_port,
            )

            if verify_rtsp:
                self._identify_host_rtsp_service_unauthenticated(scan_res)
            else:
                for p in ports_only:
                    if p in RTSP_CANDIDATE_PORTS:
                        scan_res.rtsp_endpoints.append(
                            RTSPEndpoint(
                                url=f"rtsp://{ip}:{p}/stream1",
                                transport="tcp",
                                port=p,
                                path="/stream1",
                                verified=False,
                            )
                        )

            results.append(scan_res)

        return results

    def _identify_host_rtsp_service_unauthenticated(
        self, host_result: HostScanResult
    ) -> None:
        """
        Issue unauthenticated RTSP OPTIONS probes to identify RTSP service banners.
        Never sends credentials and never marks `verified=True` until explicit enrollment.
        """
        candidate_ports = [
            p for p in host_result.open_ports if p in RTSP_CANDIDATE_PORTS
        ]
        if not candidate_ports and host_result.open_ports:
            host_result.rtsp_endpoints.append(
                RTSPEndpoint(
                    url=f"rtsp://{host_result.ip_address}:554/stream1",
                    transport="tcp",
                    port=554,
                    path="/stream1",
                    verified=False,
                )
            )
            return

        for port in candidate_ports:
            detected_any = False
            for path, vendor, profile in COMMON_RTSP_PATHS:
                is_rtsp, server_hdr, _ = verify_rtsp_endpoint(
                    ip_address=host_result.ip_address,
                    port=port,
                    path=path,
                    username=None,
                    password=None,
                    timeout_sec=self.timeout_sec,
                )
                if is_rtsp:
                    detected_any = True
                    host_result.rtsp_service_detected = True
                    if server_hdr:
                        host_result.manufacturer_hint = server_hdr
                    elif host_result.manufacturer_hint == "Generic":
                        host_result.manufacturer_hint = vendor
                    raw_url = sanitize_uri_template(
                        f"rtsp://{host_result.ip_address}:{port}{path}"
                    )
                    host_result.rtsp_endpoints.append(
                        RTSPEndpoint(
                            url=raw_url,
                            transport="tcp",
                            port=port,
                            path=path,
                            profile_token=profile,
                            verified=False,  # Remains unverified until explicit enrollment
                        )
                    )
                    break

            if not detected_any:
                host_result.rtsp_endpoints.append(
                    RTSPEndpoint(
                        url=f"rtsp://{host_result.ip_address}:{port}/stream1",
                        transport="tcp",
                        port=port,
                        path="/stream1",
                        verified=False,
                    )
                )
