"""Concurrent TCP port scanner and RTSP endpoint protocol handshake verifier."""

from __future__ import annotations

import base64
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from shared.logger import get_logger
from shared.models import RTSPEndpoint
from shared.security import expand_subnet_hosts, mask_rtsp_credentials

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
    """Discovered host with open CCTV/RTSP/ONVIF TCP ports and verified RTSP streams."""

    ip_address: str
    open_ports: List[int] = field(default_factory=list)
    latency_ms: float = 0.0
    manufacturer_hint: str = "Generic"
    rtsp_endpoints: List[RTSPEndpoint] = field(default_factory=list)
    onvif_http_port: Optional[int] = None


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
    Perform an RTSP OPTIONS/DESCRIBE protocol probe over TCP to confirm a valid RTSP service.

    Returns:
        (is_valid_rtsp, server_header, status_code_str)
    """
    target_uri = f"rtsp://{ip_address}:{port}{path}"
    headers = [
        f"OPTIONS {target_uri} RTSP/1.0",
        "CSeq: 1",
        "User-Agent: CCTV-Streamer-Discovery/1.0",
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

    # 200 OK, 401 Unauthorized, or 454 Session Not Found all prove a live RTSP server
    is_valid = status_code in ("200", "401", "403", "454")
    return (is_valid, server_header, status_code)


class NetworkPortScanner:
    """High-concurrency network scanner for RTSP and ONVIF camera ports."""

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout_sec: float = 0.8,
        max_workers: int = 64,
        rtsp_username: Optional[str] = None,
        rtsp_password: Optional[str] = None,
    ) -> None:
        self.ports = ports or [554, 8554, 80, 8000, 8080, 8899]
        self.timeout_sec = timeout_sec
        self.max_workers = max(1, min(256, max_workers))
        self.rtsp_username = rtsp_username
        self.rtsp_password = rtsp_password

    def scan_subnets(
        self,
        subnets: List[str],
        verify_rtsp: bool = True,
        max_hosts_per_subnet: int = 1024,
    ) -> List[HostScanResult]:
        """Scan all hosts in the given CIDR subnets for open camera ports and RTSP endpoints."""
        hosts = expand_subnet_hosts(subnets, max_hosts_per_subnet=max_hosts_per_subnet)
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
                self._discover_host_rtsp_endpoints(scan_res)
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

    def _discover_host_rtsp_endpoints(self, host_result: HostScanResult) -> None:
        """Probe open RTSP candidate ports on a discovered host for responsive RTSP streams."""
        candidate_ports = [
            p for p in host_result.open_ports if p in RTSP_CANDIDATE_PORTS
        ]
        if not candidate_ports and host_result.open_ports:
            # If only HTTP/ONVIF ports were open, also synthesize standard port 554 entry
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
            verified_any = False
            for path, vendor, profile in COMMON_RTSP_PATHS:
                is_valid, server_hdr, status_code = verify_rtsp_endpoint(
                    ip_address=host_result.ip_address,
                    port=port,
                    path=path,
                    username=self.rtsp_username,
                    password=self.rtsp_password,
                    timeout_sec=self.timeout_sec,
                )
                if is_valid:
                    verified_any = True
                    if server_hdr:
                        host_result.manufacturer_hint = server_hdr
                    elif host_result.manufacturer_hint == "Generic":
                        host_result.manufacturer_hint = vendor
                    raw_url = f"rtsp://{host_result.ip_address}:{port}{path}"
                    host_result.rtsp_endpoints.append(
                        RTSPEndpoint(
                            url=mask_rtsp_credentials(raw_url),
                            transport="tcp",
                            port=port,
                            path=path,
                            profile_token=profile,
                            verified=(status_code == "200"),
                        )
                    )
                    break

            if not verified_any:
                # Port is open via TCP handshake even if custom RTSP path wasn't matched
                host_result.rtsp_endpoints.append(
                    RTSPEndpoint(
                        url=f"rtsp://{host_result.ip_address}:{port}/stream1",
                        transport="tcp",
                        port=port,
                        path="/stream1",
                        verified=False,
                    )
                )
