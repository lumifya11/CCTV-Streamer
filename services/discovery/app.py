"""FastAPI application for the Camera Discovery Microservice."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.discovery.onvif_scanner import OnvifProbeDevice, OnvifScanner
from services.discovery.port_scanner import HostScanResult, NetworkPortScanner, probe_tcp_port, verify_rtsp_endpoint
from shared.config import AppConfig, get_config
from shared.logger import get_logger
from shared.models import (
    CameraDevice,
    DiscoveryRequest,
    DiscoveryResult,
    HealthStatus,
    RTSPEndpoint,
    utc_now_iso,
)
from shared.security import mask_rtsp_credentials, validate_subnet_cidr, verify_api_key

logger = get_logger("discovery.service")
SERVICE_START_TIME = time.monotonic()


class DirectCameraProbeRequest(BaseModel):
    ip_address: str = Field(..., description="Target IPv4 address to probe")
    ports: List[int] = Field(default_factory=lambda: [554, 8554, 80, 8000, 8080])
    username: Optional[str] = None
    password: Optional[str] = None
    timeout_sec: float = Field(default=1.0, ge=0.2, le=5.0)


def _camera_id_for_ip(ip_address: str) -> str:
    digest = hashlib.sha256(ip_address.encode("utf-8")).hexdigest()[:10]
    return f"cam-{digest}"


class CameraDiscoveryRegistry:
    """Thread-safe registry managing discovered ONVIF and RTSP camera devices."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._lock = threading.RLock()
        self._cameras: Dict[str, CameraDevice] = {}
        self._last_scan_result: Optional[DiscoveryResult] = None

        if self.config.enable_demo_streams:
            self._seed_default_enterprise_cameras()

    def _seed_default_enterprise_cameras(self) -> None:
        """Seed default synthetic/demo ONVIF cameras so the platform operates out-of-the-box."""
        presets = [
            (
                "cam-north-gate",
                "North Perimeter Gate PTZ",
                "192.168.10.101",
                "Axis Communications",
                "AXIS Q6135-LE PTZ",
                "Perimeter North",
                "demo://north-gate",
            ),
            (
                "cam-server-vault",
                "Data Center Corridor B2",
                "192.168.10.102",
                "Hikvision",
                "DS-2CD2186G2-ISU",
                "Server Vault B2",
                "demo://server-vault",
            ),
            (
                "cam-loading-bay",
                "Logistics Loading Dock 4",
                "192.168.10.103",
                "Dahua",
                "IPC-HFW5849T1-ASE-LED",
                "Loading Dock 4",
                "demo://loading-bay",
            ),
            (
                "cam-lobby-main",
                "Executive Terminal Main Concourse",
                "192.168.10.104",
                "Hanwha Vision",
                "XNV-8082R",
                "Terminal Concourse",
                "demo://lobby-main",
            ),
        ]
        with self._lock:
            for cam_id, name, ip, vendor, model, loc, url in presets:
                self._cameras[cam_id] = CameraDevice(
                    camera_id=cam_id,
                    name=name,
                    ip_address=ip,
                    open_ports=[554, 80, 8000],
                    onvif_supported=True,
                    onvif_xaddr=f"http://{ip}:80/onvif/device_service",
                    manufacturer=vendor,
                    model=model,
                    firmware_version="v5.8.12-enterprise",
                    location=loc,
                    rtsp_endpoints=[
                        RTSPEndpoint(
                            url=url,
                            transport="tcp",
                            port=554,
                            path="/Streaming/Channels/101",
                            profile_token="MainStream_1080p",
                            resolution="1280x720",
                            codec="H.264",
                            verified=True,
                        )
                    ],
                    primary_rtsp_url=url,
                    latency_ms=2.4,
                    discovered_via=["onvif", "port_scan"],
                    online=True,
                )

    def list_cameras(self) -> List[CameraDevice]:
        with self._lock:
            return list(self._cameras.values())

    def get_camera(self, camera_id: str) -> Optional[CameraDevice]:
        with self._lock:
            return self._cameras.get(camera_id)

    def upsert_camera(self, camera: CameraDevice) -> CameraDevice:
        with self._lock:
            self._cameras[camera.camera_id] = camera
            return camera

    def execute_discovery(self, req: DiscoveryRequest) -> DiscoveryResult:
        """Run combined ONVIF WS-Discovery and concurrent TCP/RTSP port scanning."""
        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        started_at = utc_now_iso()
        t0 = time.monotonic()

        subnets = req.subnets if req.subnets is not None else self.config.discovery_subnets
        ports = req.ports if req.ports is not None else self.config.discovery_ports

        # Validate all requested CIDR blocks before scanning
        for subnet in subnets:
            if "/" in subnet:
                validate_subnet_cidr(subnet, max_hosts=1024)

        onvif_devices: List[OnvifProbeDevice] = []
        if req.enable_onvif_multicast:
            onvif_scanner = OnvifScanner(
                multicast_host=self.config.onvif_multicast_host,
                multicast_port=self.config.onvif_multicast_port,
                timeout_sec=min(req.timeout_sec, self.config.onvif_discovery_timeout_sec),
                username=self.config.onvif_username,
                password=self.config.onvif_password,
            )
            onvif_devices = onvif_scanner.discover_multicast()

        port_scan_results: List[HostScanResult] = []
        if req.enable_port_scan and subnets:
            port_scanner = NetworkPortScanner(
                ports=ports,
                timeout_sec=req.timeout_sec,
                max_workers=self.config.discovery_max_workers,
                rtsp_username=self.config.rtsp_default_username,
                rtsp_password=self.config.rtsp_default_password,
            )
            port_scan_results = port_scanner.scan_subnets(
                subnets=subnets,
                verify_rtsp=req.verify_rtsp_endpoints,
            )

        merged_by_ip: Dict[str, CameraDevice] = {}

        for odev in onvif_devices:
            cam_id = _camera_id_for_ip(odev.ip_address)
            primary_url = (
                odev.rtsp_endpoints[0].url
                if odev.rtsp_endpoints
                else f"rtsp://{odev.ip_address}:554/Streaming/Channels/101"
            )
            merged_by_ip[odev.ip_address] = CameraDevice(
                camera_id=cam_id,
                name=f"{odev.manufacturer} {odev.model} ({odev.ip_address})",
                ip_address=odev.ip_address,
                open_ports=[554, 80],
                onvif_supported=True,
                onvif_xaddr=odev.xaddr,
                manufacturer=odev.manufacturer,
                model=odev.model,
                firmware_version=odev.firmware_version,
                serial_number=odev.serial_number,
                location=odev.location,
                rtsp_endpoints=odev.rtsp_endpoints,
                primary_rtsp_url=mask_rtsp_credentials(primary_url),
                latency_ms=odev.response_time_ms,
                discovered_via=["onvif"],
                online=True,
            )

        for host_res in port_scan_results:
            ip = host_res.ip_address
            if ip in merged_by_ip:
                existing = merged_by_ip[ip]
                combined_ports = sorted(set(existing.open_ports + host_res.open_ports))
                existing.open_ports = combined_ports
                if "port_scan" not in existing.discovered_via:
                    existing.discovered_via.append("port_scan")
                existing_urls = {ep.url for ep in existing.rtsp_endpoints}
                for ep in host_res.rtsp_endpoints:
                    if ep.url not in existing_urls:
                        existing.rtsp_endpoints.append(ep)
                if not existing.primary_rtsp_url and existing.rtsp_endpoints:
                    existing.primary_rtsp_url = existing.rtsp_endpoints[0].url
            else:
                cam_id = _camera_id_for_ip(ip)
                primary_url = (
                    host_res.rtsp_endpoints[0].url
                    if host_res.rtsp_endpoints
                    else f"rtsp://{ip}:554/stream1"
                )
                merged_by_ip[ip] = CameraDevice(
                    camera_id=cam_id,
                    name=f"{host_res.manufacturer_hint} Camera ({ip})",
                    ip_address=ip,
                    open_ports=host_res.open_ports,
                    onvif_supported=(host_res.onvif_http_port is not None),
                    onvif_xaddr=(
                        f"http://{ip}:{host_res.onvif_http_port}/onvif/device_service"
                        if host_res.onvif_http_port
                        else None
                    ),
                    manufacturer=host_res.manufacturer_hint,
                    model="RTSP Network Camera",
                    location="Discovered Subnet",
                    rtsp_endpoints=host_res.rtsp_endpoints,
                    primary_rtsp_url=mask_rtsp_credentials(primary_url),
                    latency_ms=host_res.latency_ms,
                    discovered_via=["port_scan"],
                    online=True,
                )

        with self._lock:
            for cam in merged_by_ip.values():
                self._cameras[cam.camera_id] = cam
            all_cameras = (
                list(merged_by_ip.values())
                if merged_by_ip or not req.include_simulated_if_empty
                else list(self._cameras.values())
            )

        duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
        result = DiscoveryResult(
            scan_id=scan_id,
            started_at=started_at,
            completed_at=utc_now_iso(),
            duration_ms=duration_ms,
            subnets_scanned=subnets,
            ports_probed=ports,
            onvif_devices_found=len(onvif_devices),
            port_scan_hosts_found=len(port_scan_results),
            cameras=all_cameras,
        )
        with self._lock:
            self._last_scan_result = result

        logger.info(
            "Discovery scan %s completed in %.1f ms (ONVIF=%d, PortScan=%d, Total=%d)",
            scan_id,
            duration_ms,
            len(onvif_devices),
            len(port_scan_results),
            len(all_cameras),
        )
        return result


config = get_config()
registry = CameraDiscoveryRegistry(config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting Camera Discovery Microservice on %s:%d",
        config.discovery_host,
        config.discovery_port,
    )
    yield
    logger.info("Shutting down Camera Discovery Microservice")


app = FastAPI(
    title="CCTV-Streamer Camera Discovery Service",
    description="Enterprise ONVIF WS-Discovery & Concurrent RTSP Port Scanning Microservice",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthStatus)
async def health_check() -> HealthStatus:
    return HealthStatus(
        service="discovery",
        status="healthy",
        uptime_seconds=round(time.monotonic() - SERVICE_START_TIME, 2),
        details={
            "registered_cameras": len(registry.list_cameras()),
            "configured_subnets": config.discovery_subnets,
            "configured_ports": config.discovery_ports,
        },
    )


@app.get("/api/v1/cameras", response_model=List[CameraDevice])
async def list_discovered_cameras(
    online_only: bool = Query(default=False),
    _: bool = Depends(verify_api_key),
) -> List[CameraDevice]:
    cameras = registry.list_cameras()
    if online_only:
        cameras = [c for c in cameras if c.online]
    return cameras


@app.get("/api/v1/cameras/{camera_id}", response_model=CameraDevice)
async def get_camera_details(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    camera = registry.get_camera(camera_id)
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Camera '{camera_id}' not found in discovery registry.",
        )
    return camera


@app.post("/api/v1/discover", response_model=DiscoveryResult)
async def trigger_network_discovery(
    request: DiscoveryRequest = DiscoveryRequest(),
    _: bool = Depends(verify_api_key),
) -> DiscoveryResult:
    try:
        return registry.execute_discovery(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/cameras/probe", response_model=CameraDevice)
async def probe_single_camera(
    request: DirectCameraProbeRequest,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    """Directly probe a single IP address for open RTSP/ONVIF ports and register it."""
    try:
        validate_subnet_cidr(f"{request.ip_address}/32")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    open_ports: List[int] = []
    latencies: List[float] = []
    for port in request.ports:
        is_open, lat = probe_tcp_port(request.ip_address, port, request.timeout_sec)
        if is_open:
            open_ports.append(port)
            latencies.append(lat)

    endpoints: List[RTSPEndpoint] = []
    for port in (p for p in open_ports if p in (554, 8554)):
        valid, _, code = verify_rtsp_endpoint(
            ip_address=request.ip_address,
            port=port,
            path="/Streaming/Channels/101",
            username=request.username or config.rtsp_default_username,
            password=request.password or config.rtsp_default_password,
            timeout_sec=request.timeout_sec,
        )
        endpoints.append(
            RTSPEndpoint(
                url=f"rtsp://{request.ip_address}:{port}/Streaming/Channels/101",
                transport="tcp",
                port=port,
                path="/Streaming/Channels/101",
                verified=(valid and code == "200"),
            )
        )

    if not endpoints:
        endpoints.append(
            RTSPEndpoint(
                url=f"rtsp://{request.ip_address}:554/stream1",
                transport="tcp",
                port=554,
                path="/stream1",
                verified=False,
            )
        )

    cam_id = _camera_id_for_ip(request.ip_address)
    device = CameraDevice(
        camera_id=cam_id,
        name=f"Probed Camera ({request.ip_address})",
        ip_address=request.ip_address,
        open_ports=open_ports,
        onvif_supported=any(p in (80, 8000, 8080, 8899) for p in open_ports),
        primary_rtsp_url=endpoints[0].url,
        rtsp_endpoints=endpoints,
        latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        discovered_via=["direct_probe"],
        online=bool(open_ports),
    )
    registry.upsert_camera(device)
    return device


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.discovery.app:app",
        host=config.discovery_host,
        port=config.discovery_port,
        reload=False,
    )
