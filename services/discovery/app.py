"""FastAPI application for the Scoped, Non-Authenticating Camera Discovery Microservice."""

from __future__ import annotations

import json
import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.device_manager.registry import DurableDeviceRegistry
from services.discovery.adapters import discover_ssdp_camera_candidates, read_local_arp_table
from services.discovery.onvif_scanner import OnvifProbeDevice, OnvifScanner
from services.discovery.port_scanner import (
    HostScanResult,
    NetworkPortScanner,
    probe_tcp_port,
    verify_rtsp_endpoint,
)
from shared.audit import record_audit_event
from shared.config import AppConfig, get_config
from shared.database import DatabaseManager, get_db
from shared.logger import get_logger
from shared.models import (
    CameraDevice,
    CompatibilityTier,
    DeviceLifecycleState,
    DiscoveryRequest,
    DiscoveryResult,
    HealthStatus,
    RTSPEndpoint,
    utc_now_iso,
)
from shared.security import (
    sanitize_uri_template,
    validate_subnet_cidr,
    verify_api_key,
)

logger = get_logger("discovery.service")
SERVICE_START_TIME = time.monotonic()


class DirectCameraProbeRequest(BaseModel):
    ip_address: str = Field(..., description="Target authorized IPv4 address to probe")
    site_id: str = Field(default="site-default")
    ports: List[int] = Field(default_factory=lambda: [554, 8554, 80, 8000, 8080])
    timeout_sec: float = Field(default=1.0, ge=0.2, le=5.0)


class CameraDiscoveryRegistry:
    """
    Coordinates non-authenticating ONVIF WS-Discovery and scoped TCP/RTSP discovery,
    persisting all candidates in the DurableDeviceRegistry (`shared/database.py`).
    """

    def __init__(self, config: AppConfig, db: Optional[DatabaseManager] = None) -> None:
        self.config = config
        self.db = db or get_db()
        self.durable_registry = DurableDeviceRegistry(db=self.db)
        self._lock = threading.RLock()
        self._last_scan_result: Optional[DiscoveryResult] = None

        if self.config.enable_demo_streams:
            self._seed_default_enterprise_cameras()

    def _seed_default_enterprise_cameras(self) -> None:
        """Seed demo ONVIF cameras only when ENABLE_DEMO_STREAMS is explicitly active."""
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
        for cam_id, name, ip, vendor, model, loc, url in presets:
            cam = CameraDevice(
                camera_id=cam_id,
                site_id="site-default",
                scope_id="scope-default-lan",
                name=name,
                ip_address=ip,
                open_ports=[554, 80, 8000],
                onvif_supported=True,
                onvif_xaddr=f"http://{ip}:80/onvif/device_service",
                onvif_profiles=["Profile_T", "Profile_G", "Profile_M"],
                compatibility_tier=CompatibilityTier.TIER_1_STANDARDS,
                lifecycle_state=DeviceLifecycleState.ONLINE,
                confidence=0.98,
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
                        onvif_profile="Profile_T",
                        resolution="1280x720",
                        codec="H.264",
                        verified=True,
                    )
                ],
                primary_rtsp_url=url,
                approved=True,
                approved_by="demo-profile",
                latency_ms=2.4,
                discovered_via=["onvif", "port_scan"],
                online=True,
            )
            self.durable_registry.upsert_discovered_device(cam)

    def list_cameras(
        self,
        site_id: Optional[str] = None,
        approved_only: bool = False,
        candidates_only: bool = False,
    ) -> List[CameraDevice]:
        return self.durable_registry.list_devices(
            site_id=site_id,
            approved_only=approved_only,
            candidates_only=candidates_only,
        )

    def get_camera(self, camera_id: str) -> Optional[CameraDevice]:
        return self.durable_registry.get_device(camera_id)

    def upsert_camera(self, camera: CameraDevice) -> CameraDevice:
        return self.durable_registry.upsert_discovered_device(camera)

    def execute_discovery(self, req: DiscoveryRequest) -> DiscoveryResult:
        """
        Run scope-bound, non-authenticating ONVIF WS-Discovery and TCP/RTSP service identification.
        Never sends default or saved credentials during discovery.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:10]}"
        started_at = utc_now_iso()
        t0 = time.monotonic()

        subnets = (
            req.subnets
            if req.subnets is not None
            else (
                self.durable_registry.get_approved_cidrs(site_id=req.site_id)
                or self.config.discovery_subnets
            )
        )
        ports = req.ports if req.ports is not None else self.config.discovery_ports

        # Enforce private/approved CIDR validation before probing any host
        for subnet in subnets:
            cidr_to_check = f"{subnet}/32" if "/" not in subnet else subnet
            validate_subnet_cidr(cidr_to_check, max_hosts=1024, allow_public=False)

        self.db.execute(
            """
            INSERT INTO discovery_jobs (
                job_id, site_id, scope_ids_json, status, started_at
            )
            VALUES (?, ?, ?, 'RUNNING', ?)
            """,
            (scan_id, req.site_id, json.dumps([req.scope_id or "scope-default-lan"]), started_at),
        )

        arp_map = read_local_arp_table()

        onvif_devices: List[OnvifProbeDevice] = []
        if req.enable_onvif_multicast:
            onvif_scanner = OnvifScanner(
                multicast_host=self.config.onvif_multicast_host,
                multicast_port=self.config.onvif_multicast_port,
                timeout_sec=min(req.timeout_sec, self.config.onvif_discovery_timeout_sec),
            )
            # Non-authenticating multicast probe only (`enrich_via_soap=False`)
            onvif_devices = onvif_scanner.discover_multicast(enrich_via_soap=False)

        port_scan_results: List[HostScanResult] = []
        if req.enable_port_scan and subnets:
            port_scanner = NetworkPortScanner(
                ports=ports,
                timeout_sec=req.timeout_sec,
                max_workers=self.config.discovery_max_workers,
            )
            port_scan_results = port_scanner.scan_subnets(
                subnets=subnets,
                verify_rtsp=req.verify_rtsp_endpoints,
            )

        ssdp_candidates = (
            discover_ssdp_camera_candidates(timeout_sec=0.5)
            if req.enable_ssdp
            else []
        )

        merged_by_ip: Dict[str, Tuple[CameraDevice, Optional[str], Dict[str, str]]] = {}

        for odev in onvif_devices:
            primary_url = (
                odev.rtsp_endpoints[0].url
                if odev.rtsp_endpoints
                else f"rtsp://{odev.ip_address}:554/Streaming/Channels/101"
            )
            cam = CameraDevice(
                camera_id=f"dev-{uuid.uuid4().hex[:12]}",
                site_id=req.site_id,
                scope_id=req.scope_id,
                name=f"{odev.manufacturer} {odev.model} ({odev.ip_address})",
                ip_address=odev.ip_address,
                mac_address=arp_map.get(odev.ip_address),
                open_ports=[554, 80],
                onvif_supported=True,
                onvif_xaddr=odev.xaddr,
                onvif_profiles=odev.onvif_profiles,
                legacy_profile_s=odev.legacy_profile_s,
                compatibility_tier=CompatibilityTier.TIER_1_STANDARDS,
                lifecycle_state=DeviceLifecycleState.CAMERA_CANDIDATE,
                confidence=0.90,
                manufacturer=odev.manufacturer,
                model=odev.model,
                firmware_version=odev.firmware_version,
                serial_number=odev.serial_number,
                location=odev.location,
                rtsp_endpoints=odev.rtsp_endpoints,
                primary_rtsp_url=sanitize_uri_template(primary_url),
                approved=False,
                latency_ms=odev.response_time_ms,
                discovered_via=["onvif"],
                online=True,
            )
            merged_by_ip[odev.ip_address] = (
                cam,
                odev.endpoint_reference or None,
                {"method": "onvif_ws_discovery", "xaddr": odev.xaddr},
            )

        for host_res in port_scan_results:
            ip = host_res.ip_address
            if ip in merged_by_ip:
                existing, epr, ev = merged_by_ip[ip]
                existing.open_ports = sorted(set(existing.open_ports + host_res.open_ports))
                if "port_scan" not in existing.discovered_via:
                    existing.discovered_via.append("port_scan")
                existing_urls = {ep.url for ep in existing.rtsp_endpoints}
                for ep in host_res.rtsp_endpoints:
                    if ep.url not in existing_urls:
                        existing.rtsp_endpoints.append(ep)
            else:
                primary_url = (
                    host_res.rtsp_endpoints[0].url
                    if host_res.rtsp_endpoints
                    else f"rtsp://{ip}:554/stream1"
                )
                lifecycle = (
                    DeviceLifecycleState.CAMERA_CANDIDATE
                    if host_res.rtsp_service_detected or host_res.onvif_http_port
                    else DeviceLifecycleState.SERVICE_DETECTED
                )
                confidence = 0.78 if host_res.rtsp_service_detected else 0.55
                cam = CameraDevice(
                    camera_id=f"dev-{uuid.uuid4().hex[:12]}",
                    site_id=req.site_id,
                    scope_id=req.scope_id,
                    name=f"{host_res.manufacturer_hint} Candidate ({ip})",
                    ip_address=ip,
                    mac_address=arp_map.get(ip),
                    open_ports=host_res.open_ports,
                    onvif_supported=(host_res.onvif_http_port is not None),
                    onvif_xaddr=(
                        f"http://{ip}:{host_res.onvif_http_port}/onvif/device_service"
                        if host_res.onvif_http_port
                        else None
                    ),
                    compatibility_tier=CompatibilityTier.TIER_2_DIRECT_STREAM,
                    lifecycle_state=lifecycle,
                    confidence=confidence,
                    manufacturer=host_res.manufacturer_hint,
                    model="RTSP Network Candidate",
                    location="Discovered Scope",
                    rtsp_endpoints=host_res.rtsp_endpoints,
                    primary_rtsp_url=sanitize_uri_template(primary_url),
                    approved=False,
                    latency_ms=host_res.latency_ms,
                    discovered_via=["port_scan"],
                    online=True,
                )
                merged_by_ip[ip] = (
                    cam,
                    None,
                    {"method": "unauthenticated_rtsp_probe", "ports": str(host_res.open_ports)},
                )

        for ssdp_item in ssdp_candidates:
            ip = ssdp_item["ip_address"]
            if ip in merged_by_ip:
                cam, _, _ = merged_by_ip[ip]
                if "ssdp" not in cam.discovered_via:
                    cam.discovered_via.append("ssdp")

        persisted_cameras: List[CameraDevice] = []
        for cam, epr, evidence in merged_by_ip.values():
            saved = self.durable_registry.upsert_discovered_device(
                cam, onvif_uuid=epr, evidence=evidence
            )
            persisted_cameras.append(saved)

        if not persisted_cameras and req.include_simulated_if_empty and self.config.enable_demo_streams:
            persisted_cameras = self.list_cameras(site_id=req.site_id)

        duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
        completed_at = utc_now_iso()

        self.db.execute(
            """
            UPDATE discovery_jobs
            SET status = 'COMPLETED',
                completed_at = ?,
                hosts_checked = ?,
                candidates_found = ?,
                summary_json = ?
            WHERE job_id = ?
            """,
            (
                completed_at,
                len(port_scan_results) + len(onvif_devices),
                len(persisted_cameras),
                json.dumps(
                    {
                        "duration_ms": duration_ms,
                        "onvif_found": len(onvif_devices),
                        "port_scan_found": len(port_scan_results),
                    }
                ),
                scan_id,
            ),
        )
        record_audit_event(
            action="DISCOVERY_JOB_COMPLETED",
            target_type="DISCOVERY_JOB",
            target_id=scan_id,
            actor="discovery-service",
            actor_role="SYSTEM",
            details={
                "site_id": req.site_id,
                "subnets": subnets,
                "candidates_found": len(persisted_cameras),
                "unauthenticated": True,
            },
            db=self.db,
        )

        result = DiscoveryResult(
            scan_id=scan_id,
            site_id=req.site_id,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            subnets_scanned=subnets,
            ports_probed=ports,
            onvif_devices_found=len(onvif_devices),
            port_scan_hosts_found=len(port_scan_results),
            unauthenticated_scan=True,
            cameras=persisted_cameras,
        )
        with self._lock:
            self._last_scan_result = result
        return result


config = get_config()
registry = CameraDiscoveryRegistry(config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting Scoped Camera Discovery Microservice on %s:%d",
        config.discovery_host,
        config.discovery_port,
    )
    yield
    logger.info("Shutting down Camera Discovery Microservice")


app = FastAPI(
    title="CCTV-Streamer Camera Discovery Service",
    description="Scoped, Non-Authenticating ONVIF WS-Discovery & RTSP Candidate Discovery Service",
    version="1.1.0",
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
            "registered_devices": len(registry.list_cameras()),
            "configured_subnets": config.discovery_subnets,
            "unauthenticated_discovery_enforced": True,
        },
    )


@app.get("/api/v1/cameras", response_model=List[CameraDevice])
async def list_discovered_cameras(
    online_only: bool = Query(default=False),
    approved_only: bool = Query(default=False),
    _: bool = Depends(verify_api_key),
) -> List[CameraDevice]:
    cameras = registry.list_cameras(approved_only=approved_only)
    if online_only:
        cameras = [c for c in cameras if c.online]
    return cameras


@app.get("/api/v1/discovery/candidates", response_model=List[CameraDevice])
async def list_discovery_candidates(
    site_id: Optional[str] = Query(default=None),
    _: bool = Depends(verify_api_key),
) -> List[CameraDevice]:
    return registry.list_cameras(site_id=site_id, candidates_only=True)


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
@app.post("/api/v1/discovery/jobs", response_model=DiscoveryResult)
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
    """
    Directly probe a single IP within an approved private subnet for open RTSP/ONVIF ports.
    Strictly unauthenticated: registers the device as an unapproved candidate.
    """
    try:
        validate_subnet_cidr(f"{request.ip_address}/32", allow_public=False)
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
        verify_rtsp_endpoint(
            ip_address=request.ip_address,
            port=port,
            path="/Streaming/Channels/101",
            username=None,
            password=None,
            timeout_sec=request.timeout_sec,
        )
        endpoints.append(
            RTSPEndpoint(
                url=f"rtsp://{request.ip_address}:{port}/Streaming/Channels/101",
                transport="tcp",
                port=port,
                path="/Streaming/Channels/101",
                verified=False,
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

    device = CameraDevice(
        camera_id=f"dev-{uuid.uuid4().hex[:12]}",
        site_id=request.site_id,
        name=f"Probed Candidate ({request.ip_address})",
        ip_address=request.ip_address,
        open_ports=open_ports,
        onvif_supported=any(p in (80, 8000, 8080, 8899) for p in open_ports),
        compatibility_tier=CompatibilityTier.TIER_2_DIRECT_STREAM,
        lifecycle_state=DeviceLifecycleState.CAMERA_CANDIDATE,
        primary_rtsp_url=endpoints[0].url,
        rtsp_endpoints=endpoints,
        approved=False,
        latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        discovered_via=["direct_probe"],
        online=bool(open_ports),
    )
    return registry.upsert_camera(device)
