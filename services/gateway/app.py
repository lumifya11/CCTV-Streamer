"""Unified Enterprise API Gateway, Auth/RBAC, Mobile Pairing & Control Room Orchestrator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from services.device_manager.enrollment import DeviceEnrollmentService
from services.device_manager.registry import DurableDeviceRegistry
from services.discovery.app import (
    DirectCameraProbeRequest,
    registry as local_discovery_registry,
)
from services.integrations.plugin_manager import PluginManager
from services.processor.app import (
    CameraConfigUpdateRequest,
    analytics_engine as local_analytics_engine,
)
from services.recording.coordinator import (
    RecordingCoordinator,
    calculate_storage_estimate,
)
from services.site_agent.app import SiteAgentManager
from services.transcoder.app import (
    _mjpeg_stream_generator,
    _seed_demo_streams_if_enabled,
    mediamtx_client as local_mediamtx_client,
    stream_manager as local_stream_manager,
)
from shared.audit import list_audit_events, record_audit_event
from shared.auth import (
    authenticate_user,
    bootstrap_owner_account,
    create_signed_token,
    issue_media_ticket,
    verify_media_ticket,
)
from shared.config import get_config
from shared.database import get_db
from shared.logger import get_logger
from shared.models import (
    AnalyticsEvent,
    CameraDevice,
    DiscoveryRequest,
    DiscoveryResult,
    EventSeverity,
    EventType,
    HealthStatus,
    RecordingMode,
    StreamMetrics,
    StreamRegistrationRequest,
    StreamState,
    utc_now_iso,
)
from shared.security import (
    _authenticate_request_credentials,
    verify_api_key,
    verify_media_access,
)

logger = get_logger("gateway.service")
SERVICE_START_TIME = time.monotonic()
config = get_config()
STATIC_DIR = Path(__file__).parent / "static"


def _is_distributed_mode() -> bool:
    return os.getenv("GATEWAY_MODE", "hybrid").lower() == "distributed"


# --- Request / Response Schemas for Versioned /api/v1/ Contract ---


class BootstrapOwnerRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str
    device_name: str = "web-console"


class RefreshTokenRequest(BaseModel):
    session_id: str
    refresh_token: str


class MobilePairingStartRequest(BaseModel):
    device_label: str = "Android Mobile Client"
    server_url: str = "https://cctv.local:8080"


class MobilePairingCompleteRequest(BaseModel):
    pairing_code: str
    device_label: str = "Flutter Android App"


class MobileStreamTicketRequest(BaseModel):
    camera_id: str
    protocol: str = "WebRTC"
    ttl_sec: int = Field(default=120, ge=15, le=600)


class CreateSiteRequest(BaseModel):
    name: str
    description: str = ""
    location: str = "Main Facility"


class CreateScopeRequest(BaseModel):
    cidr: str = Field(..., description="Approved private IPv4 CIDR (e.g. 192.168.1.0/24)")
    vlan_label: str = "Camera VLAN"
    allowed_methods: List[str] = Field(
        default_factory=lambda: ["onvif", "rtsp_probe", "mdns", "ssdp"]
    )
    allowed_ports: List[int] = Field(
        default_factory=lambda: [554, 8554, 80, 8000, 8080, 8899]
    )
    max_hosts: int = Field(default=256, ge=1, le=1024)
    rate_limit_per_sec: int = Field(default=64, ge=1, le=256)
    onvif_multicast_enabled: bool = True


class DevicePatchRequest(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None


class DeviceEnrollRequest(BaseModel):
    protocol: str = "ONVIF"
    username: Optional[str] = None
    password: Optional[str] = None
    credential_profile_id: Optional[str] = None
    rtsp_url: Optional[str] = None
    onvif_profile_preference: str = "Profile_T"
    perform_live_test: bool = False


class DeviceTestConnectionRequest(BaseModel):
    credential_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class CreateRecordingSegmentRequest(BaseModel):
    device_id: str
    stream_id: Optional[str] = None
    duration_sec: float = Field(default=60.0, ge=1.0, le=3600.0)
    mode: RecordingMode = RecordingMode.MANUAL
    codec: str = "H.264"
    resolution: str = "1280x720"


class StorageEstimateRequest(BaseModel):
    bitrate_mbps: float = Field(default=2.5, ge=0.1, le=100.0)
    camera_count: int = Field(default=4, ge=1, le=1000)
    hours_per_day: float = Field(default=24.0, ge=0.5, le=24.0)
    retention_days: int = Field(default=14, ge=1, le=365)


class RegisterSiteAgentRequest(BaseModel):
    site_id: str = "site-default"
    name: str
    cert_fingerprint: Optional[str] = None


class MediaMTXAuthCallbackRequest(BaseModel):
    user: Optional[str] = None
    password: Optional[str] = None
    ip: Optional[str] = None
    action: str = "read"
    path: str = ""
    protocol: str = "webrtc"
    id: Optional[str] = None
    query: str = ""


async def _local_analytics_worker(stop_event: asyncio.Event) -> None:
    """In-process OpenCV analytics loop when running in hybrid/unified mode."""
    while not stop_event.is_set():
        try:
            for metrics in local_stream_manager.list_metrics():
                if metrics.state != StreamState.STREAMING:
                    continue
                worker = local_stream_manager.get_worker(metrics.camera_id)
                if worker is None:
                    continue
                frame = worker.get_latest_raw_frame()
                if frame is not None:
                    output = local_analytics_engine.process_frame(
                        camera_id=metrics.camera_id,
                        frame=frame,
                        camera_name=metrics.name,
                    )
                    worker.update_analytics_status(
                        output.motion_detected, output.motion_score
                    )
        except Exception as exc:
            logger.debug("Local analytics cycle error: %s", exc)

        try:
            await asyncio.wait_for(
                stop_event.wait(), timeout=config.processor_sample_interval_sec
            )
        except asyncio.TimeoutError:
            continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting CCTV-Streamer Enterprise Gateway on %s:%d (mode=%s)",
        config.gateway_host,
        config.gateway_port,
        os.getenv("GATEWAY_MODE", "hybrid"),
    )
    stop_event = asyncio.Event()
    local_task: Optional[asyncio.Task] = None
    if not _is_distributed_mode():
        _seed_demo_streams_if_enabled()
        local_task = asyncio.create_task(_local_analytics_worker(stop_event))
    yield
    stop_event.set()
    if local_task:
        local_task.cancel()
        try:
            await local_task
        except asyncio.CancelledError:
            pass
    local_stream_manager.stop_all()
    logger.info("Shutting down CCTV-Streamer Enterprise Gateway")


app = FastAPI(
    title="CCTV-Streamer Enterprise API Gateway",
    description="Unified Microservices Orchestrator, Auth/RBAC, Mobile API & SOC Operations Console",
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

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_console() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", response_model=HealthStatus)
@app.get("/api/v1/system/health", response_model=HealthStatus)
async def gateway_health() -> HealthStatus:
    services_status: Dict[str, Any] = {}
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=1.5) as client:
            for svc_name, base_url in (
                ("discovery", config.discovery_service_url),
                ("transcoder", config.transcoder_service_url),
                ("processor", config.processor_service_url),
            ):
                try:
                    resp = await client.get(f"{base_url}/health")
                    services_status[svc_name] = (
                        resp.json() if resp.status_code == 200 else {"status": "degraded"}
                    )
                except Exception as exc:
                    services_status[svc_name] = {"status": "unreachable", "error": str(exc)}
    else:
        streams = local_stream_manager.list_metrics()
        proc_summary = local_analytics_engine.get_metrics_summary()
        services_status = {
            "discovery": {
                "status": "healthy",
                "registered_cameras": len(local_discovery_registry.list_cameras()),
            },
            "transcoder": {
                "status": "healthy",
                "total_streams": len(streams),
                "streaming_active": sum(1 for s in streams if s.state == StreamState.STREAMING),
            },
            "processor": {
                "status": "healthy",
                "total_frames_processed": proc_summary["total_frames_processed"],
                "total_motion_events": proc_summary["total_motion_events"],
            },
        }

    return HealthStatus(
        service="gateway",
        status="healthy",
        uptime_seconds=round(time.monotonic() - SERVICE_START_TIME, 2),
        details={
            "microservices": services_status,
            "deployment_profile": get_config().deployment_profile,
        },
    )


# =============================================================================
# 1. Authentication, Sessions & Mobile Pairing (/api/v1/auth, /api/v1/mobile)
# =============================================================================


@app.post("/api/v1/auth/bootstrap", status_code=status.HTTP_201_CREATED)
async def auth_bootstrap(request: BootstrapOwnerRequest) -> Dict[str, Any]:
    try:
        return bootstrap_owner_account(
            username=request.username,
            password=request.password,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/auth/login")
async def auth_login(request: LoginRequest) -> Dict[str, Any]:
    result, err = authenticate_user(
        username=request.username,
        password=request.password,
        device_name=request.device_name,
    )
    if err or not result:
        code = (
            status.HTTP_429_TOO_MANY_REQUESTS
            if err and "Too many" in err
            else status.HTTP_401_UNAUTHORIZED
        )
        raise HTTPException(status_code=code, detail=err or "Authentication failed.")
    return result


@app.post("/api/v1/auth/refresh")
async def auth_refresh(request: RefreshTokenRequest) -> Dict[str, Any]:
    db = get_db()
    refresh_hash = hashlib.sha256(request.refresh_token.encode("utf-8")).hexdigest()
    session = db.fetchone(
        "SELECT * FROM sessions WHERE session_id = ? AND refresh_token_hash = ? AND revoked = 0",
        (request.session_id, refresh_hash),
    )
    if not session or float(session["expires_at"]) < time.time():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked refresh token.",
        )
    user = db.fetchone(
        "SELECT * FROM users WHERE user_id = ? AND status = 'ACTIVE'",
        (session["user_id"],),
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is no longer active.",
        )
    new_refresh = secrets.token_urlsafe(32)
    new_hash = hashlib.sha256(new_refresh.encode("utf-8")).hexdigest()
    db.execute(
        "UPDATE sessions SET refresh_token_hash = ? WHERE session_id = ?",
        (new_hash, request.session_id),
    )
    access_token = create_signed_token(
        {
            "sub": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "session_id": request.session_id,
            "token_type": "access",
        },
        ttl_sec=900,
    )
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": 900,
    }


@app.post("/api/v1/auth/logout")
async def auth_logout(
    session_id: Optional[str] = Query(default=None),
    _: bool = Depends(verify_api_key),
) -> Dict[str, str]:
    if session_id:
        get_db().execute(
            "UPDATE sessions SET revoked = 1 WHERE session_id = ?", (session_id,)
        )
    return {"status": "logged_out"}


@app.get("/api/v1/auth/me")
async def auth_me(
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, Any]:
    return {
        "user_id": auth_ctx.get("sub", "operator"),
        "username": auth_ctx.get("username", auth_ctx.get("sub", "operator")),
        "role": auth_ctx.get("role", "OWNER"),
        "auth_method": auth_ctx.get("auth_method", "bearer"),
    }


@app.post("/api/v1/mobile/pairing/start")
async def mobile_pairing_start(
    request: MobilePairingStartRequest,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, Any]:
    db = get_db()
    pairing_code = f"PAIR-{secrets.token_hex(4).upper()}"
    expires_at = time.time() + 300.0
    user_id = auth_ctx.get("sub", "owner")
    db.execute(
        """
        INSERT INTO mobile_pairings (pairing_code, user_id, device_label, server_url, expires_at, completed)
        VALUES (?, ?, ?, ?, ?, 0)
        """,
        (pairing_code, user_id, request.device_label, request.server_url, expires_at),
    )
    record_audit_event(
        action="MOBILE_PAIRING_STARTED",
        target_type="MOBILE_PAIRING",
        target_id=pairing_code,
        actor=user_id,
        actor_role=auth_ctx.get("role", "OWNER"),
        db=db,
    )
    return {
        "pairing_code": pairing_code,
        "server_url": request.server_url,
        "expires_in_sec": 300,
        "qr_payload": json.dumps(
            {"server_url": request.server_url, "pairing_code": pairing_code}
        ),
    }


@app.post("/api/v1/mobile/pairing/complete")
async def mobile_pairing_complete(
    request: MobilePairingCompleteRequest,
) -> Dict[str, Any]:
    db = get_db()
    row = db.fetchone(
        "SELECT * FROM mobile_pairings WHERE pairing_code = ? AND completed = 0",
        (request.pairing_code.strip(),),
    )
    if not row or float(row["expires_at"]) < time.time():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already used mobile pairing code.",
        )
    db.execute(
        "UPDATE mobile_pairings SET completed = 1 WHERE pairing_code = ?",
        (request.pairing_code.strip(),),
    )
    session_id = f"ses-mob-{uuid.uuid4().hex[:12]}"
    refresh_token = secrets.token_urlsafe(32)
    refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
    db.execute(
        """
        INSERT INTO sessions (session_id, user_id, refresh_token_hash, device_name, expires_at, revoked, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
        """,
        (
            session_id,
            row["user_id"],
            refresh_hash,
            request.device_label,
            time.time() + 86400 * 14,
            utc_now_iso(),
        ),
    )
    access_token = create_signed_token(
        {
            "sub": row["user_id"],
            "role": "OPERATOR",
            "session_id": session_id,
            "device": request.device_label,
        },
        ttl_sec=900,
    )
    record_audit_event(
        action="MOBILE_PAIRING_COMPLETED",
        target_type="SESSION",
        target_id=session_id,
        actor=row["user_id"],
        actor_role="OPERATOR",
        details={"device_label": request.device_label},
        db=db,
    )
    return {
        "session_id": session_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "server_url": row["server_url"],
    }


@app.post("/api/v1/mobile/stream-ticket")
async def mobile_create_stream_ticket(
    request: MobileStreamTicketRequest,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, Any]:
    return local_mediamtx_client.build_playback_bundle(
        camera_id=request.camera_id,
        user_id=auth_ctx.get("sub", "mobile-operator"),
        role=auth_ctx.get("role", "OPERATOR"),
        ttl_sec=request.ttl_sec,
    )


# =============================================================================
# 2. Sites, Approved Network Scopes & Discovery (/api/v1/sites, /api/v1/discovery)
# =============================================================================


@app.get("/api/v1/sites")
async def list_sites(_: bool = Depends(verify_api_key)) -> List[Dict[str, Any]]:
    return DurableDeviceRegistry().list_sites()


@app.post("/api/v1/sites", status_code=status.HTTP_201_CREATED)
async def create_site(
    request: CreateSiteRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    return DurableDeviceRegistry().create_site(
        name=request.name,
        description=request.description,
        location=request.location,
    )


@app.get("/api/v1/sites/{site_id}/scopes")
async def list_site_scopes(
    site_id: str,
    _: bool = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    return DurableDeviceRegistry().list_scopes(site_id=site_id)


@app.post("/api/v1/sites/{site_id}/scopes", status_code=status.HTTP_201_CREATED)
async def create_site_scope(
    site_id: str,
    request: CreateScopeRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    try:
        return DurableDeviceRegistry().create_scope(
            site_id=site_id,
            cidr=request.cidr,
            vlan_label=request.vlan_label,
            allowed_methods=request.allowed_methods,
            allowed_ports=request.allowed_ports,
            max_hosts=request.max_hosts,
            rate_limit_per_sec=request.rate_limit_per_sec,
            onvif_multicast_enabled=request.onvif_multicast_enabled,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@app.post("/api/v1/discover", response_model=DiscoveryResult)
@app.post("/api/v1/discovery/jobs", response_model=DiscoveryResult)
async def trigger_discovery(
    request: DiscoveryRequest = DiscoveryRequest(),
    _: bool = Depends(verify_api_key),
) -> DiscoveryResult:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{config.discovery_service_url}/api/v1/discover",
                json=request.model_dump(),
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return DiscoveryResult(**resp.json())
    try:
        return local_discovery_registry.execute_discovery(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@app.get("/api/v1/discovery/jobs/{job_id}")
async def get_discovery_job(
    job_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    row = get_db().fetchone(
        "SELECT * FROM discovery_jobs WHERE job_id = ?", (job_id,)
    )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Discovery job '{job_id}' not found.",
        )
    row["scope_ids"] = json.loads(row.pop("scope_ids_json", "[]") or "[]")
    row["summary"] = json.loads(row.pop("summary_json", "{}") or "{}")
    return row


@app.get("/api/v1/discovery/candidates", response_model=List[CameraDevice])
async def list_discovery_candidates(
    site_id: Optional[str] = Query(default=None),
    _: bool = Depends(verify_api_key),
) -> List[CameraDevice]:
    return DurableDeviceRegistry().list_devices(
        site_id=site_id, candidates_only=True
    )


@app.post("/api/v1/discovery/candidates/{candidate_id}/approve", response_model=CameraDevice)
async def approve_discovery_candidate(
    candidate_id: str,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    try:
        return DurableDeviceRegistry().approve_candidate(candidate_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@app.post("/api/v1/discovery/candidates/{candidate_id}/reject", response_model=CameraDevice)
async def reject_discovery_candidate(
    candidate_id: str,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    try:
        return DurableDeviceRegistry().reject_candidate(candidate_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


# =============================================================================
# 3. Devices, Enrollment & Cameras (/api/v1/devices, /api/v1/cameras)
# =============================================================================


@app.get("/api/v1/devices", response_model=List[CameraDevice])
@app.get("/api/v1/cameras", response_model=List[CameraDevice])
async def list_cameras(
    site_id: Optional[str] = Query(default=None),
    approved_only: bool = Query(default=False),
    _: bool = Depends(verify_api_key),
) -> List[CameraDevice]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{config.discovery_service_url}/api/v1/cameras")
            resp.raise_for_status()
            return [CameraDevice(**item) for item in resp.json()]
    return local_discovery_registry.list_cameras(
        site_id=site_id, approved_only=approved_only
    )


@app.get("/api/v1/devices/{device_id}")
async def get_device_detail(
    device_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(device_id)
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found.",
        )
    data = dev.model_dump()
    data["address_history"] = reg.get_address_history(device_id)
    return data


@app.patch("/api/v1/devices/{device_id}", response_model=CameraDevice)
async def patch_device(
    device_id: str,
    request: DevicePatchRequest,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(device_id)
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found.",
        )
    if request.name:
        get_db().execute(
            "UPDATE devices SET name = ? WHERE device_id = ?",
            (request.name.strip(), device_id),
        )
    if request.location:
        get_db().execute(
            "UPDATE devices SET location = ? WHERE device_id = ?",
            (request.location.strip(), device_id),
        )
    updated = reg.get_device(device_id)
    assert updated is not None
    return updated


@app.delete("/api/v1/devices/{device_id}")
async def delete_device_endpoint(
    device_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, str]:
    removed = DurableDeviceRegistry().delete_device(device_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found.",
        )
    local_stream_manager.remove_stream(device_id)
    return {"status": "deleted", "device_id": device_id}


@app.post("/api/v1/devices/{device_id}/enroll")
async def enroll_device_endpoint(
    device_id: str,
    request: DeviceEnrollRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    svc = DeviceEnrollmentService()
    try:
        return svc.enroll_device(
            device_id=device_id,
            protocol=request.protocol,
            username=request.username,
            password=request.password,
            credential_profile_id=request.credential_profile_id,
            rtsp_url=request.rtsp_url,
            onvif_profile_preference=request.onvif_profile_preference,
            perform_live_test=request.perform_live_test,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@app.post("/api/v1/devices/{device_id}/test-connection")
async def test_device_connection_endpoint(
    device_id: str,
    request: DeviceTestConnectionRequest = DeviceTestConnectionRequest(),
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    svc = DeviceEnrollmentService()
    try:
        return svc.test_device_connection(
            device_id=device_id,
            credential_id=request.credential_id,
            username=request.username,
            password=request.password,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc


@app.get("/api/v1/cameras/{camera_id}/capabilities")
async def get_camera_capabilities(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(camera_id)
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Camera '{camera_id}' not found.",
        )
    row = get_db().fetchone(
        "SELECT * FROM camera_capabilities WHERE device_id = ?", (camera_id,)
    )
    return {
        "camera_id": camera_id,
        "name": dev.name,
        "compatibility_tier": dev.compatibility_tier.value,
        "onvif_supported": dev.onvif_supported,
        "onvif_profiles": dev.onvif_profiles,
        "legacy_profile_s": dev.legacy_profile_s,
        "legacy_profile_s_deprecation_date": "2027-03-31" if dev.legacy_profile_s else None,
        "ptz_supported": bool(row["ptz_supported"]) if row else ("PTZ" in dev.name.upper()),
        "imaging_supported": bool(row["imaging_supported"]) if row else dev.onvif_supported,
        "edge_storage_profile_g": "Profile_G" in dev.onvif_profiles,
        "analytics_metadata_profile_m": "Profile_M" in dev.onvif_profiles,
    }


@app.get("/api/v1/cameras/{camera_id}/streams")
async def list_camera_streams(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(camera_id)
    if not dev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Camera '{camera_id}' not found.",
        )
    return [ep.model_dump() for ep in dev.rtsp_endpoints]


@app.post("/api/v1/cameras/{camera_id}/streams", response_model=StreamMetrics, status_code=status.HTTP_201_CREATED)
async def start_camera_stream(
    camera_id: str,
    request: StreamRegistrationRequest,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(camera_id)
    if dev is not None and not dev.approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Camera candidate '{camera_id}' must be approved before starting a stream.",
        )
    return await register_stream(request, _=True)


@app.post("/api/v1/cameras/probe", response_model=CameraDevice)
async def probe_camera(
    request: DirectCameraProbeRequest,
    _: bool = Depends(verify_api_key),
) -> CameraDevice:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                f"{config.discovery_service_url}/api/v1/cameras/probe",
                json=request.model_dump(),
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return CameraDevice(**resp.json())
    from services.discovery.app import probe_single_camera

    return await probe_single_camera(request, _=True)


# =============================================================================
# 4. Live Streams, MediaMTX Auth & Recordings (/api/v1/streams, /api/v1/recordings)
# =============================================================================


@app.get("/api/v1/streams", response_model=List[StreamMetrics])
async def list_streams(_: bool = Depends(verify_api_key)) -> List[StreamMetrics]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{config.transcoder_service_url}/api/v1/streams")
            resp.raise_for_status()
            return [StreamMetrics(**item) for item in resp.json()]
    return local_stream_manager.list_metrics()


@app.get("/api/v1/streams/{stream_id}/status", response_model=StreamMetrics)
async def get_stream_status(
    stream_id: str,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    worker = local_stream_manager.get_worker(stream_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{stream_id}' not found.",
        )
    return worker.get_metrics()


@app.post("/api/v1/streams", response_model=StreamMetrics, status_code=status.HTTP_201_CREATED)
async def register_stream(
    request: StreamRegistrationRequest,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    reg = DurableDeviceRegistry()
    dev = reg.get_device(request.camera_id)
    if dev is not None and not dev.approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Camera candidate '{request.camera_id}' has not been approved for streaming.",
        )
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{config.transcoder_service_url}/api/v1/streams",
                json=request.model_dump(),
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return StreamMetrics(**resp.json())
    try:
        metrics = local_stream_manager.register_stream(request)
        local_mediamtx_client.register_camera_path(request.camera_id, request.rtsp_url)
        return metrics
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@app.post("/api/v1/streams/{camera_id}/reconnect", response_model=StreamMetrics)
async def reconnect_stream(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{config.transcoder_service_url}/api/v1/streams/{camera_id}/reconnect"
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return StreamMetrics(**resp.json())
    worker = local_stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{camera_id}' not found.",
        )
    worker.trigger_reconnect()
    return worker.get_metrics()


@app.post("/api/v1/streams/{stream_id}/playback-ticket")
async def get_stream_playback_ticket(
    stream_id: str,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, Any]:
    worker = local_stream_manager.get_worker(stream_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{stream_id}' not found.",
        )
    return local_mediamtx_client.build_playback_bundle(
        camera_id=stream_id,
        user_id=auth_ctx.get("sub", "operator"),
        role=auth_ctx.get("role", "OPERATOR"),
    )


@app.post("/api/v1/streams/mediamtx-auth")
async def mediamtx_http_auth_webhook(
    request: MediaMTXAuthCallbackRequest,
) -> Dict[str, str]:
    """External HTTP auth webhook called by MediaMTX before allowing stream read/publish."""
    camera_id = request.path.split("/")[-1] if "/" in request.path else request.path
    ticket_val = request.password or ""
    if not ticket_val and "ticket=" in request.query:
        for part in request.query.split("&"):
            if part.startswith("ticket="):
                ticket_val = part.split("=", 1)[1]
                break
    verified = verify_media_ticket(ticket_val, required_camera_id=camera_id or None)
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MediaMTX playback ticket invalid or expired.",
        )
    return {"status": "authorized"}


@app.delete("/api/v1/streams/{camera_id}")
async def remove_stream(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, str]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.delete(
                f"{config.transcoder_service_url}/api/v1/streams/{camera_id}"
            )
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=resp.text)
            return resp.json()
    if not local_stream_manager.remove_stream(camera_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{camera_id}' not found.",
        )
    local_mediamtx_client.remove_camera_path(camera_id)
    return {"status": "deleted", "camera_id": camera_id}


@app.get("/api/v1/streams/{camera_id}/snapshot")
async def stream_snapshot(
    camera_id: str,
    _auth: Dict[str, Any] = Depends(verify_media_access),
) -> Response:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"{config.transcoder_service_url}/api/v1/streams/{camera_id}/snapshot"
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail="Snapshot unavailable")
            return Response(
                content=resp.content,
                media_type="image/jpeg",
                headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
            )
    worker = local_stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{camera_id}' not found.",
        )
    jpeg = worker.get_latest_jpeg()
    return Response(
        content=jpeg or b"",
        media_type="image/jpeg",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"},
    )


@app.get("/api/v1/streams/{camera_id}/mjpeg")
async def stream_mjpeg(
    camera_id: str,
    _auth: Dict[str, Any] = Depends(verify_media_access),
) -> StreamingResponse:
    if _is_distributed_mode():
        async def _proxy_mjpeg():
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "GET",
                    f"{config.transcoder_service_url}/api/v1/streams/{camera_id}/mjpeg",
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk

        return StreamingResponse(
            _proxy_mjpeg(),
            media_type="multipart/x-mixed-replace; boundary=frame",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "X-Accel-Buffering": "no",
            },
        )

    worker = local_stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream '{camera_id}' not found.",
        )
    return StreamingResponse(
        _mjpeg_stream_generator(worker),
        media_type="multipart/x-mixed-replace; boundary=frame",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/recordings")
async def list_recordings_endpoint(
    device_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _: bool = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    return RecordingCoordinator().list_recordings(device_id=device_id, limit=limit)


@app.post("/api/v1/recordings", status_code=status.HTTP_201_CREATED)
async def create_recording_segment_endpoint(
    request: CreateRecordingSegmentRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    return RecordingCoordinator().index_segment(
        device_id=request.device_id,
        stream_id=request.stream_id or request.device_id,
        duration_sec=request.duration_sec,
        mode=request.mode,
        codec=request.codec,
        resolution=request.resolution,
    )


@app.get("/api/v1/recordings/{recording_id}")
async def get_recording_endpoint(
    recording_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    rec = RecordingCoordinator().get_recording(recording_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording '{recording_id}' not found.",
        )
    return rec


@app.post("/api/v1/recordings/{recording_id}/export")
async def export_recording_endpoint(
    recording_id: str,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, Any]:
    try:
        return RecordingCoordinator().export_recording(
            recording_id=recording_id,
            actor=auth_ctx.get("sub", "operator"),
            actor_role=auth_ctx.get("role", "OPERATOR"),
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@app.delete("/api/v1/recordings/{recording_id}")
async def delete_recording_endpoint(
    recording_id: str,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> Dict[str, str]:
    try:
        removed = RecordingCoordinator().delete_recording(
            recording_id=recording_id,
            actor=auth_ctx.get("sub", "owner"),
            actor_role=auth_ctx.get("role", "OWNER"),
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Recording '{recording_id}' not found.",
        )
    return {"status": "deleted", "recording_id": recording_id}


# =============================================================================
# 5. Events, Storage, Audit, Site Agents & Plugins
# =============================================================================


@app.get("/api/v1/events", response_model=List[AnalyticsEvent])
async def list_events(
    camera_id: Optional[str] = Query(default=None),
    event_type: Optional[EventType] = Query(default=None),
    severity: Optional[EventSeverity] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _: bool = Depends(verify_api_key),
) -> List[AnalyticsEvent]:
    if _is_distributed_mode():
        params: Dict[str, Any] = {"limit": limit}
        if camera_id:
            params["camera_id"] = camera_id
        if event_type:
            params["event_type"] = event_type.value
        if severity:
            params["severity"] = severity.value
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"{config.processor_service_url}/api/v1/events", params=params
            )
            resp.raise_for_status()
            return [AnalyticsEvent(**item) for item in resp.json()]
    return local_analytics_engine.list_events(
        camera_id=camera_id,
        event_type=event_type,
        severity=severity,
        limit=limit,
    )


@app.post("/api/v1/events/{event_id}/acknowledge", response_model=AnalyticsEvent)
async def acknowledge_event(
    event_id: str,
    auth_ctx: Dict[str, Any] = Depends(verify_media_access),
) -> AnalyticsEvent:
    evt = local_analytics_engine.acknowledge_event(
        event_id, actor=auth_ctx.get("sub", "operator")
    )
    if not evt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found.",
        )
    return evt


@app.get("/api/v1/analytics/metrics")
async def get_analytics_metrics(_: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{config.processor_service_url}/api/v1/metrics")
            resp.raise_for_status()
            return resp.json()
    return local_analytics_engine.get_metrics_summary()


@app.put("/api/v1/analytics/config/{camera_id}")
async def update_analytics_config(
    camera_id: str,
    request: CameraConfigUpdateRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.put(
                f"{config.processor_service_url}/api/v1/config/{camera_id}",
                json=request.model_dump(exclude_none=True),
            )
            resp.raise_for_status()
            return resp.json()
    from services.processor.app import update_camera_analytics_config

    return await update_camera_analytics_config(camera_id, request, _=True)


@app.get("/api/v1/system/storage")
async def get_system_storage(_: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    active_streams = len(local_stream_manager.list_metrics())
    return RecordingCoordinator().get_storage_status(
        active_camera_count=max(1, active_streams)
    )


@app.post("/api/v1/system/storage/estimate")
async def estimate_storage_capacity(
    request: StorageEstimateRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    return calculate_storage_estimate(
        bitrate_mbps=request.bitrate_mbps,
        camera_count=request.camera_count,
        hours_per_day=request.hours_per_day,
        retention_days=request.retention_days,
    )


@app.get("/api/v1/audit")
async def get_audit_trail(
    limit: int = Query(default=100, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    _: bool = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    return list_audit_events(limit=limit, action=action)


@app.get("/api/v1/plugins")
async def list_plugins_endpoint(_: bool = Depends(verify_api_key)) -> List[Dict[str, Any]]:
    return PluginManager().list_plugins()


@app.post("/api/v1/plugins/{plugin_id}/enable")
async def enable_plugin_endpoint(
    plugin_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    try:
        return PluginManager().set_plugin_enabled(plugin_id, enabled=True)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@app.post("/api/v1/plugins/{plugin_id}/disable")
async def disable_plugin_endpoint(
    plugin_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    try:
        return PluginManager().set_plugin_enabled(plugin_id, enabled=False)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc


@app.get("/api/v1/site-agents")
async def list_site_agents(
    site_id: Optional[str] = Query(default=None),
    _: bool = Depends(verify_api_key),
) -> List[Dict[str, Any]]:
    return SiteAgentManager().list_agents(site_id=site_id)


@app.post("/api/v1/site-agents", status_code=status.HTTP_201_CREATED)
async def register_site_agent(
    request: RegisterSiteAgentRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    return SiteAgentManager().register_agent(
        site_id=request.site_id,
        name=request.name,
        cert_fingerprint=request.cert_fingerprint,
    )


@app.get("/api/v1/overview")
async def get_system_overview(_: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    """Aggregate sites, scopes, discovery, active streams, storage, plugins, and recent events."""
    cameras = await list_cameras(site_id=None, approved_only=False, _=True)
    streams = await list_streams(_=True)
    events = await list_events(
        camera_id=None, event_type=None, severity=None, limit=25, _=True
    )
    analytics = await get_analytics_metrics(_=True)
    health = await gateway_health()
    reg = DurableDeviceRegistry()
    sites = reg.list_sites()
    scopes = reg.list_scopes()
    storage = RecordingCoordinator().get_storage_status(
        active_camera_count=max(1, len(streams))
    )
    plugins = PluginManager().list_plugins()

    # Issue a short-lived UI media playback ticket per active stream so browser `<img src>` works securely
    stream_dicts = []
    for s in streams:
        d = s.model_dump() if hasattr(s, "model_dump") else dict(s)
        tkt = issue_media_ticket(camera_id=d["camera_id"], ttl_sec=180)["ticket"]
        d["playback_ticket"] = tkt
        d["mjpeg_ticket_url"] = f"/api/v1/streams/{d['camera_id']}/mjpeg?ticket={tkt}"
        d["snapshot_ticket_url"] = f"/api/v1/streams/{d['camera_id']}/snapshot?ticket={tkt}"
        stream_dicts.append(d)

    return {
        "timestamp": utc_now_iso(),
        "health": health.model_dump(),
        "sites": sites,
        "scopes": scopes,
        "cameras": [c.model_dump() if hasattr(c, "model_dump") else c for c in cameras],
        "streams": stream_dicts,
        "analytics": analytics,
        "events": [e.model_dump() if hasattr(e, "model_dump") else e for e in events],
        "storage": storage,
        "plugins": plugins,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.gateway.app:app",
        host=config.gateway_host,
        port=config.gateway_port,
        reload=False,
    )
