"""Shared Pydantic schemas and domain models across CCTV-Streamer microservices."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UserRole(str, Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


class CompatibilityTier(str, Enum):
    TIER_1_STANDARDS = "TIER_1_STANDARDS"       # ONVIF Profile T / Legacy Profile S + RTSP
    TIER_2_DIRECT_STREAM = "TIER_2_DIRECT_STREAM"  # User-supplied authenticated RTSP/MJPEG/HLS
    TIER_3_VENDOR_ADAPTER = "TIER_3_VENDOR_ADAPTER"  # Documented vendor/NVR/IoT plugin
    TIER_4_UNSUPPORTED = "TIER_4_UNSUPPORTED"   # Proprietary cloud-locked/encrypted device


class DeviceLifecycleState(str, Enum):
    DISCOVERED_HOST = "DISCOVERED_HOST"
    SERVICE_DETECTED = "SERVICE_DETECTED"
    CAMERA_CANDIDATE = "CAMERA_CANDIDATE"
    USER_APPROVED = "USER_APPROVED"
    CREDENTIALS_CONFIGURED = "CREDENTIALS_CONFIGURED"
    CONNECTION_VERIFIED = "CONNECTION_VERIFIED"
    STREAM_VERIFIED = "STREAM_VERIFIED"
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    REJECTED = "REJECTED"


class StreamState(str, Enum):
    UNCONFIGURED = "UNCONFIGURED"
    CONFIGURED = "CONFIGURED"
    IDLE = "IDLE"
    CONNECTING = "CONNECTING"
    STREAMING = "STREAMING"
    RECONNECTING = "RECONNECTING"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"


class DeliveryProtocol(str, Enum):
    WEBRTC = "WebRTC"
    HLS = "HLS"
    RTSP = "RTSP"
    MJPEG_FALLBACK = "MJPEG"


class RecordingMode(str, Enum):
    CONTINUOUS = "CONTINUOUS"
    SCHEDULED = "SCHEDULED"
    MOTION_TRIGGERED = "MOTION_TRIGGERED"
    MANUAL = "MANUAL"


class EventType(str, Enum):
    MOTION_DETECTED = "MOTION_DETECTED"
    TAMPER_OBSTRUCTION = "TAMPER_OBSTRUCTION"
    SCENE_CHANGE = "SCENE_CHANGE"
    SIGNAL_LOSS = "SIGNAL_LOSS"
    STREAM_RECOVERED = "STREAM_RECOVERED"
    CAMERA_DISCOVERED = "CAMERA_DISCOVERED"
    OBJECT_DETECTED = "OBJECT_DETECTED"
    IOT_TELEMETRY = "IOT_TELEMETRY"


class EventSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class RTSPEndpoint(BaseModel):
    url: str = Field(..., description="Masked or sanitized RTSP endpoint URI template")
    transport: str = Field(default="tcp", description="RTSP transport protocol (tcp/udp)")
    port: int = Field(default=554)
    path: str = Field(default="/")
    profile_token: Optional[str] = None
    onvif_profile: Optional[str] = "Profile_T"
    resolution: Optional[str] = "1280x720"
    codec: Optional[str] = "H.264"
    verified: bool = False


class CameraDevice(BaseModel):
    camera_id: str = Field(..., description="Immutable UUID or deterministic device ID")
    site_id: str = Field(default="site-default", description="Associated site identifier")
    scope_id: Optional[str] = None
    name: str = Field(..., description="Human-readable camera label")
    ip_address: str = Field(..., description="Current IPv4 address of the camera")
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    onvif_supported: bool = False
    onvif_xaddr: Optional[str] = None
    onvif_profiles: List[str] = Field(default_factory=list)
    legacy_profile_s: bool = False
    compatibility_tier: CompatibilityTier = CompatibilityTier.TIER_1_STANDARDS
    lifecycle_state: DeviceLifecycleState = DeviceLifecycleState.CAMERA_CANDIDATE
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    manufacturer: str = "Generic"
    model: str = "IP Camera"
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: str = "Sector A"
    rtsp_endpoints: List[RTSPEndpoint] = Field(default_factory=list)
    primary_rtsp_url: Optional[str] = None
    credential_profile_id: Optional[str] = None
    approved: bool = False
    approved_by: Optional[str] = None
    latency_ms: float = 0.0
    discovered_via: List[str] = Field(default_factory=list)
    last_seen: str = Field(default_factory=utc_now_iso)
    online: bool = True


class DiscoveryRequest(BaseModel):
    site_id: str = Field(default="site-default")
    scope_id: Optional[str] = Field(default=None)
    subnets: Optional[List[str]] = Field(
        default=None,
        description="Approved IPv4 CIDRs or single IPs to scan within the site scope",
    )
    ports: Optional[List[int]] = Field(
        default=None,
        description="TCP ports to probe for RTSP/ONVIF service presence (unauthenticated)",
    )
    enable_onvif_multicast: bool = True
    enable_port_scan: bool = True
    enable_mdns: bool = False
    enable_ssdp: bool = False
    verify_rtsp_endpoints: bool = True
    include_simulated_if_empty: bool = False
    timeout_sec: float = Field(default=1.0, ge=0.2, le=10.0)


class DiscoveryResult(BaseModel):
    scan_id: str
    site_id: str = "site-default"
    started_at: str
    completed_at: str
    duration_ms: float
    subnets_scanned: List[str]
    ports_probed: List[int]
    onvif_devices_found: int
    port_scan_hosts_found: int
    unauthenticated_scan: bool = True
    cameras: List[CameraDevice]


class StreamRegistrationRequest(BaseModel):
    camera_id: str
    name: str
    rtsp_url: str
    location: str = "Main Facility"
    site_id: str = "site-default"
    credential_profile_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    target_fps: int = Field(default=20, ge=1, le=60)
    width: int = Field(default=1280, ge=160, le=3840)
    height: int = Field(default=720, ge=120, le=2160)
    jpeg_quality: int = Field(default=80, ge=10, le=100)
    preferred_delivery: DeliveryProtocol = DeliveryProtocol.WEBRTC
    enable_analytics: bool = True
    require_approval: bool = False


class StreamMetrics(BaseModel):
    camera_id: str
    name: str
    location: str = "Main Facility"
    rtsp_url_masked: str
    state: StreamState
    delivery_protocol: DeliveryProtocol = DeliveryProtocol.MJPEG_FALLBACK
    mediamtx_path: Optional[str] = None
    webrtc_url: Optional[str] = None
    hls_url: Optional[str] = None
    fps_actual: float = 0.0
    fps_target: int = 20
    frame_width: int = 1280
    frame_height: int = 720
    codec: str = "H.264"
    frames_ingested: int = 0
    frames_dropped: int = 0
    reconnect_attempts: int = 0
    total_reconnections: int = 0
    first_frame_timestamp: Optional[str] = None
    last_frame_timestamp: Optional[str] = None
    last_error: Optional[str] = None
    uptime_seconds: float = 0.0
    latency_ms: float = 0.0
    bitrate_kbps: float = 0.0
    motion_active: bool = False
    motion_score: float = 0.0


class AnalyticsEvent(BaseModel):
    event_id: str
    camera_id: str
    site_id: str = "site-default"
    camera_name: str
    event_type: EventType
    severity: EventSeverity
    timestamp: str = Field(default_factory=utc_now_iso)
    score: float = 0.0
    zone_name: str = "full_frame"
    description: str
    snapshot_ref: Optional[str] = None
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    bounding_boxes: List[Dict[str, int]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HealthStatus(BaseModel):
    service: str
    status: str = "healthy"
    version: str = "1.1.0"
    uptime_seconds: float
    timestamp: str = Field(default_factory=utc_now_iso)
    details: Dict[str, Any] = Field(default_factory=dict)
