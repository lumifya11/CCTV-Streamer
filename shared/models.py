"""Shared Pydantic schemas and domain models across CCTV-Streamer microservices."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StreamState(str, Enum):
    IDLE = "IDLE"
    CONNECTING = "CONNECTING"
    STREAMING = "STREAMING"
    RECONNECTING = "RECONNECTING"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"


class EventType(str, Enum):
    MOTION_DETECTED = "MOTION_DETECTED"
    TAMPER_OBSTRUCTION = "TAMPER_OBSTRUCTION"
    SIGNAL_LOSS = "SIGNAL_LOSS"
    STREAM_RECOVERED = "STREAM_RECOVERED"
    CAMERA_DISCOVERED = "CAMERA_DISCOVERED"
    OBJECT_DETECTED = "OBJECT_DETECTED"


class EventSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class RTSPEndpoint(BaseModel):
    url: str = Field(..., description="Masked or usable RTSP endpoint URI")
    transport: str = Field(default="tcp", description="RTSP transport protocol (tcp/udp)")
    port: int = Field(default=554)
    path: str = Field(default="/")
    profile_token: Optional[str] = None
    resolution: Optional[str] = "1280x720"
    codec: Optional[str] = "H.264"
    verified: bool = False


class CameraDevice(BaseModel):
    camera_id: str = Field(..., description="Unique deterministic camera identifier")
    name: str = Field(..., description="Human-readable camera label")
    ip_address: str = Field(..., description="IPv4 address of the camera")
    open_ports: List[int] = Field(default_factory=list)
    onvif_supported: bool = False
    onvif_xaddr: Optional[str] = None
    manufacturer: str = "Generic"
    model: str = "IP Camera"
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: str = "Sector A"
    rtsp_endpoints: List[RTSPEndpoint] = Field(default_factory=list)
    primary_rtsp_url: Optional[str] = None
    latency_ms: float = 0.0
    discovered_via: List[str] = Field(default_factory=list)
    last_seen: str = Field(default_factory=utc_now_iso)
    online: bool = True


class DiscoveryRequest(BaseModel):
    subnets: Optional[List[str]] = Field(
        default=None,
        description="Optional list of IPv4 CIDRs or single IPs to scan",
    )
    ports: Optional[List[int]] = Field(
        default=None,
        description="Optional TCP ports to probe for RTSP/ONVIF services",
    )
    enable_onvif_multicast: bool = True
    enable_port_scan: bool = True
    verify_rtsp_endpoints: bool = True
    include_simulated_if_empty: bool = False
    timeout_sec: float = Field(default=1.2, ge=0.2, le=10.0)


class DiscoveryResult(BaseModel):
    scan_id: str
    started_at: str
    completed_at: str
    duration_ms: float
    subnets_scanned: List[str]
    ports_probed: List[int]
    onvif_devices_found: int
    port_scan_hosts_found: int
    cameras: List[CameraDevice]


class StreamRegistrationRequest(BaseModel):
    camera_id: str
    name: str
    rtsp_url: str
    location: str = "Main Facility"
    username: Optional[str] = None
    password: Optional[str] = None
    target_fps: int = Field(default=20, ge=1, le=60)
    width: int = Field(default=1280, ge=160, le=3840)
    height: int = Field(default=720, ge=120, le=2160)
    jpeg_quality: int = Field(default=80, ge=10, le=100)
    enable_analytics: bool = True


class StreamMetrics(BaseModel):
    camera_id: str
    name: str
    location: str = "Main Facility"
    rtsp_url_masked: str
    state: StreamState
    fps_actual: float = 0.0
    fps_target: int = 20
    frame_width: int = 1280
    frame_height: int = 720
    frames_ingested: int = 0
    frames_dropped: int = 0
    reconnect_attempts: int = 0
    total_reconnections: int = 0
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
    camera_name: str
    event_type: EventType
    severity: EventSeverity
    timestamp: str = Field(default_factory=utc_now_iso)
    score: float = 0.0
    description: str
    bounding_boxes: List[Dict[str, int]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HealthStatus(BaseModel):
    service: str
    status: str = "healthy"
    version: str = "1.0.0"
    uptime_seconds: float
    timestamp: str = Field(default_factory=utc_now_iso)
    details: Dict[str, Any] = Field(default_factory=dict)
