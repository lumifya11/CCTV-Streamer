"""Shared enterprise utilities, configuration, security, and schemas for CCTV-Streamer."""

from shared.config import AppConfig, get_config
from shared.logger import get_logger
from shared.models import (
    AnalyticsEvent,
    CameraDevice,
    DiscoveryRequest,
    DiscoveryResult,
    EventSeverity,
    EventType,
    HealthStatus,
    RTSPEndpoint,
    StreamMetrics,
    StreamRegistrationRequest,
    StreamState,
)
from shared.security import mask_rtsp_credentials, verify_api_key, validate_subnet_cidr

__all__ = [
    "AppConfig",
    "get_config",
    "get_logger",
    "AnalyticsEvent",
    "CameraDevice",
    "DiscoveryRequest",
    "DiscoveryResult",
    "EventSeverity",
    "EventType",
    "HealthStatus",
    "RTSPEndpoint",
    "StreamMetrics",
    "StreamRegistrationRequest",
    "StreamState",
    "mask_rtsp_credentials",
    "verify_api_key",
    "validate_subnet_cidr",
]
