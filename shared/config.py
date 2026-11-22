"""Centralized environment-driven configuration management for CCTV-Streamer microservices."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


def _load_dotenv_if_present(env_path: str = ".env") -> None:
    """Lightweight .env file loader without external hard dependencies."""
    path = Path(env_path)
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def _parse_int_list(raw: str, default: List[int]) -> List[int]:
    if not raw.strip():
        return list(default)
    result: List[int] = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            result.append(int(item))
    return result or list(default)


def _parse_str_list(raw: str, default: List[str]) -> List[str]:
    if not raw.strip():
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def is_placeholder_secret(secret: str) -> bool:
    """Return True if a secret is empty or uses an insecure placeholder prefix."""
    clean = (secret or "").strip()
    if not clean or len(clean) < 16:
        return True
    lower = clean.lower()
    return (
        lower.startswith("change-me")
        or lower.startswith("placeholder")
        or lower in ("secret", "password", "admin", "default")
    )


@dataclass(frozen=True)
class AppConfig:
    """Immutable runtime configuration populated from environment variables."""

    # Global, Deployment Profile & Security
    environment: str = "development"
    deployment_profile: str = "personal_lan"
    log_level: str = "INFO"
    log_format: str = "json"
    api_secret_key: str = ""
    vault_master_key: str = ""
    internal_service_token: str = ""
    allowed_origins: List[str] = field(default_factory=lambda: ["http://localhost:8080"])
    allow_private_networks: bool = True
    allow_loopback_in_tests: bool = True
    fail_closed_auth: bool = True

    # Storage & Database
    database_url: str = "sqlite:///data/cctv_streamer.db"
    recordings_dir: str = "recordings"
    storage_budget_gb: float = 500.0
    default_retention_days: int = 14

    # Discovery Microservice
    discovery_host: str = "0.0.0.0"
    discovery_port: int = 8001
    discovery_subnets: List[str] = field(default_factory=lambda: ["192.168.1.0/24"])
    discovery_ports: List[int] = field(
        default_factory=lambda: [554, 8554, 80, 8000, 8080, 8899]
    )
    discovery_scan_interval_sec: int = 300
    discovery_socket_timeout_sec: float = 1.0
    discovery_max_workers: int = 64
    onvif_multicast_host: str = "239.255.255.250"
    onvif_multicast_port: int = 3702
    onvif_discovery_timeout_sec: float = 2.0

    # Legacy env vars (never used during unauthenticated discovery; only for explicit CLI/test helpers)
    onvif_username: str = ""
    onvif_password: str = ""
    rtsp_default_username: str = ""
    rtsp_default_password: str = ""

    # Transcoder & MediaMTX Media Plane
    transcoder_host: str = "0.0.0.0"
    transcoder_port: int = 8002
    mediamtx_api_url: str = "http://mediamtx:9997"
    mediamtx_webrtc_url: str = "http://localhost:8889"
    mediamtx_hls_url: str = "http://localhost:8888"
    mediamtx_rtsp_url: str = "rtsp://localhost:8554"
    rtsp_transport: str = "tcp"
    stream_target_fps: int = 20
    stream_jpeg_quality: int = 80
    stream_frame_width: int = 1280
    stream_frame_height: int = 720
    stream_buffer_size: int = 2
    stream_read_timeout_sec: float = 8.0
    stream_reconnect_base_delay_sec: float = 1.0
    stream_reconnect_max_delay_sec: float = 30.0
    stream_reconnect_max_attempts: int = 0
    enable_demo_streams: bool = False

    # Processor Microservice
    processor_host: str = "0.0.0.0"
    processor_port: int = 8003
    processor_sample_interval_sec: float = 0.5
    motion_sensitivity_threshold: float = 500.0
    motion_min_contour_area: int = 450
    tamper_darkness_threshold: float = 18.0
    tamper_variance_threshold: float = 5.0
    event_cooldown_sec: float = 5.0
    max_stored_events: int = 1000

    # Gateway & Service Discovery URLs
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8080
    discovery_service_url: str = "http://localhost:8001"
    transcoder_service_url: str = "http://localhost:8002"
    processor_service_url: str = "http://localhost:8003"
    redis_url: str = "redis://localhost:6379/0"

    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def validate_production_readiness(self) -> List[str]:
        """Return a list of configuration security violations for production mode."""
        violations: List[str] = []
        if self.is_production():
            if is_placeholder_secret(self.api_secret_key):
                violations.append(
                    "API_SECRET_KEY must be set to a strong non-placeholder secret in production."
                )
            if is_placeholder_secret(self.vault_master_key):
                violations.append(
                    "VAULT_MASTER_KEY must be set to a strong non-placeholder key in production."
                )
            if self.enable_demo_streams and self.deployment_profile != "demo":
                violations.append(
                    "ENABLE_DEMO_STREAMS cannot be enabled in production unless DEPLOYMENT_PROFILE=demo."
                )
        return violations


def get_config(env_file: str = ".env") -> AppConfig:
    """Load configuration from environment variables (with .env fallback)."""
    _load_dotenv_if_present(env_file)

    environment = os.getenv("ENVIRONMENT", "development").strip().lower()
    deployment_profile = os.getenv("DEPLOYMENT_PROFILE", "personal_lan").strip().lower()

    # Demo streams are opt-in and forcibly disabled in production unless DEPLOYMENT_PROFILE=demo
    raw_demo = os.getenv("ENABLE_DEMO_STREAMS", "")
    if environment == "production" and deployment_profile != "demo":
        enable_demo_streams = False
    elif raw_demo:
        enable_demo_streams = raw_demo.lower() in ("1", "true", "yes")
    else:
        enable_demo_streams = environment in ("development", "test", "demo")

    return AppConfig(
        environment=environment,
        deployment_profile=deployment_profile,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        log_format=os.getenv("LOG_FORMAT", "json").lower(),
        api_secret_key=os.getenv("API_SECRET_KEY", ""),
        vault_master_key=os.getenv("VAULT_MASTER_KEY", ""),
        internal_service_token=os.getenv("INTERNAL_SERVICE_TOKEN", ""),
        allowed_origins=_parse_str_list(
            os.getenv("ALLOWED_ORIGINS", ""),
            ["http://localhost:8080", "http://127.0.0.1:8080"],
        ),
        allow_private_networks=os.getenv("ALLOW_PRIVATE_NETWORKS", "true").lower()
        in ("1", "true", "yes"),
        allow_loopback_in_tests=os.getenv("ALLOW_LOOPBACK_IN_TESTS", "true").lower()
        in ("1", "true", "yes"),
        fail_closed_auth=os.getenv(
            "FAIL_CLOSED_AUTH",
            "true" if environment == "production" else "false",
        ).lower()
        in ("1", "true", "yes"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///data/cctv_streamer.db"),
        recordings_dir=os.getenv("RECORDINGS_DIR", "recordings"),
        storage_budget_gb=float(os.getenv("STORAGE_BUDGET_GB", "500.0")),
        default_retention_days=int(os.getenv("DEFAULT_RETENTION_DAYS", "14")),
        discovery_host=os.getenv("DISCOVERY_HOST", "0.0.0.0"),
        discovery_port=int(os.getenv("DISCOVERY_PORT", "8001")),
        discovery_subnets=_parse_str_list(
            os.getenv("DISCOVERY_SUBNETS", ""), ["192.168.1.0/24"]
        ),
        discovery_ports=_parse_int_list(
            os.getenv("DISCOVERY_PORTS", ""), [554, 8554, 80, 8000, 8080, 8899]
        ),
        discovery_scan_interval_sec=int(
            os.getenv("DISCOVERY_SCAN_INTERVAL_SEC", "300")
        ),
        discovery_socket_timeout_sec=float(
            os.getenv("DISCOVERY_SOCKET_TIMEOUT_SEC", "1.0")
        ),
        discovery_max_workers=int(os.getenv("DISCOVERY_MAX_WORKERS", "64")),
        onvif_multicast_host=os.getenv("ONVIF_MULTICAST_HOST", "239.255.255.250"),
        onvif_multicast_port=int(os.getenv("ONVIF_MULTICAST_PORT", "3702")),
        onvif_discovery_timeout_sec=float(
            os.getenv("ONVIF_DISCOVERY_TIMEOUT_SEC", "2.0")
        ),
        onvif_username=os.getenv("ONVIF_USERNAME", ""),
        onvif_password=os.getenv("ONVIF_PASSWORD", ""),
        rtsp_default_username=os.getenv("RTSP_DEFAULT_USERNAME", ""),
        rtsp_default_password=os.getenv("RTSP_DEFAULT_PASSWORD", ""),
        transcoder_host=os.getenv("TRANSCODER_HOST", "0.0.0.0"),
        transcoder_port=int(os.getenv("TRANSCODER_PORT", "8002")),
        mediamtx_api_url=os.getenv("MEDIAMTX_API_URL", "http://mediamtx:9997").rstrip("/"),
        mediamtx_webrtc_url=os.getenv("MEDIAMTX_WEBRTC_URL", "http://localhost:8889").rstrip("/"),
        mediamtx_hls_url=os.getenv("MEDIAMTX_HLS_URL", "http://localhost:8888").rstrip("/"),
        mediamtx_rtsp_url=os.getenv("MEDIAMTX_RTSP_URL", "rtsp://localhost:8554").rstrip("/"),
        rtsp_transport=os.getenv("RTSP_TRANSPORT", "tcp").lower(),
        stream_target_fps=max(1, min(60, int(os.getenv("STREAM_TARGET_FPS", "20")))),
        stream_jpeg_quality=max(
            10, min(100, int(os.getenv("STREAM_JPEG_QUALITY", "80")))
        ),
        stream_frame_width=int(os.getenv("STREAM_FRAME_WIDTH", "1280")),
        stream_frame_height=int(os.getenv("STREAM_FRAME_HEIGHT", "720")),
        stream_buffer_size=max(1, int(os.getenv("STREAM_BUFFER_SIZE", "2"))),
        stream_read_timeout_sec=float(os.getenv("STREAM_READ_TIMEOUT_SEC", "8.0")),
        stream_reconnect_base_delay_sec=float(
            os.getenv("STREAM_RECONNECT_BASE_DELAY_SEC", "1.0")
        ),
        stream_reconnect_max_delay_sec=float(
            os.getenv("STREAM_RECONNECT_MAX_DELAY_SEC", "30.0")
        ),
        stream_reconnect_max_attempts=int(
            os.getenv("STREAM_RECONNECT_MAX_ATTEMPTS", "0")
        ),
        enable_demo_streams=enable_demo_streams,
        processor_host=os.getenv("PROCESSOR_HOST", "0.0.0.0"),
        processor_port=int(os.getenv("PROCESSOR_PORT", "8003")),
        processor_sample_interval_sec=float(
            os.getenv("PROCESSOR_SAMPLE_INTERVAL_SEC", "0.5")
        ),
        motion_sensitivity_threshold=float(
            os.getenv("MOTION_SENSITIVITY_THRESHOLD", "500.0")
        ),
        motion_min_contour_area=int(os.getenv("MOTION_MIN_CONTOUR_AREA", "450")),
        tamper_darkness_threshold=float(
            os.getenv("TAMPER_DARKNESS_THRESHOLD", "18.0")
        ),
        tamper_variance_threshold=float(
            os.getenv("TAMPER_VARIANCE_THRESHOLD", "5.0")
        ),
        event_cooldown_sec=float(os.getenv("EVENT_COOLDOWN_SEC", "5.0")),
        max_stored_events=int(os.getenv("MAX_STORED_EVENTS", "1000")),
        gateway_host=os.getenv("GATEWAY_HOST", "0.0.0.0"),
        gateway_port=int(os.getenv("GATEWAY_PORT", "8080")),
        discovery_service_url=os.getenv(
            "DISCOVERY_SERVICE_URL", "http://localhost:8001"
        ).rstrip("/"),
        transcoder_service_url=os.getenv(
            "TRANSCODER_SERVICE_URL", "http://localhost:8002"
        ).rstrip("/"),
        processor_service_url=os.getenv(
            "PROCESSOR_SERVICE_URL", "http://localhost:8003"
        ).rstrip("/"),
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    )
