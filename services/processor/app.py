"""FastAPI application for the Data Processing & Video Analytics Microservice."""

from __future__ import annotations

import asyncio
import base64
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.processor.analytics_engine import VideoAnalyticsEngine
from shared.config import get_config, is_placeholder_secret
from shared.logger import get_logger
from shared.models import AnalyticsEvent, EventSeverity, EventType, HealthStatus
from shared.security import verify_api_key

logger = get_logger("processor.service")
SERVICE_START_TIME = time.monotonic()
config = get_config()

analytics_engine = VideoAnalyticsEngine(
    default_motion_threshold=config.motion_sensitivity_threshold,
    default_min_contour_area=config.motion_min_contour_area,
    default_tamper_darkness=config.tamper_darkness_threshold,
    default_tamper_variance=config.tamper_variance_threshold,
    default_cooldown_sec=config.event_cooldown_sec,
    max_stored_events=config.max_stored_events,
)

MAX_FRAME_BASE64_LEN = 6_000_000  # ~4.5 MB upper bound on frame payload


class FrameProcessRequest(BaseModel):
    camera_id: str
    camera_name: Optional[str] = None
    image_base64: str = Field(..., max_length=MAX_FRAME_BASE64_LEN, description="Base64-encoded JPEG frame bytes")


class CameraConfigUpdateRequest(BaseModel):
    motion_sensitivity_threshold: Optional[float] = Field(default=None, ge=10.0)
    motion_min_contour_area: Optional[int] = Field(default=None, ge=20)
    tamper_darkness_threshold: Optional[float] = Field(default=None, ge=1.0, le=255.0)
    tamper_variance_threshold: Optional[float] = Field(default=None, ge=0.5, le=255.0)
    event_cooldown_sec: Optional[float] = Field(default=None, ge=0.5, le=3600.0)
    enabled: Optional[bool] = None
    zones: Optional[List[Dict[str, Any]]] = None


async def _poll_transcoder_streams_task(stop_event: asyncio.Event) -> None:
    """Background worker that samples active camera snapshots from the Transcoder service."""
    headers: Dict[str, str] = {}
    if not is_placeholder_secret(config.api_secret_key):
        headers["X-API-Key"] = config.api_secret_key

    async with httpx.AsyncClient(timeout=2.5, headers=headers) as client:
        while not stop_event.is_set():
            try:
                resp = await client.get(f"{config.transcoder_service_url}/api/v1/streams")
                if resp.status_code == 200:
                    streams = resp.json()
                    for stream_info in streams:
                        if stream_info.get("state") != "STREAMING":
                            continue
                        cam_id = stream_info["camera_id"]
                        cam_name = stream_info.get("name", cam_id)
                        snap_resp = await client.get(
                            f"{config.transcoder_service_url}/api/v1/streams/{cam_id}/snapshot"
                        )
                        if snap_resp.status_code == 200 and snap_resp.content:
                            output = analytics_engine.process_jpeg_bytes(
                                camera_id=cam_id,
                                jpeg_bytes=snap_resp.content,
                                camera_name=cam_name,
                            )
                            await client.post(
                                f"{config.transcoder_service_url}/api/v1/streams/{cam_id}/analytics",
                                json={
                                    "motion_active": output.motion_detected,
                                    "motion_score": output.motion_score,
                                },
                            )
            except Exception as exc:
                logger.debug("Transcoder sampling cycle skipped: %s", exc)

            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=config.processor_sample_interval_sec
                )
            except asyncio.TimeoutError:
                continue


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting Data Processing & Video Analytics Microservice on %s:%d",
        config.processor_host,
        config.processor_port,
    )
    stop_event = asyncio.Event()
    poller_task = asyncio.create_task(_poll_transcoder_streams_task(stop_event))
    yield
    stop_event.set()
    poller_task.cancel()
    try:
        await poller_task
    except asyncio.CancelledError:
        pass
    logger.info("Stopped Data Processing Microservice")


app = FastAPI(
    title="CCTV-Streamer Data Processing & Video Analytics Service",
    description="OpenCV Real-Time Motion Detection, Zone Masking & Durable Event Persistence Service",
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
    summary = analytics_engine.get_metrics_summary()
    return HealthStatus(
        service="processor",
        status="healthy",
        uptime_seconds=round(time.monotonic() - SERVICE_START_TIME, 2),
        details={
            "total_frames_processed": summary["total_frames_processed"],
            "total_motion_events": summary["total_motion_events"],
            "total_tamper_events": summary["total_tamper_events"],
            "monitored_cameras": len(summary["cameras"]),
            "durable_persistence": True,
        },
    )


@app.post("/api/v1/process/frame")
async def process_frame_endpoint(
    request: FrameProcessRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    try:
        raw_bytes = base64.b64decode(request.image_base64)
        output = analytics_engine.process_jpeg_bytes(
            camera_id=request.camera_id,
            jpeg_bytes=raw_bytes,
            camera_name=request.camera_name,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to decode or analyze frame: {exc}",
        ) from exc

    return {
        "camera_id": output.camera_id,
        "camera_name": output.camera_name,
        "motion_detected": output.motion_detected,
        "motion_score": output.motion_score,
        "tamper_detected": output.tamper_detected,
        "mean_luminance": output.mean_luminance,
        "pixel_std_dev": output.pixel_std_dev,
        "bounding_boxes": output.bounding_boxes,
        "processing_time_ms": output.processing_time_ms,
        "events_emitted": [e.model_dump() for e in output.events_emitted],
    }


@app.get("/api/v1/events", response_model=List[AnalyticsEvent])
async def list_analytics_events(
    camera_id: Optional[str] = Query(default=None),
    event_type: Optional[EventType] = Query(default=None),
    severity: Optional[EventSeverity] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    _: bool = Depends(verify_api_key),
) -> List[AnalyticsEvent]:
    return analytics_engine.list_events(
        camera_id=camera_id,
        event_type=event_type,
        severity=severity,
        limit=limit,
    )


@app.post("/api/v1/events/{event_id}/acknowledge", response_model=AnalyticsEvent)
async def acknowledge_event_endpoint(
    event_id: str,
    _: bool = Depends(verify_api_key),
) -> AnalyticsEvent:
    evt = analytics_engine.acknowledge_event(event_id)
    if not evt:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found.",
        )
    return evt


@app.get("/api/v1/metrics")
async def get_analytics_metrics(_: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    return analytics_engine.get_metrics_summary()


@app.put("/api/v1/config/{camera_id}")
async def update_camera_analytics_config(
    camera_id: str,
    request: CameraConfigUpdateRequest,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    cfg = analytics_engine.update_config(
        camera_id=camera_id,
        motion_sensitivity_threshold=request.motion_sensitivity_threshold,
        motion_min_contour_area=request.motion_min_contour_area,
        tamper_darkness_threshold=request.tamper_darkness_threshold,
        tamper_variance_threshold=request.tamper_variance_threshold,
        event_cooldown_sec=request.event_cooldown_sec,
        enabled=request.enabled,
        zones=request.zones,
    )
    return {
        "camera_id": cfg.camera_id,
        "motion_sensitivity_threshold": cfg.motion_sensitivity_threshold,
        "motion_min_contour_area": cfg.motion_min_contour_area,
        "tamper_darkness_threshold": cfg.tamper_darkness_threshold,
        "tamper_variance_threshold": cfg.tamper_variance_threshold,
        "event_cooldown_sec": cfg.event_cooldown_sec,
        "enabled": cfg.enabled,
        "zones": [z.__dict__ for z in cfg.zones],
    }
