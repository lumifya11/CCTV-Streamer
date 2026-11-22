"""FastAPI application for the Video Stream Transcoding & MediaMTX Control Microservice."""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from services.device_manager.registry import DurableDeviceRegistry
from services.transcoder.mediamtx_client import MediaMTXClient
from services.transcoder.stream_engine import RTSPStreamWorker, StreamManager
from shared.auth import verify_media_ticket, verify_signed_token
from shared.config import get_config, is_placeholder_secret
from shared.logger import get_logger
from shared.models import (
    HealthStatus,
    StreamMetrics,
    StreamRegistrationRequest,
    StreamState,
)
from shared.security import verify_api_key, verify_media_access

logger = get_logger("transcoder.service")
SERVICE_START_TIME = time.monotonic()
config = get_config()

stream_manager = StreamManager(
    rtsp_transport=config.rtsp_transport,
    buffer_size=config.stream_buffer_size,
    read_timeout_sec=config.stream_read_timeout_sec,
    reconnect_base_delay_sec=config.stream_reconnect_base_delay_sec,
    reconnect_max_delay_sec=config.stream_reconnect_max_delay_sec,
    reconnect_max_attempts=config.stream_reconnect_max_attempts,
)
mediamtx_client = MediaMTXClient()


class AnalyticsFeedbackPayload(BaseModel):
    motion_active: bool
    motion_score: float = 0.0


def _seed_demo_streams_if_enabled() -> None:
    if not config.enable_demo_streams:
        return
    defaults = [
        StreamRegistrationRequest(
            camera_id="cam-north-gate",
            name="North Perimeter Gate PTZ",
            location="Perimeter North",
            rtsp_url="demo://north-gate",
            target_fps=config.stream_target_fps,
            width=config.stream_frame_width,
            height=config.stream_frame_height,
            jpeg_quality=config.stream_jpeg_quality,
        ),
        StreamRegistrationRequest(
            camera_id="cam-server-vault",
            name="Data Center Corridor B2",
            location="Server Vault B2",
            rtsp_url="demo://server-vault",
            target_fps=config.stream_target_fps,
            width=config.stream_frame_width,
            height=config.stream_frame_height,
            jpeg_quality=config.stream_jpeg_quality,
        ),
        StreamRegistrationRequest(
            camera_id="cam-loading-bay",
            name="Logistics Loading Dock 4",
            location="Loading Dock 4",
            rtsp_url="demo://loading-bay",
            target_fps=config.stream_target_fps,
            width=config.stream_frame_width,
            height=config.stream_frame_height,
            jpeg_quality=config.stream_jpeg_quality,
        ),
        StreamRegistrationRequest(
            camera_id="cam-lobby-main",
            name="Executive Terminal Main Concourse",
            location="Terminal Concourse",
            rtsp_url="demo://lobby-main",
            target_fps=config.stream_target_fps,
            width=config.stream_frame_width,
            height=config.stream_frame_height,
            jpeg_quality=config.stream_jpeg_quality,
        ),
    ]
    for item in defaults:
        stream_manager.register_stream(item)
        mediamtx_client.register_camera_path(item.camera_id, item.rtsp_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting Video Stream Transcoding Microservice on %s:%d",
        config.transcoder_host,
        config.transcoder_port,
    )
    _seed_demo_streams_if_enabled()
    yield
    logger.info("Stopping all active OpenCV stream workers...")
    stream_manager.stop_all()


app = FastAPI(
    title="CCTV-Streamer Video Transcoding & MediaMTX Control Service",
    description="Resilient OpenCV RTSP Engine & MediaMTX WebRTC/HLS Stream Controller",
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
    all_metrics = stream_manager.list_metrics()
    active_count = sum(1 for m in all_metrics if m.state == StreamState.STREAMING)
    reconnecting_count = sum(1 for m in all_metrics if m.state == StreamState.RECONNECTING)
    return HealthStatus(
        service="transcoder",
        status="healthy",
        uptime_seconds=round(time.monotonic() - SERVICE_START_TIME, 2),
        details={
            "total_streams": len(all_metrics),
            "streaming_active": active_count,
            "reconnecting": reconnecting_count,
            "rtsp_transport": config.rtsp_transport,
            "media_routes_protected": True,
        },
    )


@app.get("/api/v1/streams", response_model=List[StreamMetrics])
async def list_streams(_: bool = Depends(verify_api_key)) -> List[StreamMetrics]:
    return stream_manager.list_metrics()


@app.get("/api/v1/streams/{camera_id}", response_model=StreamMetrics)
@app.get("/api/v1/streams/{camera_id}/status", response_model=StreamMetrics)
async def get_stream_metrics(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline for camera '{camera_id}' not found.",
        )
    return worker.get_metrics()


@app.post("/api/v1/streams", response_model=StreamMetrics, status_code=status.HTTP_201_CREATED)
async def register_or_update_stream(
    request: StreamRegistrationRequest,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    if request.require_approval:
        reg = DurableDeviceRegistry()
        dev = reg.get_device(request.camera_id)
        if dev is not None and not dev.approved:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Camera candidate '{request.camera_id}' must be approved before streaming.",
            )
    try:
        metrics = stream_manager.register_stream(request)
        mediamtx_client.register_camera_path(request.camera_id, request.rtsp_url)
        return metrics
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@app.delete("/api/v1/streams/{camera_id}")
async def delete_stream(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> dict:
    removed = stream_manager.remove_stream(camera_id)
    mediamtx_client.remove_camera_path(camera_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    return {"status": "deleted", "camera_id": camera_id}


@app.post("/api/v1/streams/{camera_id}/reconnect", response_model=StreamMetrics)
async def reconnect_stream(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    worker.trigger_reconnect()
    return worker.get_metrics()


@app.post("/api/v1/streams/{camera_id}/playback-ticket")
async def create_stream_playback_ticket(
    camera_id: str,
    _: bool = Depends(verify_api_key),
) -> Dict[str, Any]:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    return mediamtx_client.build_playback_bundle(camera_id=camera_id)


@app.post("/api/v1/streams/{camera_id}/analytics", response_model=StreamMetrics)
async def update_stream_analytics_overlay(
    camera_id: str,
    payload: AnalyticsFeedbackPayload,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    worker.update_analytics_status(payload.motion_active, payload.motion_score)
    return worker.get_metrics()


@app.get("/api/v1/streams/{camera_id}/snapshot")
async def get_stream_snapshot(
    camera_id: str,
    _auth: Dict[str, Any] = Depends(verify_media_access),
) -> Response:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    jpeg_bytes = worker.get_latest_jpeg()
    if not jpeg_bytes:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Frame buffer not yet initialized.",
        )
    return Response(
        content=jpeg_bytes,
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )


async def _mjpeg_stream_generator(worker: RTSPStreamWorker) -> AsyncGenerator[bytes, None]:
    """Low-latency multipart MJPEG stream generator."""
    last_seq = -1
    loop = asyncio.get_running_loop()
    try:
        while True:
            seq, jpeg_bytes = await loop.run_in_executor(
                None, worker.wait_for_next_jpeg, last_seq, 0.5
            )
            last_seq = seq
            if jpeg_bytes:
                header = (
                    b"--frame\r\n"
                    b"Content-Type: image/jpeg\r\n"
                    + f"Content-Length: {len(jpeg_bytes)}\r\n\r\n".encode("ascii")
                )
                yield header + jpeg_bytes + b"\r\n"
            await asyncio.sleep(0.01)
    except asyncio.CancelledError:
        return


@app.get("/api/v1/streams/{camera_id}/mjpeg")
async def stream_mjpeg(
    camera_id: str,
    _auth: Dict[str, Any] = Depends(verify_media_access),
) -> StreamingResponse:
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Stream pipeline '{camera_id}' not found.",
        )
    return StreamingResponse(
        _mjpeg_stream_generator(worker),
        media_type="multipart/x-mixed-replace; boundary=frame",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _authorize_websocket(websocket: WebSocket, camera_id: str, ticket: Optional[str]) -> bool:
    """Enforce fail-closed WebSocket authentication via ticket or headers."""
    cfg = get_config()
    must_fail_closed = cfg.is_production() or cfg.fail_closed_auth
    expected_key = cfg.api_secret_key

    if must_fail_closed and is_placeholder_secret(expected_key):
        return False

    if ticket:
        return verify_media_ticket(ticket, required_camera_id=camera_id) is not None

    auth_hdr = websocket.headers.get("authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        tok = auth_hdr[7:].strip()
        if verify_signed_token(tok) is not None:
            return True
        if not is_placeholder_secret(expected_key) and tok == expected_key:
            return True

    api_key_hdr = websocket.headers.get("x-api-key", "")
    if api_key_hdr and not is_placeholder_secret(expected_key) and api_key_hdr == expected_key:
        return True

    if must_fail_closed or not is_placeholder_secret(expected_key):
        return False
    return True


@app.websocket("/api/v1/streams/{camera_id}/ws")
async def stream_websocket(
    websocket: WebSocket,
    camera_id: str,
    ticket: Optional[str] = Query(default=None),
) -> None:
    if not _authorize_websocket(websocket, camera_id, ticket):
        await websocket.close(code=1008)
        return
    worker = stream_manager.get_worker(camera_id)
    if not worker:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    last_seq = -1
    loop = asyncio.get_running_loop()
    try:
        while True:
            seq, jpeg_bytes = await loop.run_in_executor(
                None, worker.wait_for_next_jpeg, last_seq, 0.5
            )
            last_seq = seq
            if jpeg_bytes:
                await websocket.send_bytes(jpeg_bytes)
            await asyncio.sleep(0.01)
    except WebSocketDisconnect:
        return
    except Exception:
        return
