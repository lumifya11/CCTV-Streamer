"""Unified Enterprise API Gateway & Control Room Orchestrator for CCTV-Streamer."""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from services.discovery.app import (
    DirectCameraProbeRequest,
    registry as local_discovery_registry,
)
from services.processor.app import (
    CameraConfigUpdateRequest,
    analytics_engine as local_analytics_engine,
)
from services.transcoder.app import (
    _mjpeg_stream_generator,
    _seed_demo_streams_if_enabled,
    stream_manager as local_stream_manager,
)
from shared.config import get_config
from shared.logger import get_logger
from shared.models import (
    AnalyticsEvent,
    CameraDevice,
    DiscoveryRequest,
    DiscoveryResult,
    EventSeverity,
    EventType,
    HealthStatus,
    StreamMetrics,
    StreamRegistrationRequest,
    StreamState,
    utc_now_iso,
)
from shared.security import verify_api_key

logger = get_logger("gateway.service")
SERVICE_START_TIME = time.monotonic()
config = get_config()
STATIC_DIR = Path(__file__).parent / "static"


def _is_distributed_mode() -> bool:
    return os.getenv("GATEWAY_MODE", "hybrid").lower() == "distributed"


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
    description="Unified Microservices Orchestrator & Web Operations Console for CCTV-Streamer",
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

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def serve_console() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", response_model=HealthStatus)
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
        details={"microservices": services_status},
    )


@app.get("/api/v1/overview")
async def get_system_overview(_: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    """Aggregate discovery, active streams, analytics metrics, and recent events in one call."""
    cameras = await list_cameras(_=True)
    streams = await list_streams(_=True)
    events = await list_events(limit=25, _=True)
    analytics = await get_analytics_metrics(_=True)
    health = await gateway_health()

    return {
        "timestamp": utc_now_iso(),
        "health": health.model_dump(),
        "cameras": [c.model_dump() if hasattr(c, "model_dump") else c for c in cameras],
        "streams": [s.model_dump() if hasattr(s, "model_dump") else s for s in streams],
        "analytics": analytics,
        "events": [e.model_dump() if hasattr(e, "model_dump") else e for e in events],
    }


@app.get("/api/v1/cameras", response_model=List[CameraDevice])
async def list_cameras(_: bool = Depends(verify_api_key)) -> List[CameraDevice]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{config.discovery_service_url}/api/v1/cameras")
            resp.raise_for_status()
            return [CameraDevice(**item) for item in resp.json()]
    return local_discovery_registry.list_cameras()


@app.post("/api/v1/discover", response_model=DiscoveryResult)
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


@app.get("/api/v1/streams", response_model=List[StreamMetrics])
async def list_streams(_: bool = Depends(verify_api_key)) -> List[StreamMetrics]:
    if _is_distributed_mode():
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{config.transcoder_service_url}/api/v1/streams")
            resp.raise_for_status()
            return [StreamMetrics(**item) for item in resp.json()]
    return local_stream_manager.list_metrics()


@app.post("/api/v1/streams", response_model=StreamMetrics, status_code=status.HTTP_201_CREATED)
async def register_stream(
    request: StreamRegistrationRequest,
    _: bool = Depends(verify_api_key),
) -> StreamMetrics:
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
        return local_stream_manager.register_stream(request)
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
    return {"status": "deleted", "camera_id": camera_id}


@app.get("/api/v1/streams/{camera_id}/snapshot")
async def stream_snapshot(camera_id: str) -> Response:
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
async def stream_mjpeg(camera_id: str) -> StreamingResponse:
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "services.gateway.app:app",
        host=config.gateway_host,
        port=config.gateway_port,
        reload=False,
    )
