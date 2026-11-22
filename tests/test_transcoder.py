"""Tests for the OpenCV Video Stream Transcoding Engine and Automatic Reconnection."""

from __future__ import annotations

import time
import numpy as np
from fastapi.testclient import TestClient

from services.transcoder.app import app as transcoder_app
from services.transcoder.stream_engine import (
    RTSPStreamWorker,
    compute_backoff_delay,
)
from shared.models import StreamRegistrationRequest, StreamState


class FlakyMockCapture:
    """
    Simulates an unstable RTSP camera connection for testing automatic reconnection:
    - Call 1: fails to open
    - Call 2: opens, yields 2 valid frames, then drops connection (`read()` returns False)
    - Call 3+: opens and streams continuously
    """

    def __init__(self, attempt_number: int) -> None:
        self.attempt_number = attempt_number
        self._opened = attempt_number >= 2
        self._reads = 0

    def isOpened(self) -> bool:
        return self._opened

    def set(self, prop_id: int, value: float) -> bool:
        return True

    def read(self):
        if not self._opened:
            return (False, None)
        self._reads += 1
        if self.attempt_number == 2 and self._reads > 2:
            self._opened = False
            return (False, None)
        frame = np.full((360, 640, 3), 90, dtype=np.uint8)
        return (True, frame)

    def release(self) -> None:
        self._opened = False


def test_exponential_backoff_calculation():
    d1 = compute_backoff_delay(1, base_delay_sec=1.0, max_delay_sec=30.0, jitter_ratio=0.0)
    d2 = compute_backoff_delay(2, base_delay_sec=1.0, max_delay_sec=30.0, jitter_ratio=0.0)
    d4 = compute_backoff_delay(4, base_delay_sec=1.0, max_delay_sec=30.0, jitter_ratio=0.0)
    assert d1 == 1.0
    assert d2 == 2.0
    assert d4 == 8.0


def test_opencv_stream_worker_synthetic_ingestion():
    req = StreamRegistrationRequest(
        camera_id="cam-test-synth",
        name="Synthetic Unit Test Camera",
        location="Lab Zone",
        rtsp_url="demo://unit-test",
        target_fps=25,
        width=640,
        height=360,
        jpeg_quality=75,
    )
    worker = RTSPStreamWorker(registration=req)
    worker.start()
    try:
        seq, jpeg_bytes = worker.wait_for_next_jpeg(-1, timeout_sec=2.0)
        assert seq >= 1
        assert jpeg_bytes.startswith(b"\xff\xd8")
        metrics = worker.get_metrics()
        assert metrics.state == StreamState.STREAMING
        assert metrics.frames_ingested >= 1
    finally:
        worker.stop()


def test_opencv_stream_worker_automatic_reconnection():
    """Verify that RTSPStreamWorker recovers from connection failure and mid-stream drops."""
    attempts = {"count": 0}

    def factory(_url: str):
        attempts["count"] += 1
        return FlakyMockCapture(attempts["count"])

    req = StreamRegistrationRequest(
        camera_id="cam-flaky-rtsp",
        name="Flaky RTSP Camera",
        location="Perimeter West",
        rtsp_url="rtsp://admin:supersecret@192.168.1.99:554/stream1",
        target_fps=30,
        width=640,
        height=360,
    )
    worker = RTSPStreamWorker(
        registration=req,
        reconnect_base_delay_sec=0.05,
        reconnect_max_delay_sec=0.15,
        capture_factory=factory,
    )
    worker.start()
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            metrics = worker.get_metrics()
            if metrics.total_reconnections >= 2 and metrics.frames_ingested >= 4:
                break
            time.sleep(0.05)

        final_metrics = worker.get_metrics()
        assert attempts["count"] >= 3
        assert final_metrics.total_reconnections >= 2
        assert final_metrics.frames_ingested >= 4
        assert "supersecret" not in final_metrics.rtsp_url_masked
        assert "********" in final_metrics.rtsp_url_masked
    finally:
        worker.stop()


def test_transcoder_api_endpoints():
    with TestClient(transcoder_app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["service"] == "transcoder"

        create_resp = client.post(
            "/api/v1/streams",
            json={
                "camera_id": "cam-api-test",
                "name": "API Test Stream",
                "location": "Gate 2",
                "rtsp_url": "demo://api-test",
                "target_fps": 15,
                "width": 640,
                "height": 360,
            },
        )
        assert create_resp.status_code == 201

        time.sleep(0.15)
        snap_resp = client.get("/api/v1/streams/cam-api-test/snapshot")
        assert snap_resp.status_code == 200
        assert snap_resp.headers["content-type"] == "image/jpeg"
        assert snap_resp.content.startswith(b"\xff\xd8")

        reconn_resp = client.post("/api/v1/streams/cam-api-test/reconnect")
        assert reconn_resp.status_code == 200

        del_resp = client.delete("/api/v1/streams/cam-api-test")
        assert del_resp.status_code == 200
