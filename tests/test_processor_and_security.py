"""Tests for OpenCV Data Processing & Video Analytics and Security Credential Redaction."""

from __future__ import annotations

import base64
import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient

from services.processor.analytics_engine import VideoAnalyticsEngine
from services.processor.app import app as processor_app
from shared.logger import redact_sensitive_text
from shared.models import EventType
from shared.security import (
    inject_rtsp_credentials,
    mask_rtsp_credentials,
    validate_rtsp_source,
    validate_subnet_cidr,
)


def test_opencv_motion_detection_and_bounding_boxes():
    engine = VideoAnalyticsEngine(
        default_motion_threshold=300.0,
        default_min_contour_area=200,
        default_cooldown_sec=0.0,
    )

    # Frame 1: Static gray room background
    frame1 = np.full((360, 640, 3), 70, dtype=np.uint8)
    out1 = engine.process_frame("cam-lab-1", frame1, "Lab Camera 1")
    assert out1.motion_detected is False

    # Frame 2: Bright intruder object enters frame
    frame2 = frame1.copy()
    cv2.rectangle(frame2, (220, 140), (340, 280), (240, 240, 240), -1)
    out2 = engine.process_frame("cam-lab-1", frame2, "Lab Camera 1")

    assert out2.motion_detected is True
    assert out2.motion_score >= 300.0
    assert len(out2.bounding_boxes) >= 1
    assert any(e.event_type == EventType.MOTION_DETECTED for e in out2.events_emitted)


def test_opencv_tamper_obstruction_detection():
    engine = VideoAnalyticsEngine(
        default_tamper_darkness=20.0,
        default_tamper_variance=5.0,
        default_cooldown_sec=0.0,
    )
    # Near-black frame simulating covered or spray-painted lens
    black_frame = np.zeros((360, 640, 3), dtype=np.uint8)
    output = engine.process_frame("cam-tampered", black_frame, "Vault Cam")
    assert output.tamper_detected is True
    assert any(
        e.event_type == EventType.TAMPER_OBSTRUCTION for e in output.events_emitted
    )


def test_processor_api_endpoints():
    client = TestClient(processor_app)
    frame = np.full((360, 640, 3), 85, dtype=np.uint8)
    ok, buf = cv2.imencode(".jpg", frame)
    assert ok
    b64_img = base64.b64encode(buf.tobytes()).decode("ascii")

    resp = client.post(
        "/api/v1/process/frame",
        json={
            "camera_id": "cam-proc-api",
            "camera_name": "Processor API Cam",
            "image_base64": b64_img,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["camera_id"] == "cam-proc-api"
    assert "processing_time_ms" in data


def test_security_credential_masking_and_validation():
    raw_url = "rtsp://admin:MyTopSecretPwd!@192.168.1.55:554/Streaming/Channels/101"
    masked = mask_rtsp_credentials(raw_url)
    assert "MyTopSecretPwd!" not in masked
    assert "admin:********@192.168.1.55:554" in masked

    log_line = f"Connecting to {raw_url} with token Bearer eyJhbGciOiJIUzI1NiJ9"
    redacted = redact_sensitive_text(log_line)
    assert "MyTopSecretPwd!" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted

    injected = inject_rtsp_credentials(
        "rtsp://10.0.0.15:554/stream1", "operator", "pass123"
    )
    assert injected == "rtsp://operator:pass123@10.0.0.15:554/stream1"

    net = validate_subnet_cidr("192.168.1.0/24")
    assert net.num_addresses == 256

    with pytest.raises(ValueError):
        validate_subnet_cidr("10.0.0.0/8", max_hosts=1024)

    with pytest.raises(ValueError):
        validate_rtsp_source("file:///etc/passwd")
