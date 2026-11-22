"""End-to-end integration tests for the Gateway Microservice and Web Operations Console."""

from __future__ import annotations

import time
from fastapi.testclient import TestClient

from services.gateway.app import app as gateway_app


def test_gateway_console_and_end_to_end_pipeline():
    with TestClient(gateway_app) as client:
        index_resp = client.get("/")
        assert index_resp.status_code == 200
        assert "CCTV-Streamer Operations Console" in index_resp.text

        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        health_data = health_resp.json()
        assert health_data["service"] == "gateway"
        assert "discovery" in health_data["details"]["microservices"]
        assert "transcoder" in health_data["details"]["microservices"]
        assert "processor" in health_data["details"]["microservices"]

        # Wait briefly for seeded OpenCV demo streams and analytics worker to process frames
        time.sleep(0.6)

        overview_resp = client.get("/api/v1/overview")
        assert overview_resp.status_code == 200
        overview = overview_resp.json()
        assert len(overview["cameras"]) >= 4
        assert len(overview["streams"]) >= 4
        assert overview["analytics"]["total_frames_processed"] >= 1

        # Verify snapshot endpoint through gateway
        snap_resp = client.get("/api/v1/streams/cam-north-gate/snapshot")
        assert snap_resp.status_code == 200
        assert snap_resp.content.startswith(b"\xff\xd8")
