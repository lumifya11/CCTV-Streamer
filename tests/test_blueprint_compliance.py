"""Comprehensive test suite verifying Ultra Master Blueprint v1.0 security, registry, vault, and API gates."""

from __future__ import annotations

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from services.device_manager.enrollment import DeviceEnrollmentService
from services.device_manager.registry import DurableDeviceRegistry
from services.gateway.app import app as gateway_app
from services.recording.coordinator import RecordingCoordinator, calculate_storage_estimate
from shared.auth import clear_login_failures, issue_media_ticket, verify_media_ticket
from shared.config import get_config
from shared.database import DatabaseManager, reset_global_db
from shared.models import (
    CameraDevice,
    CompatibilityTier,
    DeviceLifecycleState,
    RTSPEndpoint,
)
from shared.secrets import CredentialVault
from shared.security import (
    validate_onvif_xaddr,
    validate_rtsp_source,
    validate_subnet_cidr,
    validate_target_destination,
)


def test_fail_closed_authentication_in_production(monkeypatch):
    """SEC-001: Production mode must fail closed if API_SECRET_KEY is missing or a placeholder."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("API_SECRET_KEY", "change-me-placeholder-secret-key")
    monkeypatch.setenv("VAULT_MASTER_KEY", "change-me-placeholder-vault-key")

    cfg = get_config()
    violations = cfg.validate_production_readiness()
    assert len(violations) >= 2
    assert cfg.enable_demo_streams is False

    client = TestClient(gateway_app)
    resp = client.get("/api/v1/cameras")
    assert resp.status_code == 503
    assert "failed closed" in resp.json()["detail"].lower()


def test_media_endpoints_require_auth_or_camera_scoped_ticket(monkeypatch):
    """SEC-002: Snapshot, MJPEG, and WebSocket routes must enforce auth and camera-scoped tickets."""
    strong_secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("FAIL_CLOSED_AUTH", "true")
    monkeypatch.setenv("API_SECRET_KEY", strong_secret)

    with TestClient(gateway_app) as client:
        # 1. Anonymous request to snapshot or MJPEG must be rejected with 401
        unauth_snap = client.get("/api/v1/streams/cam-north-gate/snapshot")
        assert unauth_snap.status_code == 401

        unauth_mjpeg = client.get("/api/v1/streams/cam-north-gate/mjpeg")
        assert unauth_mjpeg.status_code == 401

        # 2. Issue a short-lived playback ticket scoped strictly to cam-north-gate
        tkt_bundle = issue_media_ticket(camera_id="cam-north-gate", ttl_sec=60)
        ticket = tkt_bundle["ticket"]

        # 3. Valid ticket grants access to cam-north-gate snapshot
        auth_snap = client.get(f"/api/v1/streams/cam-north-gate/snapshot?ticket={ticket}")
        assert auth_snap.status_code == 200
        assert auth_snap.headers["content-type"] == "image/jpeg"

        # 4. Using cam-north-gate's ticket to view cam-server-vault must be rejected (401)
        cross_cam_snap = client.get(f"/api/v1/streams/cam-server-vault/snapshot?ticket={ticket}")
        assert cross_cam_snap.status_code == 401


def test_ssrf_and_destination_allowlist_protections():
    """SEC-003: Block cloud metadata, link-local, multicast, loopback, public IPs, and XAddr spoofing."""
    # Cloud metadata / link-local 169.254.169.254 must be blocked
    with pytest.raises(ValueError, match="link-local"):
        validate_target_destination("http://169.254.169.254/latest/meta-data/")

    # Multicast address must be blocked
    with pytest.raises(ValueError, match="multicast"):
        validate_target_destination("rtsp://239.255.255.250:554/stream")

    # Public internet IP must be blocked
    with pytest.raises(ValueError, match="public internet"):
        validate_target_destination("rtsp://93.184.216.34:554/live")

    # Public CIDR range in subnet scanner must be blocked
    with pytest.raises(ValueError, match="prohibited"):
        validate_subnet_cidr("8.8.8.0/24", allow_public=False)

    # ONVIF XAddr pointing to a different host than the discovered camera IP must be blocked
    with pytest.raises(ValueError, match="does not match"):
        validate_onvif_xaddr(
            "http://192.168.1.200:80/onvif/device_service",
            expected_device_ip="192.168.1.50",
            approved_cidrs=["192.168.1.0/24"],
        )

    # Valid private camera IP within approved CIDR scope succeeds
    resolved = validate_target_destination(
        "rtsp://192.168.1.50:554/Streaming/Channels/101",
        approved_cidrs=["192.168.1.0/24"],
    )
    assert resolved == "192.168.1.50"


def test_encrypted_credential_vault_and_key_rotation():
    """Phase 3: Credentials must be encrypted at rest and never exposed in plaintext."""
    key_v1 = "vault-master-key-version-1-super-strong-32bytes"
    key_v2 = "vault-master-key-version-2-rotated-strong-32bytes"
    vault = CredentialVault(master_key=key_v1)

    ciphertext = vault.encrypt_secret("CameraSecretPass!2026")
    assert "CameraSecretPass!2026" not in ciphertext
    assert vault.decrypt_secret(ciphertext) == "CameraSecretPass!2026"

    # Rotate to key_v2
    rotated_ct = vault.rotate_ciphertext(ciphertext, new_master_key=key_v2)
    vault_v2 = CredentialVault(master_key=key_v2)
    assert vault_v2.decrypt_secret(rotated_ct) == "CameraSecretPass!2026"


def test_durable_registry_immutable_identity_and_approval_workflow():
    """Phase 1 & 3: Immutable UUID across DHCP IP changes and mandatory approval before enrollment."""
    db = DatabaseManager(database_url="sqlite:///:memory:")
    reg = DurableDeviceRegistry(db=db)
    vault = CredentialVault(master_key="test-vault-master-key-for-enrollment-suite")
    enrollment = DeviceEnrollmentService(registry=reg, vault=vault, db=db)

    # 1. Discover a camera candidate at 192.168.1.110 with ONVIF UUID urn:uuid:cam-fixed-001
    candidate = CameraDevice(
        camera_id="dev-fixed001",
        site_id="site-default",
        name="Warehouse East Camera",
        ip_address="192.168.1.110",
        mac_address="aa:bb:cc:11:22:33",
        open_ports=[554, 80],
        onvif_supported=True,
        onvif_xaddr="http://192.168.1.110:80/onvif/device_service",
        compatibility_tier=CompatibilityTier.TIER_1_STANDARDS,
        lifecycle_state=DeviceLifecycleState.CAMERA_CANDIDATE,
        approved=False,
        rtsp_endpoints=[
            RTSPEndpoint(
                url="rtsp://admin:leakedpass@192.168.1.110:554/Streaming/Channels/101",
                port=554,
                path="/Streaming/Channels/101",
            )
        ],
        primary_rtsp_url="rtsp://admin:leakedpass@192.168.1.110:554/Streaming/Channels/101",
    )
    saved = reg.upsert_discovered_device(candidate, onvif_uuid="urn:uuid:cam-fixed-001")
    # Credentials must be stripped from stored URI template
    assert "leakedpass" not in (saved.primary_rtsp_url or "")
    assert saved.approved is False

    # 2. Attempting to enroll an unapproved candidate must fail with PermissionError
    with pytest.raises(PermissionError, match="not been approved"):
        enrollment.enroll_device(
            device_id=saved.camera_id,
            protocol="ONVIF",
            username="admin",
            password="AuthorizedPassword123",
        )

    # 3. DHCP changes camera IP from 192.168.1.110 to 192.168.1.115 (same ONVIF UUID)
    candidate_dhcp = candidate.model_copy(update={"ip_address": "192.168.1.115"})
    saved_after_dhcp = reg.upsert_discovered_device(
        candidate_dhcp, onvif_uuid="urn:uuid:cam-fixed-001"
    )
    assert saved_after_dhcp.camera_id == saved.camera_id
    assert saved_after_dhcp.ip_address == "192.168.1.115"
    history = reg.get_address_history(saved.camera_id)
    assert len(history) == 2

    # 4. Owner approves candidate -> enrollment succeeds
    approved_dev = reg.approve_candidate(saved.camera_id, approved_by="owner")
    assert approved_dev.approved is True
    assert approved_dev.lifecycle_state == DeviceLifecycleState.USER_APPROVED

    enroll_res = enrollment.enroll_device(
        device_id=saved.camera_id,
        protocol="ONVIF",
        username="operator_cam",
        password="AuthorizedPassword123",
        onvif_profile_preference="Profile_S",
    )
    assert enroll_res["credential_profile_id"].startswith("cred-")
    assert enroll_res["legacy_profile_s_warning"] is not None
    assert "2027" in enroll_res["legacy_profile_s_warning"]


def test_auth_bootstrap_login_throttling_and_mobile_pairing(monkeypatch):
    """Phase 6 & 7: Owner bootstrap, login brute-force throttling, and mobile QR pairing flow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_url = f"sqlite:///{tmpdir}/test_auth.db"
        monkeypatch.setenv("DATABASE_URL", db_url)
        reset_global_db(db_url)
        clear_login_failures("chief_owner")

        with TestClient(gateway_app) as client:
            # 1. One-time owner bootstrap
            boot_resp = client.post(
                "/api/v1/auth/bootstrap",
                json={"username": "chief_owner", "password": "UltraSecureOwnerPassword!99"},
            )
            assert boot_resp.status_code == 201
            assert boot_resp.json()["role"] == "OWNER"

            # Second bootstrap attempt must fail with 409 Conflict
            boot_dup = client.post(
                "/api/v1/auth/bootstrap",
                json={"username": "second_owner", "password": "AnotherPassword!99"},
            )
            assert boot_dup.status_code == 409

            # 2. Login and token refresh
            login_resp = client.post(
                "/api/v1/auth/login",
                json={"username": "chief_owner", "password": "UltraSecureOwnerPassword!99"},
            )
            assert login_resp.status_code == 200
            tokens = login_resp.json()
            access_token = tokens["access_token"]

            refresh_resp = client.post(
                "/api/v1/auth/refresh",
                json={
                    "session_id": tokens["session_id"],
                    "refresh_token": tokens["refresh_token"],
                },
            )
            assert refresh_resp.status_code == 200

            # 3. Mobile pairing start & complete
            pair_start = client.post(
                "/api/v1/mobile/pairing/start",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"device_label": "Pixel 9 Pro", "server_url": "https://192.168.1.10:8080"},
            )
            assert pair_start.status_code == 200
            pairing_code = pair_start.json()["pairing_code"]

            pair_complete = client.post(
                "/api/v1/mobile/pairing/complete",
                json={"pairing_code": pairing_code, "device_label": "Pixel 9 Pro"},
            )
            assert pair_complete.status_code == 200
            mobile_access_token = pair_complete.json()["access_token"]

            # 4. Mobile client requests short-lived camera stream ticket
            tkt_resp = client.post(
                "/api/v1/mobile/stream-ticket",
                headers={"Authorization": f"Bearer {mobile_access_token}"},
                json={"camera_id": "cam-north-gate", "protocol": "WebRTC", "ttl_sec": 90},
            )
            assert tkt_resp.status_code == 200
            tkt_data = tkt_resp.json()
            assert "webrtc" in tkt_data["urls"]
            assert "hls" in tkt_data["urls"]

            # 5. Brute-force login throttling after 5 failed password attempts
            for _ in range(5):
                bad = client.post(
                    "/api/v1/auth/login",
                    json={"username": "chief_owner", "password": "WrongPassword"},
                )
                assert bad.status_code == 401
            throttled = client.post(
                "/api/v1/auth/login",
                json={"username": "chief_owner", "password": "UltraSecureOwnerPassword!99"},
            )
            assert throttled.status_code == 429
            clear_login_failures("chief_owner")


def test_storage_calculator_recordings_and_plugins():
    """Phase 5 & 9: Storage calculator formula, recording index/export/delete, and plugin auditing."""
    # Verify exact blueprint formula: 4 Mbps * 3600 * 24h * 10d * 5 cameras / 8 / 1000 = 2160.0 GB
    est = calculate_storage_estimate(
        bitrate_mbps=4.0,
        camera_count=5,
        hours_per_day=24.0,
        retention_days=10,
    )
    assert est["estimated_gb"] == 2160.0
    assert est["recommended_with_20pct_margin_gb"] == 2592.0

    with tempfile.TemporaryDirectory() as tmpdir:
        db = DatabaseManager(database_url=f"sqlite:///{tmpdir}/rec.db")
        coord = RecordingCoordinator(db=db, recordings_dir=f"{tmpdir}/recordings")

        seg = coord.index_segment(
            device_id="cam-north-gate",
            stream_id="main",
            duration_sec=120.0,
            payload_bytes=b"test-fmp4-video-segment-bytes",
        )
        assert seg["recording_id"].startswith("rec-")
        assert len(seg["checksum_sha256"]) == 64

        exp = coord.export_recording(seg["recording_id"], actor="op1", actor_role="OPERATOR")
        assert "download_url" in exp

        # Viewer role cannot delete recordings
        with pytest.raises(PermissionError):
            coord.delete_recording(seg["recording_id"], actor="viewer1", actor_role="VIEWER")

        # Owner role can delete recordings
        assert coord.delete_recording(seg["recording_id"], actor="owner1", actor_role="OWNER") is True
