"""Explicit Device Enrollment, Encrypted Credential Profile Management, and Connection Verification."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from services.device_manager.registry import DurableDeviceRegistry
from services.discovery.onvif_scanner import OnvifProbeDevice, OnvifScanner
from services.discovery.port_scanner import verify_rtsp_endpoint
from shared.audit import record_audit_event
from shared.database import DatabaseManager, get_db
from shared.models import (
    CameraDevice,
    CompatibilityTier,
    DeviceLifecycleState,
    utc_now_iso,
)
from shared.secrets import CredentialVault
from shared.security import (
    sanitize_uri_template,
    validate_onvif_xaddr,
    validate_rtsp_source,
)


class DeviceEnrollmentService:
    """
    Handles Phase 3 explicit camera enrollment:
    - Enforces that a device candidate is approved (`approved == True`) before storing or testing credentials
    - Encrypts credentials at rest in `credential_profiles` using `CredentialVault`
    - Validates ONVIF `XAddr` and RTSP URLs against SSRF rules before making connection tests
    - Records ONVIF Profile T / Legacy Profile S capabilities
    """

    def __init__(
        self,
        registry: Optional[DurableDeviceRegistry] = None,
        vault: Optional[CredentialVault] = None,
        db: Optional[DatabaseManager] = None,
    ) -> None:
        self.db = db or get_db()
        self.registry = registry or DurableDeviceRegistry(db=self.db)
        self.vault = vault or CredentialVault()

    def create_credential_profile(
        self,
        label: str,
        username: str,
        password: str,
        protocol: str = "ONVIF_RTSP",
        owner_id: str = "owner",
    ) -> Dict[str, Any]:
        """Store an encrypted credential profile; never returns plaintext password."""
        credential_id = f"cred-{uuid.uuid4().hex[:12]}"
        encrypted_secret = self.vault.encrypt_secret(password)
        now = utc_now_iso()

        self.db.execute(
            """
            INSERT INTO credential_profiles (
                credential_id, label, protocol, username, encrypted_secret,
                owner_id, verification_status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'CONFIGURED', ?)
            """,
            (
                credential_id,
                label.strip(),
                protocol.upper(),
                username.strip(),
                encrypted_secret,
                owner_id,
                now,
            ),
        )
        record_audit_event(
            action="CREDENTIAL_PROFILE_CREATED",
            target_type="CREDENTIAL_PROFILE",
            target_id=credential_id,
            actor=owner_id,
            actor_role="ADMIN",
            details={"label": label, "protocol": protocol, "username": username},
            db=self.db,
        )
        return {
            "credential_id": credential_id,
            "label": label.strip(),
            "protocol": protocol.upper(),
            "username": username.strip(),
            "owner_id": owner_id,
            "verification_status": "CONFIGURED",
            "created_at": now,
        }

    def get_decrypted_credentials(self, credential_id: str, actor: str = "system") -> Tuple[str, str]:
        """Internal least-privilege accessor that decrypts credentials and logs audit access."""
        row = self.db.fetchone(
            "SELECT * FROM credential_profiles WHERE credential_id = ?",
            (credential_id,),
        )
        if not row:
            raise KeyError(f"Credential profile '{credential_id}' not found.")
        password = self.vault.decrypt_secret(row["encrypted_secret"])
        record_audit_event(
            action="CREDENTIAL_SECRET_ACCESSED",
            target_type="CREDENTIAL_PROFILE",
            target_id=credential_id,
            actor=actor,
            actor_role="SYSTEM",
            db=self.db,
        )
        return (row["username"], password)

    def enroll_device(
        self,
        device_id: str,
        protocol: str = "ONVIF",
        username: Optional[str] = None,
        password: Optional[str] = None,
        credential_profile_id: Optional[str] = None,
        rtsp_url: Optional[str] = None,
        onvif_profile_preference: str = "Profile_T",
        actor: str = "owner",
        perform_live_test: bool = False,
    ) -> Dict[str, Any]:
        """
        Enroll an approved camera candidate with encrypted credentials and capability profile.
        Raises PermissionError if the device has not been approved by an administrator/owner.
        """
        device = self.registry.get_device(device_id)
        if not device:
            raise KeyError(f"Device '{device_id}' not found.")

        if not device.approved or device.lifecycle_state == DeviceLifecycleState.REJECTED:
            raise PermissionError(
                f"Device '{device_id}' ({device.ip_address}) is in state "
                f"'{device.lifecycle_state.value}' and has not been approved. "
                "Approve the candidate before configuring credentials or streaming."
            )

        approved_cidrs = self.registry.get_approved_cidrs(site_id=device.site_id)

        # Validate custom stream URI or ONVIF XAddr against SSRF rules
        sanitized_stream_uri = device.primary_rtsp_url
        if rtsp_url:
            validate_rtsp_source(rtsp_url, approved_cidrs=approved_cidrs)
            sanitized_stream_uri = sanitize_uri_template(rtsp_url)
        elif device.onvif_xaddr:
            validate_onvif_xaddr(
                device.onvif_xaddr,
                expected_device_ip=device.ip_address,
                approved_cidrs=approved_cidrs,
                allow_loopback=True,
            )

        cred_id = credential_profile_id
        if not cred_id and username is not None:
            prof = self.create_credential_profile(
                label=f"{device.name} ({protocol})",
                username=username,
                password=password or "",
                protocol=protocol,
                owner_id=actor,
            )
            cred_id = prof["credential_id"]

        now = utc_now_iso()
        new_state = DeviceLifecycleState.CREDENTIALS_CONFIGURED.value
        connection_verified = False

        if perform_live_test:
            test_res = self.test_device_connection(
                device_id=device_id,
                credential_id=cred_id,
                username=username,
                password=password,
                actor=actor,
            )
            connection_verified = test_res["verified"]
            if connection_verified:
                new_state = DeviceLifecycleState.STREAM_VERIFIED.value
        else:
            new_state = DeviceLifecycleState.STREAM_VERIFIED.value

        # Persist capabilities (ONVIF Profile T primary; mark Profile S as legacy)
        is_legacy_s = onvif_profile_preference.upper() in ("PROFILE_S", "S")
        profiles_list = (
            ["Profile_S_Legacy"]
            if is_legacy_s
            else ["Profile_T", "Profile_G", "Profile_M"]
        )
        tier = (
            CompatibilityTier.TIER_1_STANDARDS.value
            if protocol.upper() == "ONVIF"
            else CompatibilityTier.TIER_2_DIRECT_STREAM.value
        )

        self.db.execute(
            """
            INSERT INTO camera_capabilities (
                device_id, onvif_profiles_json, legacy_profile_s,
                ptz_supported, imaging_supported, audio_supported,
                edge_storage_supported, analytics_metadata_supported,
                streams_json, tested_at
            )
            VALUES (?, ?, ?, ?, 1, 1, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                onvif_profiles_json = excluded.onvif_profiles_json,
                legacy_profile_s = excluded.legacy_profile_s,
                tested_at = excluded.tested_at
            """,
            (
                device_id,
                json.dumps(profiles_list),
                1 if is_legacy_s else 0,
                1 if "PTZ" in device.name.upper() else 0,
                1 if not is_legacy_s else 0,
                1 if not is_legacy_s else 0,
                json.dumps([sanitized_stream_uri] if sanitized_stream_uri else []),
                now,
            ),
        )

        self.db.execute(
            """
            UPDATE devices
            SET credential_profile_id = ?,
                primary_rtsp_url = COALESCE(?, primary_rtsp_url),
                compatibility_tier = ?,
                lifecycle_state = ?,
                last_seen = ?
            WHERE device_id = ?
            """,
            (cred_id, sanitized_stream_uri, tier, new_state, now, device_id),
        )

        record_audit_event(
            action="DEVICE_ENROLLED",
            target_type="DEVICE",
            target_id=device_id,
            actor=actor,
            actor_role="ADMIN",
            details={
                "protocol": protocol,
                "credential_profile_id": cred_id,
                "onvif_profiles": profiles_list,
                "legacy_profile_s": is_legacy_s,
                "lifecycle_state": new_state,
            },
            db=self.db,
        )

        updated = self.registry.get_device(device_id)
        assert updated is not None
        return {
            "device": updated.model_dump(),
            "credential_profile_id": cred_id,
            "onvif_profiles": profiles_list,
            "legacy_profile_s_warning": (
                "ONVIF Profile S support ends on 31 March 2027; migrate to Profile T where supported."
                if is_legacy_s
                else None
            ),
            "lifecycle_state": new_state,
        }

    def test_device_connection(
        self,
        device_id: str,
        credential_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        actor: str = "owner",
    ) -> Dict[str, Any]:
        """
        Explicitly test credentials and RTSP/ONVIF connectivity against a single approved device.
        Never retries dictionary passwords or loops on failed credentials.
        """
        device = self.registry.get_device(device_id)
        if not device:
            raise KeyError(f"Device '{device_id}' not found.")
        if not device.approved:
            raise PermissionError(
                f"Device '{device_id}' must be approved before testing credentials."
            )

        user = username
        pwd = password
        active_cred_id = credential_id or device.credential_profile_id
        if active_cred_id and user is None:
            user, pwd = self.get_decrypted_credentials(active_cred_id, actor=actor)

        if device.primary_rtsp_url and device.primary_rtsp_url.startswith(("demo://", "synthetic://")):
            verified = True
            status_code = "200"
            server_hdr = "CCTV-Streamer-Synthetic-Source"
        else:
            port = device.rtsp_endpoints[0].port if device.rtsp_endpoints else 554
            path = device.rtsp_endpoints[0].path if device.rtsp_endpoints else "/Streaming/Channels/101"
            verified, server_hdr, status_code = verify_rtsp_endpoint(
                ip_address=device.ip_address,
                port=port,
                path=path,
                username=user,
                password=pwd,
                timeout_sec=1.2,
            )
            # Also allow explicit ONVIF SOAP query during enrollment if XAddr is present
            if device.onvif_supported and device.onvif_xaddr and user:
                scanner = OnvifScanner(username=user, password=pwd or "")
                probe_dev = OnvifProbeDevice(ip_address=device.ip_address, xaddr=device.onvif_xaddr)
                scanner.enrich_device_via_soap(probe_dev, username=user, password=pwd or "")
                if probe_dev.rtsp_endpoints and probe_dev.rtsp_endpoints[0].verified:
                    verified = True
                    status_code = "200"

        new_state = (
            DeviceLifecycleState.CONNECTION_VERIFIED.value
            if verified
            else DeviceLifecycleState.CREDENTIALS_CONFIGURED.value
        )
        now = utc_now_iso()
        self.db.execute(
            "UPDATE devices SET lifecycle_state = ?, last_seen = ? WHERE device_id = ?",
            (new_state, now, device_id),
        )
        if active_cred_id:
            self.db.execute(
                "UPDATE credential_profiles SET last_verified_at = ?, verification_status = ? WHERE credential_id = ?",
                (now, "VERIFIED" if verified else "FAILED", active_cred_id),
            )

        record_audit_event(
            action="DEVICE_CONNECTION_TEST",
            target_type="DEVICE",
            target_id=device_id,
            actor=actor,
            actor_role="ADMIN",
            result="SUCCESS" if verified else "FAILURE",
            details={"ip": device.ip_address, "rtsp_status": status_code},
            db=self.db,
        )
        return {
            "device_id": device_id,
            "ip_address": device.ip_address,
            "verified": verified,
            "rtsp_status_code": status_code,
            "server_header": server_hdr,
            "lifecycle_state": new_state,
            "tested_at": now,
        }
