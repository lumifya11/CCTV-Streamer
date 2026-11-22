"""Durable Device Registry with immutable UUID identities, IP/MAC history, and candidate approval."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from shared.audit import record_audit_event
from shared.database import DatabaseManager, get_db
from shared.models import (
    CameraDevice,
    CompatibilityTier,
    DeviceLifecycleState,
    RTSPEndpoint,
    utc_now_iso,
)
from shared.security import sanitize_uri_template, validate_subnet_cidr


class DurableDeviceRegistry:
    """
    Manages persistent Sites, approved NetworkScopes, and Devices in SQLite/PostgreSQL.
    Uses immutable UUIDs as primary identity and tracks IP/MAC/hostname history.
    """

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db = db or get_db()

    # --- Sites & Approved Network Scopes ---

    def list_sites(self) -> List[Dict[str, Any]]:
        return self.db.fetchall("SELECT * FROM sites ORDER BY created_at ASC")

    def create_site(
        self,
        name: str,
        description: str = "",
        location: str = "Main Facility",
        created_by: str = "owner",
    ) -> Dict[str, Any]:
        site_id = f"site-{uuid.uuid4().hex[:10]}"
        now = utc_now_iso()
        self.db.execute(
            """
            INSERT INTO sites (site_id, name, description, location, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (site_id, name.strip(), description.strip(), location.strip(), created_by, now),
        )
        record_audit_event(
            action="SITE_CREATED",
            target_type="SITE",
            target_id=site_id,
            actor=created_by,
            actor_role="ADMIN",
            details={"name": name, "location": location},
            db=self.db,
        )
        return {
            "site_id": site_id,
            "name": name.strip(),
            "description": description.strip(),
            "location": location.strip(),
            "created_by": created_by,
            "created_at": now,
        }

    def list_scopes(self, site_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if site_id:
            rows = self.db.fetchall(
                "SELECT * FROM network_scopes WHERE site_id = ? ORDER BY approved_at ASC",
                (site_id,),
            )
        else:
            rows = self.db.fetchall("SELECT * FROM network_scopes ORDER BY approved_at ASC")
        for r in rows:
            r["allowed_methods"] = json.loads(r.pop("allowed_methods_json", "[]") or "[]")
            r["allowed_ports"] = json.loads(r.pop("allowed_ports_json", "[]") or "[]")
            r["onvif_multicast_enabled"] = bool(r.get("onvif_multicast_enabled", 1))
            r["active"] = bool(r.get("active", 1))
        return rows

    def get_approved_cidrs(self, site_id: Optional[str] = None) -> List[str]:
        scopes = self.list_scopes(site_id=site_id)
        return [s["cidr"] for s in scopes if s.get("active")]

    def create_scope(
        self,
        site_id: str,
        cidr: str,
        vlan_label: str = "Camera VLAN",
        approved_by: str = "owner",
        allowed_methods: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        max_hosts: int = 256,
        rate_limit_per_sec: int = 64,
        onvif_multicast_enabled: bool = True,
    ) -> Dict[str, Any]:
        # Validate that CIDR is a safe private/local range within host bounds
        net = validate_subnet_cidr(cidr, max_hosts=max_hosts, allow_public=False)
        normalized_cidr = str(net)
        scope_id = f"scope-{uuid.uuid4().hex[:10]}"
        methods = allowed_methods or ["onvif", "rtsp_probe", "mdns", "ssdp"]
        ports = allowed_ports or [554, 8554, 80, 8000, 8080, 8899]
        now = utc_now_iso()

        self.db.execute(
            """
            INSERT INTO network_scopes (
                scope_id, site_id, cidr, vlan_label, approved_by,
                allowed_methods_json, allowed_ports_json, max_hosts,
                rate_limit_per_sec, onvif_multicast_enabled, approved_at, active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                scope_id,
                site_id,
                normalized_cidr,
                vlan_label,
                approved_by,
                json.dumps(methods),
                json.dumps(ports),
                max_hosts,
                rate_limit_per_sec,
                1 if onvif_multicast_enabled else 0,
                now,
            ),
        )
        record_audit_event(
            action="NETWORK_SCOPE_APPROVED",
            target_type="NETWORK_SCOPE",
            target_id=scope_id,
            actor=approved_by,
            actor_role="OWNER",
            details={"site_id": site_id, "cidr": normalized_cidr, "max_hosts": max_hosts},
            db=self.db,
        )
        return {
            "scope_id": scope_id,
            "site_id": site_id,
            "cidr": normalized_cidr,
            "vlan_label": vlan_label,
            "approved_by": approved_by,
            "allowed_methods": methods,
            "allowed_ports": ports,
            "max_hosts": max_hosts,
            "rate_limit_per_sec": rate_limit_per_sec,
            "onvif_multicast_enabled": onvif_multicast_enabled,
            "approved_at": now,
            "active": True,
        }

    # --- Device Identity & Candidate Management ---

    def _find_existing_device_row(
        self,
        ip_address: str,
        onvif_uuid: Optional[str] = None,
        serial_number: Optional[str] = None,
        mac_address: Optional[str] = None,
        explicit_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Match device by immutable ID, ONVIF UUID, serial number, MAC address, or current IP."""
        if explicit_id:
            row = self.db.fetchone(
                "SELECT * FROM devices WHERE device_id = ?", (explicit_id,)
            )
            if row:
                return row
        if onvif_uuid:
            row = self.db.fetchone(
                "SELECT * FROM devices WHERE onvif_uuid = ?", (onvif_uuid,)
            )
            if row:
                return row
        if serial_number:
            row = self.db.fetchone(
                "SELECT * FROM devices WHERE serial_number = ?", (serial_number,)
            )
            if row:
                return row
        if mac_address:
            row = self.db.fetchone(
                "SELECT * FROM devices WHERE mac_address = ?", (mac_address,)
            )
            if row:
                return row
        return self.db.fetchone(
            "SELECT * FROM devices WHERE primary_ip = ?", (ip_address,)
        )

    def upsert_discovered_device(
        self,
        camera: CameraDevice,
        onvif_uuid: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> CameraDevice:
        """
        Persist or update a discovered camera candidate.
        If the device already exists (by ONVIF UUID/serial/MAC/ID) and changed IP via DHCP,
        updates its `primary_ip` and appends to `device_addresses` history!
        """
        existing = self._find_existing_device_row(
            ip_address=camera.ip_address,
            onvif_uuid=onvif_uuid,
            serial_number=camera.serial_number,
            mac_address=camera.mac_address,
            explicit_id=camera.camera_id if camera.camera_id.startswith(("dev-", "cam-")) else None,
        )
        now = utc_now_iso()
        sanitized_primary = (
            sanitize_uri_template(camera.primary_rtsp_url)
            if camera.primary_rtsp_url
            else None
        )
        endpoints_dicts = [
            {
                **ep.model_dump(),
                "url": sanitize_uri_template(ep.url),
            }
            for ep in camera.rtsp_endpoints
        ]

        if existing:
            device_id = existing["device_id"]
            old_ip = existing["primary_ip"]
            updated_xaddr = camera.onvif_xaddr
            if updated_xaddr and old_ip != camera.ip_address and old_ip in updated_xaddr:
                updated_xaddr = updated_xaddr.replace(old_ip, camera.ip_address)
            # Preserve approval and higher lifecycle states across re-discovery scans
            approved = bool(existing["approved"]) or camera.approved
            current_state = existing["lifecycle_state"]
            if current_state in (
                DeviceLifecycleState.USER_APPROVED.value,
                DeviceLifecycleState.CREDENTIALS_CONFIGURED.value,
                DeviceLifecycleState.CONNECTION_VERIFIED.value,
                DeviceLifecycleState.STREAM_VERIFIED.value,
                DeviceLifecycleState.ONLINE.value,
                DeviceLifecycleState.REJECTED.value,
            ):
                new_state = current_state
            else:
                new_state = camera.lifecycle_state.value

            self.db.execute(
                """
                UPDATE devices
                SET primary_ip = ?,
                    mac_address = COALESCE(?, mac_address),
                    hostname = COALESCE(?, hostname),
                    open_ports_json = ?,
                    onvif_supported = ?,
                    onvif_xaddr = COALESCE(?, onvif_xaddr),
                    rtsp_endpoints_json = ?,
                    primary_rtsp_url = COALESCE(?, primary_rtsp_url),
                    discovered_methods_json = ?,
                    lifecycle_state = ?,
                    approved = ?,
                    latency_ms = ?,
                    last_seen = ?,
                    online = ?
                WHERE device_id = ?
                """,
                (
                    camera.ip_address,
                    camera.mac_address,
                    camera.hostname,
                    json.dumps(camera.open_ports),
                    1 if camera.onvif_supported else 0,
                    updated_xaddr,
                    json.dumps(endpoints_dicts),
                    sanitized_primary,
                    json.dumps(camera.discovered_via),
                    new_state,
                    1 if approved else 0,
                    camera.latency_ms,
                    now,
                    1 if camera.online else 0,
                    device_id,
                ),
            )
        else:
            device_id = (
                camera.camera_id
                if camera.camera_id and not camera.camera_id.startswith("cam-ip-")
                else f"dev-{uuid.uuid4().hex[:12]}"
            )
            self.db.execute(
                """
                INSERT INTO devices (
                    device_id, site_id, scope_id, name, device_type,
                    compatibility_tier, lifecycle_state, manufacturer, model,
                    firmware_version, serial_number, onvif_uuid, primary_ip,
                    mac_address, hostname, location, open_ports_json,
                    onvif_supported, onvif_xaddr, rtsp_endpoints_json,
                    primary_rtsp_url, discovered_methods_json, evidence_json,
                    confidence, credential_profile_id, approved, approved_by,
                    approved_at, latency_ms, last_seen, online
                )
                VALUES (?, ?, ?, ?, 'CAMERA', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    camera.site_id,
                    camera.scope_id,
                    camera.name,
                    camera.compatibility_tier.value,
                    camera.lifecycle_state.value,
                    camera.manufacturer,
                    camera.model,
                    camera.firmware_version,
                    camera.serial_number,
                    onvif_uuid,
                    camera.ip_address,
                    camera.mac_address,
                    camera.hostname,
                    camera.location,
                    json.dumps(camera.open_ports),
                    1 if camera.onvif_supported else 0,
                    camera.onvif_xaddr,
                    json.dumps(endpoints_dicts),
                    sanitized_primary,
                    json.dumps(camera.discovered_via),
                    json.dumps(evidence or {}),
                    camera.confidence,
                    camera.credential_profile_id,
                    1 if camera.approved else 0,
                    camera.approved_by,
                    now if camera.approved else None,
                    camera.latency_ms,
                    now,
                    1 if camera.online else 0,
                ),
            )

        # Record IP/MAC history in device_addresses
        addr_row = self.db.fetchone(
            "SELECT id FROM device_addresses WHERE device_id = ? AND ip_address = ?",
            (device_id, camera.ip_address),
        )
        if addr_row:
            self.db.execute(
                "UPDATE device_addresses SET last_seen = ?, mac_address = COALESCE(?, mac_address), hostname = COALESCE(?, hostname) WHERE id = ?",
                (now, camera.mac_address, camera.hostname, addr_row["id"]),
            )
        else:
            self.db.execute(
                """
                INSERT INTO device_addresses (device_id, ip_address, mac_address, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (device_id, camera.ip_address, camera.mac_address, camera.hostname, now, now),
            )

        res = self.get_device(device_id)
        assert res is not None
        return res

    def _row_to_camera_device(self, row: Dict[str, Any]) -> CameraDevice:
        raw_eps = json.loads(row.get("rtsp_endpoints_json", "[]") or "[]")
        endpoints = [RTSPEndpoint(**ep) for ep in raw_eps]
        cap_row = self.db.fetchone(
            "SELECT * FROM camera_capabilities WHERE device_id = ?",
            (row["device_id"],),
        )
        onvif_profiles = (
            json.loads(cap_row["onvif_profiles_json"])
            if cap_row and cap_row.get("onvif_profiles_json")
            else (["Profile_T"] if row.get("onvif_supported") else [])
        )
        legacy_s = bool(cap_row["legacy_profile_s"]) if cap_row else False

        return CameraDevice(
            camera_id=row["device_id"],
            site_id=row.get("site_id", "site-default"),
            scope_id=row.get("scope_id"),
            name=row["name"],
            ip_address=row["primary_ip"],
            mac_address=row.get("mac_address"),
            hostname=row.get("hostname"),
            open_ports=json.loads(row.get("open_ports_json", "[]") or "[]"),
            onvif_supported=bool(row.get("onvif_supported", 0)),
            onvif_xaddr=row.get("onvif_xaddr"),
            onvif_profiles=onvif_profiles,
            legacy_profile_s=legacy_s,
            compatibility_tier=CompatibilityTier(
                row.get("compatibility_tier", CompatibilityTier.TIER_1_STANDARDS.value)
            ),
            lifecycle_state=DeviceLifecycleState(
                row.get("lifecycle_state", DeviceLifecycleState.CAMERA_CANDIDATE.value)
            ),
            confidence=float(row.get("confidence", 0.75)),
            manufacturer=row.get("manufacturer", "Generic"),
            model=row.get("model", "IP Camera"),
            firmware_version=row.get("firmware_version"),
            serial_number=row.get("serial_number"),
            location=row.get("location", "Sector A"),
            rtsp_endpoints=endpoints,
            primary_rtsp_url=row.get("primary_rtsp_url"),
            credential_profile_id=row.get("credential_profile_id"),
            approved=bool(row.get("approved", 0)),
            approved_by=row.get("approved_by"),
            latency_ms=float(row.get("latency_ms", 0.0)),
            discovered_via=json.loads(row.get("discovered_methods_json", "[]") or "[]"),
            last_seen=row.get("last_seen", utc_now_iso()),
            online=bool(row.get("online", 1)),
        )

    def get_device(self, device_id: str) -> Optional[CameraDevice]:
        row = self.db.fetchone(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        )
        return self._row_to_camera_device(row) if row else None

    def get_address_history(self, device_id: str) -> List[Dict[str, Any]]:
        return self.db.fetchall(
            "SELECT * FROM device_addresses WHERE device_id = ? ORDER BY last_seen DESC",
            (device_id,),
        )

    def list_devices(
        self,
        site_id: Optional[str] = None,
        approved_only: bool = False,
        candidates_only: bool = False,
    ) -> List[CameraDevice]:
        query = "SELECT * FROM devices WHERE 1=1"
        params: List[Any] = []
        if site_id:
            query += " AND site_id = ?"
            params.append(site_id)
        if approved_only:
            query += " AND approved = 1"
        if candidates_only:
            query += " AND approved = 0 AND lifecycle_state != 'REJECTED'"
        query += " ORDER BY last_seen DESC"
        rows = self.db.fetchall(query, tuple(params))
        return [self._row_to_camera_device(r) for r in rows]

    def approve_candidate(
        self, device_id: str, approved_by: str = "owner"
    ) -> CameraDevice:
        row = self.db.fetchone(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        )
        if not row:
            raise KeyError(f"Device candidate '{device_id}' not found.")
        now = utc_now_iso()
        next_state = (
            row["lifecycle_state"]
            if row["lifecycle_state"]
            in (
                DeviceLifecycleState.CREDENTIALS_CONFIGURED.value,
                DeviceLifecycleState.CONNECTION_VERIFIED.value,
                DeviceLifecycleState.STREAM_VERIFIED.value,
                DeviceLifecycleState.ONLINE.value,
            )
            else DeviceLifecycleState.USER_APPROVED.value
        )
        self.db.execute(
            """
            UPDATE devices
            SET approved = 1, approved_by = ?, approved_at = ?, lifecycle_state = ?
            WHERE device_id = ?
            """,
            (approved_by, now, next_state, device_id),
        )
        record_audit_event(
            action="DEVICE_CANDIDATE_APPROVED",
            target_type="DEVICE",
            target_id=device_id,
            actor=approved_by,
            actor_role="ADMIN",
            details={"ip": row["primary_ip"], "name": row["name"]},
            db=self.db,
        )
        dev = self.get_device(device_id)
        assert dev is not None
        return dev

    def reject_candidate(
        self, device_id: str, rejected_by: str = "owner"
    ) -> CameraDevice:
        row = self.db.fetchone(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        )
        if not row:
            raise KeyError(f"Device candidate '{device_id}' not found.")
        self.db.execute(
            """
            UPDATE devices
            SET approved = 0, lifecycle_state = ?
            WHERE device_id = ?
            """,
            (DeviceLifecycleState.REJECTED.value, device_id),
        )
        record_audit_event(
            action="DEVICE_CANDIDATE_REJECTED",
            target_type="DEVICE",
            target_id=device_id,
            actor=rejected_by,
            actor_role="ADMIN",
            db=self.db,
        )
        dev = self.get_device(device_id)
        assert dev is not None
        return dev

    def delete_device(self, device_id: str, actor: str = "owner") -> bool:
        row = self.db.fetchone(
            "SELECT device_id FROM devices WHERE device_id = ?", (device_id,)
        )
        if not row:
            return False
        self.db.execute("DELETE FROM device_addresses WHERE device_id = ?", (device_id,))
        self.db.execute("DELETE FROM camera_capabilities WHERE device_id = ?", (device_id,))
        self.db.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        record_audit_event(
            action="DEVICE_DELETED",
            target_type="DEVICE",
            target_id=device_id,
            actor=actor,
            actor_role="ADMIN",
            db=self.db,
        )
        return True
