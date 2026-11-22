"""Plugin Manager and Standard Adapter Interface for ONVIF, RTSP, NVR/DVR, MQTT, and Home Assistant."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from shared.audit import record_audit_event
from shared.database import DatabaseManager, get_db


class BaseIntegrationAdapter(ABC):
    """
    Standard adapter contract defined in Section 9 of the Ultra Master Blueprint:
    discover(), identify(), enroll(), get_status(), get_capabilities(), execute(), health_check()
    """

    plugin_id: str = "base-adapter"

    @abstractmethod
    def discover(self, scope_cidr: str) -> List[Dict[str, Any]]:
        """Discover devices strictly within an approved site/scope."""

    @abstractmethod
    def identify(self, target_ip: str) -> Dict[str, Any]:
        """Return capability and vendor/model metadata without credential guessing."""

    @abstractmethod
    def enroll(self, target_ip: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """Validate operator-provided credentials against an approved target."""

    @abstractmethod
    def get_status(self, device_id: str) -> Dict[str, Any]:
        """Poll current operational status."""

    @abstractmethod
    def get_capabilities(self, device_id: str) -> Dict[str, Any]:
        """Describe supported profiles and controls."""

    @abstractmethod
    def execute(self, device_id: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform an explicitly permitted control action (e.g., ONVIF PTZ or IoT relay)."""

    @abstractmethod
    def health_check(self) -> Dict[str, str]:
        """Report adapter health."""


class NVRChannelAdapter(BaseIntegrationAdapter):
    """Maps multi-channel NVR/DVR RTSP stream templates for authorized NVR devices."""

    plugin_id = "nvr-channel-mapper"

    def discover(self, scope_cidr: str) -> List[Dict[str, Any]]:
        return []

    def identify(self, target_ip: str) -> Dict[str, Any]:
        return {"ip_address": target_ip, "type": "NVR", "max_channels": 16}

    def enroll(self, target_ip: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        channels = int(credentials.get("channels", "4"))
        vendor = credentials.get("vendor", "hikvision").lower()
        endpoints = []
        for ch in range(1, channels + 1):
            if vendor == "dahua":
                path = f"/cam/realmonitor?channel={ch}&subtype=0"
            else:
                path = f"/Streaming/Channels/{ch}01"
            endpoints.append(
                {
                    "channel": ch,
                    "rtsp_template": f"rtsp://{target_ip}:554{path}",
                }
            )
        return {"ip_address": target_ip, "vendor": vendor, "channels": endpoints}

    def get_status(self, device_id: str) -> Dict[str, Any]:
        return {"device_id": device_id, "status": "ONLINE"}

    def get_capabilities(self, device_id: str) -> Dict[str, Any]:
        return {"multi_channel": True, "edge_playback": True}

    def execute(self, device_id: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"device_id": device_id, "action": action, "status": "EXECUTED"}

    def health_check(self) -> Dict[str, str]:
        return {"plugin_id": self.plugin_id, "status": "HEALTHY"}


class PluginManager:
    """Manages persistent adapter plugins, permission policies, and enable/disable auditing."""

    def __init__(self, db: Optional[DatabaseManager] = None) -> None:
        self.db = db or get_db()
        self._adapters: Dict[str, BaseIntegrationAdapter] = {
            NVRChannelAdapter.plugin_id: NVRChannelAdapter(),
        }

    def list_plugins(self) -> List[Dict[str, Any]]:
        rows = self.db.fetchall("SELECT * FROM plugins ORDER BY plugin_id ASC")
        for r in rows:
            r["permissions"] = json.loads(r.pop("permissions_json", "[]") or "[]")
            r["enabled"] = bool(r.get("enabled", 0))
        return rows

    def set_plugin_enabled(
        self,
        plugin_id: str,
        enabled: bool,
        actor: str = "owner",
        actor_role: str = "ADMIN",
    ) -> Dict[str, Any]:
        row = self.db.fetchone(
            "SELECT * FROM plugins WHERE plugin_id = ?", (plugin_id,)
        )
        if not row:
            raise KeyError(f"Plugin '{plugin_id}' not found.")

        self.db.execute(
            "UPDATE plugins SET enabled = ? WHERE plugin_id = ?",
            (1 if enabled else 0, plugin_id),
        )
        record_audit_event(
            action="PLUGIN_ENABLED" if enabled else "PLUGIN_DISABLED",
            target_type="PLUGIN",
            target_id=plugin_id,
            actor=actor,
            actor_role=actor_role,
            details={"name": row["name"], "enabled": enabled},
            db=self.db,
        )
        updated = self.db.fetchone(
            "SELECT * FROM plugins WHERE plugin_id = ?", (plugin_id,)
        )
        assert updated is not None
        updated["permissions"] = json.loads(updated.pop("permissions_json", "[]") or "[]")
        updated["enabled"] = bool(updated.get("enabled", 0))
        return updated
