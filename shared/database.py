"""Durable SQLite / Relational Database Manager for CCTV-Streamer Registry, Events, Recordings, and Audit."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.config import get_config
from shared.logger import get_logger
from shared.models import utc_now_iso

logger = get_logger("shared.database")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'VIEWER',
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret_enc TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT 'web',
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT 'Primary LAN',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_scopes (
    scope_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    cidr TEXT NOT NULL,
    vlan_label TEXT NOT NULL DEFAULT 'Default VLAN',
    approved_by TEXT NOT NULL DEFAULT 'owner',
    allowed_methods_json TEXT NOT NULL DEFAULT '["onvif","rtsp_probe"]',
    allowed_ports_json TEXT NOT NULL DEFAULT '[554,8554,80,8000,8080,8899]',
    max_hosts INTEGER NOT NULL DEFAULT 256,
    rate_limit_per_sec INTEGER NOT NULL DEFAULT 64,
    onvif_multicast_enabled INTEGER NOT NULL DEFAULT 1,
    approved_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS site_agents (
    agent_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.1.0',
    cert_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ONLINE',
    last_heartbeat TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discovery_jobs (
    job_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    scope_ids_json TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    hosts_checked INTEGER NOT NULL DEFAULT 0,
    candidates_found INTEGER NOT NULL DEFAULT 0,
    errors_count INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL DEFAULT 'site-default',
    scope_id TEXT,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'CAMERA',
    compatibility_tier TEXT NOT NULL DEFAULT 'TIER_1_STANDARDS',
    lifecycle_state TEXT NOT NULL DEFAULT 'CAMERA_CANDIDATE',
    manufacturer TEXT NOT NULL DEFAULT 'Generic',
    model TEXT NOT NULL DEFAULT 'IP Camera',
    firmware_version TEXT,
    serial_number TEXT,
    onvif_uuid TEXT,
    primary_ip TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    location TEXT NOT NULL DEFAULT 'Sector A',
    open_ports_json TEXT NOT NULL DEFAULT '[]',
    onvif_supported INTEGER NOT NULL DEFAULT 0,
    onvif_xaddr TEXT,
    rtsp_endpoints_json TEXT NOT NULL DEFAULT '[]',
    primary_rtsp_url TEXT,
    discovered_methods_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    confidence REAL NOT NULL DEFAULT 0.75,
    credential_profile_id TEXT,
    approved INTEGER NOT NULL DEFAULT 0,
    approved_by TEXT,
    approved_at TEXT,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    last_seen TEXT NOT NULL,
    online INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS device_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS camera_capabilities (
    device_id TEXT PRIMARY KEY,
    onvif_profiles_json TEXT NOT NULL DEFAULT '["Profile_T"]',
    legacy_profile_s INTEGER NOT NULL DEFAULT 0,
    ptz_supported INTEGER NOT NULL DEFAULT 0,
    imaging_supported INTEGER NOT NULL DEFAULT 0,
    audio_supported INTEGER NOT NULL DEFAULT 0,
    edge_storage_supported INTEGER NOT NULL DEFAULT 0,
    analytics_metadata_supported INTEGER NOT NULL DEFAULT 0,
    streams_json TEXT NOT NULL DEFAULT '[]',
    tested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_profiles (
    credential_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'RTSP',
    username TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL,
    owner_id TEXT NOT NULL DEFAULT 'owner',
    last_verified_at TEXT,
    verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS camera_streams (
    stream_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    profile_name TEXT NOT NULL DEFAULT 'MainStream',
    sanitized_uri_template TEXT NOT NULL,
    credential_id TEXT,
    codec TEXT NOT NULL DEFAULT 'H.264',
    resolution TEXT NOT NULL DEFAULT '1280x720',
    transport TEXT NOT NULL DEFAULT 'tcp',
    delivery_protocol TEXT NOT NULL DEFAULT 'WebRTC',
    mediamtx_path TEXT,
    lifecycle_state TEXT NOT NULL DEFAULT 'CONFIGURED',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recording_segments (
    recording_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'CONTINUOUS',
    file_path TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    duration_sec REAL NOT NULL,
    size_bytes INTEGER NOT NULL,
    codec TEXT NOT NULL DEFAULT 'H.264',
    resolution TEXT NOT NULL DEFAULT '1280x720',
    checksum_sha256 TEXT NOT NULL,
    retention_days INTEGER NOT NULL DEFAULT 14,
    status TEXT NOT NULL DEFAULT 'READY'
);

CREATE TABLE IF NOT EXISTS analytics_events (
    event_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    site_id TEXT NOT NULL DEFAULT 'site-default',
    camera_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 0.0,
    zone_name TEXT NOT NULL DEFAULT 'full_frame',
    description TEXT NOT NULL,
    snapshot_ref TEXT,
    bounding_boxes_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source_ip TEXT NOT NULL DEFAULT '127.0.0.1',
    result TEXT NOT NULL DEFAULT 'SUCCESS',
    details_json TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plugins (
    plugin_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    category TEXT NOT NULL,
    compatibility_tier TEXT NOT NULL,
    permissions_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 0,
    health_status TEXT NOT NULL DEFAULT 'HEALTHY',
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS mobile_pairings (
    pairing_code TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_label TEXT NOT NULL,
    server_url TEXT NOT NULL,
    expires_at REAL NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0
);
"""


def _resolve_sqlite_path(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        raw_path = database_url[len("sqlite:///") :]
    elif database_url.startswith("sqlite://"):
        raw_path = database_url[len("sqlite://") :]
    else:
        raw_path = "data/cctv_streamer.db"
    if raw_path == ":memory:":
        return ":memory:"
    path_obj = Path(raw_path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    return str(path_obj)


class DatabaseManager:
    """Thread-safe durable SQLite database layer for CCTV-Streamer."""

    def __init__(self, database_url: Optional[str] = None) -> None:
        cfg = get_config()
        url = database_url or os.getenv("DATABASE_URL", cfg.database_url)
        self.db_path = _resolve_sqlite_path(url)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()
            self._seed_defaults()

    def _seed_defaults(self) -> None:
        """Seed default site, approved private LAN scope, and standard plugin adapters."""
        now = utc_now_iso()
        with self._lock:
            row = self._conn.execute(
                "SELECT site_id FROM sites WHERE site_id = 'site-default'"
            ).fetchone()
            if not row:
                self._conn.execute(
                    """
                    INSERT INTO sites (site_id, name, description, location, created_by, created_at)
                    VALUES ('site-default', 'Primary Authorized LAN Site',
                            'Default self-hosted local facility network', 'Main Facility', 'system', ?)
                    """,
                    (now,),
                )
            scope_row = self._conn.execute(
                "SELECT scope_id FROM network_scopes WHERE scope_id = 'scope-default-lan'"
            ).fetchone()
            if not scope_row:
                self._conn.execute(
                    """
                    INSERT INTO network_scopes (
                        scope_id, site_id, cidr, vlan_label, approved_by,
                        allowed_methods_json, allowed_ports_json, max_hosts,
                        rate_limit_per_sec, onvif_multicast_enabled, approved_at, active
                    )
                    VALUES (
                        'scope-default-lan', 'site-default', '192.168.1.0/24',
                        'Authorized Camera VLAN 10', 'owner',
                        '["onvif","rtsp_probe","mdns","ssdp"]', '[554,8554,80,8000,8080,8899]',
                        256, 64, 1, ?, 1
                    )
                    """,
                    (now,),
                )

            default_plugins = [
                (
                    "onvif-profile-t",
                    "ONVIF Profile T & Legacy S Adapter",
                    "1.1.0",
                    "CAMERA",
                    "TIER_1_STANDARDS",
                    '["discover","enroll","stream","ptz","events"]',
                    1,
                    "Standards-based ONVIF Profile T (and legacy Profile S) discovery and control adapter.",
                ),
                (
                    "generic-rtsp",
                    "Generic RTSP / RTSPS Stream Adapter",
                    "1.1.0",
                    "CAMERA",
                    "TIER_2_DIRECT_STREAM",
                    '["enroll","stream"]',
                    1,
                    "Direct authenticated RTSP/RTSPS and HTTP/MJPEG stream ingestion adapter.",
                ),
                (
                    "nvr-channel-mapper",
                    "Multi-Channel NVR / DVR Adapter",
                    "1.0.0",
                    "NVR",
                    "TIER_3_VENDOR_ADAPTER",
                    '["enroll","stream","recordings"]',
                    1,
                    "Maps multi-channel NVR/DVR RTSP and ONVIF endpoints per channel.",
                ),
                (
                    "mqtt-iot",
                    "MQTT Local IoT Telemetry Adapter",
                    "1.0.0",
                    "IOT",
                    "TIER_3_VENDOR_ADAPTER",
                    '["telemetry","events"]',
                    0,
                    "Subscribes to local Mosquitto/MQTT sensor topics for door, PIR, and alarm telemetry.",
                ),
                (
                    "home-assistant-bridge",
                    "Home Assistant Local Entity Adapter",
                    "1.0.0",
                    "IOT",
                    "TIER_3_VENDOR_ADAPTER",
                    '["inventory","events","execute"]',
                    0,
                    "Integrates local Home Assistant sensors and approved automation triggers.",
                ),
                (
                    "frigate-nvr-bridge",
                    "Frigate Local AI Event Adapter (Optional)",
                    "1.0.0",
                    "ANALYTICS",
                    "TIER_3_VENDOR_ADAPTER",
                    '["events"]',
                    0,
                    "Ingests local object detection events from an existing self-hosted Frigate instance.",
                ),
            ]
            for pid, name, ver, cat, tier, perms, enabled, desc in default_plugins:
                exists = self._conn.execute(
                    "SELECT plugin_id FROM plugins WHERE plugin_id = ?", (pid,)
                ).fetchone()
                if not exists:
                    self._conn.execute(
                        """
                        INSERT INTO plugins (
                            plugin_id, name, version, category, compatibility_tier,
                            permissions_json, enabled, health_status, description
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'HEALTHY', ?)
                        """,
                        (pid, name, ver, cat, tier, perms, enabled, desc),
                    )
            self._conn.commit()

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(query, params)
            self._conn.commit()
            return cur

    def fetchone(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(query, params).fetchone()
            return dict(row) if row is not None else None

    def fetchall(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]


_GLOBAL_DB: Optional[DatabaseManager] = None
_DB_LOCK = threading.Lock()


def get_db(database_url: Optional[str] = None) -> DatabaseManager:
    """Return the singleton DatabaseManager (or create a fresh instance if custom URL provided)."""
    global _GLOBAL_DB
    if database_url is not None:
        return DatabaseManager(database_url=database_url)
    with _DB_LOCK:
        if _GLOBAL_DB is None:
            _GLOBAL_DB = DatabaseManager()
        return _GLOBAL_DB


def reset_global_db(database_url: Optional[str] = None) -> DatabaseManager:
    """Re-initialize the global database singleton (used by test fixtures)."""
    global _GLOBAL_DB
    with _DB_LOCK:
        _GLOBAL_DB = DatabaseManager(database_url=database_url)
        return _GLOBAL_DB
