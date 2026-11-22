"""Segmented Recording Indexer, Retention Manager, Storage Calculator, and Audited Export/Delete."""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.audit import record_audit_event
from shared.auth import create_signed_token
from shared.config import get_config
from shared.database import DatabaseManager, get_db
from shared.models import RecordingMode, utc_now_iso


def calculate_storage_estimate(
    bitrate_mbps: float,
    camera_count: int,
    hours_per_day: float = 24.0,
    retention_days: int = 14,
) -> Dict[str, Any]:
    """
    Calculate estimated recording storage using the blueprint formula:
    Estimated GB = bitrate_Mbps × 3600 × hours_per_day × days × camera_count ÷ 8 ÷ 1000
    """
    estimated_gb = (
        float(bitrate_mbps)
        * 3600.0
        * float(hours_per_day)
        * float(retention_days)
        * int(camera_count)
        / 8.0
        / 1000.0
    )
    recommended_with_margin_gb = estimated_gb * 1.20
    return {
        "bitrate_mbps": bitrate_mbps,
        "camera_count": camera_count,
        "hours_per_day": hours_per_day,
        "retention_days": retention_days,
        "estimated_gb": round(estimated_gb, 2),
        "recommended_with_20pct_margin_gb": round(recommended_with_margin_gb, 2),
        "formula": "bitrate_Mbps * 3600 * hours_per_day * days * camera_count / 8 / 1000",
        "disclaimer": (
            "Actual storage varies with codec (H.264 vs H.265), motion intensity, "
            "frame rate, VBR/CBR profile, and audio tracks."
        ),
    }


class RecordingCoordinator:
    """
    Manages recording segment metadata, disk utilization health, retention cleanup,
    and role-audited playback/export/delete actions.
    """

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        recordings_dir: Optional[str] = None,
    ) -> None:
        cfg = get_config()
        self.db = db or get_db()
        self.recordings_dir = Path(recordings_dir or cfg.recordings_dir)
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        self.storage_budget_gb = cfg.storage_budget_gb
        self.default_retention_days = cfg.default_retention_days

    def get_storage_status(
        self,
        active_camera_count: int = 4,
        avg_bitrate_mbps: float = 2.0,
    ) -> Dict[str, Any]:
        """Return real local disk utilization, indexed segment totals, and storage projection."""
        usage = shutil.disk_usage(self.recordings_dir)
        row = self.db.fetchone(
            "SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS total_bytes FROM recording_segments"
        )
        indexed_count = int(row["count"]) if row else 0
        indexed_bytes = int(row["total_bytes"]) if row else 0

        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        used_pct = round((usage.used / usage.total) * 100.0, 2) if usage.total else 0.0
        disk_low = free_gb < 2.0 or used_pct > 95.0

        estimate = calculate_storage_estimate(
            bitrate_mbps=avg_bitrate_mbps,
            camera_count=max(1, active_camera_count),
            hours_per_day=24.0,
            retention_days=self.default_retention_days,
        )
        return {
            "recordings_dir": str(self.recordings_dir.resolve()),
            "disk_total_gb": round(total_gb, 2),
            "disk_free_gb": round(free_gb, 2),
            "disk_used_percent": used_pct,
            "disk_pressure_warning": disk_low,
            "indexed_segments_count": indexed_count,
            "indexed_recordings_mb": round(indexed_bytes / (1024 ** 2), 2),
            "storage_budget_gb": self.storage_budget_gb,
            "default_retention_days": self.default_retention_days,
            "capacity_estimate": estimate,
        }

    def index_segment(
        self,
        device_id: str,
        stream_id: str,
        duration_sec: float = 60.0,
        mode: RecordingMode = RecordingMode.CONTINUOUS,
        payload_bytes: Optional[bytes] = None,
        codec: str = "H.264",
        resolution: str = "1280x720",
        retention_days: Optional[int] = None,
        actor: str = "recording-coordinator",
    ) -> Dict[str, Any]:
        """Write or index a segmented recording file with SHA-256 integrity checksum."""
        status_info = self.get_storage_status()
        if status_info["disk_free_gb"] < 0.05:
            # Enforce automatic retention eviction before failing on low disk
            self.enforce_retention_policy(actor="disk-guard")

        recording_id = f"rec-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(seconds=max(1.0, duration_sec))
        start_iso = start_dt.isoformat()
        end_iso = now.isoformat()

        cam_dir = self.recordings_dir / device_id
        cam_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{start_dt.strftime('%Y%m%dT%H%M%SZ')}_{recording_id}.mp4"
        file_path = cam_dir / filename

        content = payload_bytes if payload_bytes is not None else f"fMP4-segment:{recording_id}".encode("utf-8")
        file_path.write_bytes(content)
        checksum = hashlib.sha256(content).hexdigest()
        size_bytes = len(content)
        ret_days = retention_days or self.default_retention_days

        self.db.execute(
            """
            INSERT INTO recording_segments (
                recording_id, device_id, stream_id, mode, file_path,
                start_time, end_time, duration_sec, size_bytes,
                codec, resolution, checksum_sha256, retention_days, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'READY')
            """,
            (
                recording_id,
                device_id,
                stream_id,
                mode.value,
                str(file_path),
                start_iso,
                end_iso,
                round(duration_sec, 2),
                size_bytes,
                codec,
                resolution,
                checksum,
                ret_days,
            ),
        )
        record_audit_event(
            action="RECORDING_SEGMENT_INDEXED",
            target_type="RECORDING",
            target_id=recording_id,
            actor=actor,
            actor_role="SYSTEM",
            details={"device_id": device_id, "size_bytes": size_bytes, "checksum": checksum[:16]},
            db=self.db,
        )
        return self.get_recording(recording_id)  # type: ignore[return-value]

    def list_recordings(
        self,
        device_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if device_id:
            return self.db.fetchall(
                "SELECT * FROM recording_segments WHERE device_id = ? ORDER BY start_time DESC LIMIT ?",
                (device_id, max(1, min(500, limit))),
            )
        return self.db.fetchall(
            "SELECT * FROM recording_segments ORDER BY start_time DESC LIMIT ?",
            (max(1, min(500, limit)),),
        )

    def get_recording(self, recording_id: str) -> Optional[Dict[str, Any]]:
        return self.db.fetchone(
            "SELECT * FROM recording_segments WHERE recording_id = ?",
            (recording_id,),
        )

    def export_recording(
        self,
        recording_id: str,
        actor: str = "operator",
        actor_role: str = "OPERATOR",
    ) -> Dict[str, Any]:
        """Generate a short-lived signed export token and audit the export request."""
        rec = self.get_recording(recording_id)
        if not rec:
            raise KeyError(f"Recording '{recording_id}' not found.")

        signed_token = create_signed_token(
            {
                "sub": actor,
                "role": actor_role,
                "recording_id": recording_id,
                "action": "recording_export",
            },
            ttl_sec=300,
        )
        record_audit_event(
            action="RECORDING_EXPORTED",
            target_type="RECORDING",
            target_id=recording_id,
            actor=actor,
            actor_role=actor_role,
            details={"device_id": rec["device_id"], "checksum": rec["checksum_sha256"]},
            db=self.db,
        )
        return {
            "recording_id": recording_id,
            "device_id": rec["device_id"],
            "checksum_sha256": rec["checksum_sha256"],
            "size_bytes": rec["size_bytes"],
            "download_url": f"/api/v1/recordings/{recording_id}/download?token={signed_token}",
            "expires_in_sec": 300,
        }

    def delete_recording(
        self,
        recording_id: str,
        actor: str = "owner",
        actor_role: str = "OWNER",
    ) -> bool:
        """Delete a recording segment (Owner/Admin only) and record in audit trail."""
        if actor_role not in ("OWNER", "ADMIN"):
            raise PermissionError("Only OWNER or ADMIN roles may delete recording segments.")
        rec = self.get_recording(recording_id)
        if not rec:
            return False

        fpath = Path(rec["file_path"])
        if fpath.is_file():
            try:
                fpath.unlink()
            except OSError:
                pass

        self.db.execute(
            "DELETE FROM recording_segments WHERE recording_id = ?",
            (recording_id,),
        )
        record_audit_event(
            action="RECORDING_DELETED",
            target_type="RECORDING",
            target_id=recording_id,
            actor=actor,
            actor_role=actor_role,
            details={"device_id": rec["device_id"]},
            db=self.db,
        )
        return True

    def enforce_retention_policy(self, actor: str = "retention-worker") -> int:
        """Purge expired recording segments exceeding their retention window."""
        rows = self.db.fetchall("SELECT * FROM recording_segments")
        now = datetime.now(timezone.utc)
        removed = 0
        for row in rows:
            try:
                end_dt = datetime.fromisoformat(row["end_time"])
            except ValueError:
                continue
            max_age = timedelta(days=int(row.get("retention_days", self.default_retention_days)))
            if (now - end_dt) > max_age:
                self.delete_recording(
                    row["recording_id"], actor=actor, actor_role="OWNER"
                )
                removed += 1
        return removed
