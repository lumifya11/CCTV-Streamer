"""OpenCV real-time video frame analytics with detection zones, privacy masks, and durable DB persistence."""

from __future__ import annotations

import collections
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

import cv2
import numpy as np

from services.processor.zones import ZoneRect, apply_privacy_masks, match_detection_zone
from shared.audit import record_audit_event
from shared.database import DatabaseManager, get_db
from shared.logger import get_logger
from shared.models import AnalyticsEvent, EventSeverity, EventType, utc_now_iso

logger = get_logger("processor.analytics")


@dataclass
class CameraAnalyticsConfig:
    """Per-camera tunable analytics parameters and detection/privacy zones."""

    camera_id: str
    motion_sensitivity_threshold: float = 500.0
    motion_min_contour_area: int = 450
    tamper_darkness_threshold: float = 18.0
    tamper_variance_threshold: float = 5.0
    scene_change_threshold: float = 42000.0
    event_cooldown_sec: float = 5.0
    enabled: bool = True
    zones: List[ZoneRect] = field(default_factory=list)


@dataclass
class CameraAnalyticsState:
    """Internal OpenCV background model and telemetry state per camera."""

    camera_id: str
    camera_name: str
    prev_gray: Optional[np.ndarray] = None
    frames_processed: int = 0
    motion_events_count: int = 0
    tamper_events_count: int = 0
    last_motion_score: float = 0.0
    last_luminance: float = 0.0
    last_std_dev: float = 0.0
    last_processing_ms: float = 0.0
    motion_active: bool = False
    tamper_active: bool = False
    last_event_epoch: Dict[str, float] = field(default_factory=dict)
    last_bounding_boxes: List[Dict[str, int]] = field(default_factory=list)


@dataclass
class FrameAnalysisOutput:
    """Result of analyzing a single video frame with OpenCV."""

    camera_id: str
    camera_name: str
    motion_detected: bool
    motion_score: float
    tamper_detected: bool
    mean_luminance: float
    pixel_std_dev: float
    bounding_boxes: List[Dict[str, int]]
    processing_time_ms: float
    events_emitted: List[AnalyticsEvent]


class VideoAnalyticsEngine:
    """
    Thread-safe OpenCV video data processing engine providing:
    - Gaussian-smoothed inter-frame differential motion detection & contour bounding boxes
    - User-defined detection zones and privacy mask zones
    - Lens obstruction / darkness / low-variance tamper & scene-change detection
    - Cooldown-based event deduplication and durable SQLite/PostgreSQL event persistence
    """

    def __init__(
        self,
        default_motion_threshold: float = 500.0,
        default_min_contour_area: int = 450,
        default_tamper_darkness: float = 18.0,
        default_tamper_variance: float = 5.0,
        default_cooldown_sec: float = 5.0,
        max_stored_events: int = 1000,
        db: Optional[DatabaseManager] = None,
    ) -> None:
        self.default_motion_threshold = default_motion_threshold
        self.default_min_contour_area = default_min_contour_area
        self.default_tamper_darkness = default_tamper_darkness
        self.default_tamper_variance = default_tamper_variance
        self.default_cooldown_sec = default_cooldown_sec
        self.db = db or get_db()

        self._lock = threading.RLock()
        self._configs: Dict[str, CameraAnalyticsConfig] = {}
        self._states: Dict[str, CameraAnalyticsState] = {}
        self._events: Deque[AnalyticsEvent] = collections.deque(maxlen=max_stored_events)

    def get_or_create_config(self, camera_id: str) -> CameraAnalyticsConfig:
        with self._lock:
            cfg = self._configs.get(camera_id)
            if cfg is None:
                cfg = CameraAnalyticsConfig(
                    camera_id=camera_id,
                    motion_sensitivity_threshold=self.default_motion_threshold,
                    motion_min_contour_area=self.default_min_contour_area,
                    tamper_darkness_threshold=self.default_tamper_darkness,
                    tamper_variance_threshold=self.default_tamper_variance,
                    event_cooldown_sec=self.default_cooldown_sec,
                )
                self._configs[camera_id] = cfg
            return cfg

    def update_config(
        self,
        camera_id: str,
        motion_sensitivity_threshold: Optional[float] = None,
        motion_min_contour_area: Optional[int] = None,
        tamper_darkness_threshold: Optional[float] = None,
        tamper_variance_threshold: Optional[float] = None,
        event_cooldown_sec: Optional[float] = None,
        enabled: Optional[bool] = None,
        zones: Optional[List[Dict[str, Any]]] = None,
    ) -> CameraAnalyticsConfig:
        with self._lock:
            cfg = self.get_or_create_config(camera_id)
            if motion_sensitivity_threshold is not None:
                cfg.motion_sensitivity_threshold = motion_sensitivity_threshold
            if motion_min_contour_area is not None:
                cfg.motion_min_contour_area = motion_min_contour_area
            if tamper_darkness_threshold is not None:
                cfg.tamper_darkness_threshold = tamper_darkness_threshold
            if tamper_variance_threshold is not None:
                cfg.tamper_variance_threshold = tamper_variance_threshold
            if event_cooldown_sec is not None:
                cfg.event_cooldown_sec = event_cooldown_sec
            if enabled is not None:
                cfg.enabled = enabled
            if zones is not None:
                cfg.zones = [
                    ZoneRect(
                        name=z.get("name", "zone"),
                        x1=float(z.get("x1", 0.0)),
                        y1=float(z.get("y1", 0.0)),
                        x2=float(z.get("x2", 1.0)),
                        y2=float(z.get("y2", 1.0)),
                        is_privacy_mask=bool(z.get("is_privacy_mask", False)),
                    )
                    for z in zones
                ]
            return cfg

    def _persist_event(self, evt: AnalyticsEvent) -> None:
        """Persist AnalyticsEvent to durable SQLite/PostgreSQL storage and in-memory buffer."""
        self._events.appendleft(evt)
        try:
            self.db.execute(
                """
                INSERT INTO analytics_events (
                    event_id, device_id, site_id, camera_name, event_type,
                    severity, score, zone_name, description, snapshot_ref,
                    bounding_boxes_json, metadata_json, acknowledged, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    evt.event_id,
                    evt.camera_id,
                    evt.site_id,
                    evt.camera_name,
                    evt.event_type.value,
                    evt.severity.value,
                    evt.score,
                    evt.zone_name,
                    evt.description,
                    evt.snapshot_ref,
                    json.dumps(evt.bounding_boxes),
                    json.dumps(evt.metadata),
                    evt.timestamp,
                ),
            )
        except Exception as exc:
            logger.debug("Event persistence fallback: %s", exc)

    def process_jpeg_bytes(
        self,
        camera_id: str,
        jpeg_bytes: bytes,
        camera_name: Optional[str] = None,
    ) -> FrameAnalysisOutput:
        """Decode JPEG frame bytes into an OpenCV BGR matrix and analyze."""
        arr = np.frombuffer(jpeg_bytes, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame is None or frame.size == 0:
            raise ValueError("Invalid or corrupted JPEG image buffer")
        return self.process_frame(
            camera_id=camera_id,
            frame=frame,
            camera_name=camera_name or camera_id,
        )

    def process_frame(
        self,
        camera_id: str,
        frame: np.ndarray,
        camera_name: Optional[str] = None,
    ) -> FrameAnalysisOutput:
        """Run OpenCV motion, zone, scene-change, and tamper analysis on a single BGR frame."""
        if frame is None or frame.size == 0:
            raise ValueError("Frame cannot be empty")

        t0 = time.monotonic()
        label = camera_name or camera_id
        cfg = self.get_or_create_config(camera_id)

        masked_frame = apply_privacy_masks(frame, cfg.zones)

        analysis_w, analysis_h = 640, 360
        orig_h, orig_w = masked_frame.shape[:2]
        resized = cv2.resize(
            masked_frame, (analysis_w, analysis_h), interpolation=cv2.INTER_AREA
        )

        # Crop out top 28px OSD timestamp bar so ticking clock digits do not trigger motion
        roi = resized[28:, :]
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (15, 15), 0)

        mean_arr, std_arr = cv2.meanStdDev(gray)
        mean_lum = float(mean_arr[0][0])
        std_dev = float(std_arr[0][0])

        tamper_detected = (
            mean_lum < cfg.tamper_darkness_threshold
            and std_dev < cfg.tamper_variance_threshold
        )

        scale_x = orig_w / float(analysis_w)
        scale_y = orig_h / float(analysis_h)

        bounding_boxes: List[Dict[str, int]] = []
        motion_score = 0.0
        motion_detected = False
        matched_zone = "full_frame"
        emitted_events: List[AnalyticsEvent] = []

        with self._lock:
            state = self._states.get(camera_id)
            if state is None:
                state = CameraAnalyticsState(camera_id=camera_id, camera_name=label)
                self._states[camera_id] = state
            state.camera_name = label

            if (
                state.prev_gray is not None
                and state.prev_gray.shape == blurred.shape
                and cfg.enabled
            ):
                frame_delta = cv2.absdiff(state.prev_gray, blurred)
                _, thresh = cv2.threshold(frame_delta, 22, 255, cv2.THRESH_BINARY)
                dilated = cv2.dilate(thresh, None, iterations=2)
                contours, _ = cv2.findContours(
                    dilated, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
                )

                total_area = 0.0
                for contour in contours:
                    area = float(cv2.contourArea(contour))
                    if area < cfg.motion_min_contour_area:
                        continue
                    x, y, w, h = cv2.boundingRect(contour)
                    box = {
                        "x": int(round(x * scale_x)),
                        "y": int(round((y + 28) * scale_y)),
                        "width": int(round(w * scale_x)),
                        "height": int(round(h * scale_y)),
                        "area": int(round(area)),
                    }
                    zone_label = match_detection_zone(
                        box, orig_w, orig_h, cfg.zones
                    )
                    if zone_label == "outside_zone":
                        continue
                    matched_zone = zone_label
                    total_area += area
                    bounding_boxes.append(box)

                motion_score = round(total_area, 2)
                motion_detected = (
                    motion_score >= cfg.motion_sensitivity_threshold
                    and len(bounding_boxes) > 0
                )

            if state.prev_gray is None or state.prev_gray.shape != blurred.shape:
                state.prev_gray = blurred
            else:
                state.prev_gray = cv2.addWeighted(state.prev_gray, 0.65, blurred, 0.35, 0)

            elapsed_ms = round((time.monotonic() - t0) * 1000.0, 2)
            state.frames_processed += 1
            state.last_motion_score = motion_score
            state.last_luminance = round(mean_lum, 2)
            state.last_std_dev = round(std_dev, 2)
            state.last_processing_ms = elapsed_ms
            state.motion_active = motion_detected
            state.tamper_active = tamper_detected
            state.last_bounding_boxes = bounding_boxes

            now_epoch = time.monotonic()

            if motion_detected and self._can_emit(
                state, EventType.MOTION_DETECTED.value, now_epoch, cfg.event_cooldown_sec
            ):
                state.motion_events_count += 1
                evt = AnalyticsEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:10]}",
                    camera_id=camera_id,
                    camera_name=label,
                    event_type=EventType.MOTION_DETECTED,
                    severity=(
                        EventSeverity.WARNING
                        if motion_score < cfg.motion_sensitivity_threshold * 3
                        else EventSeverity.CRITICAL
                    ),
                    score=motion_score,
                    zone_name=matched_zone,
                    description=(
                        f"Kinetic activity detected in {label} [{matched_zone}] "
                        f"({len(bounding_boxes)} region(s), score={motion_score:.0f})"
                    ),
                    snapshot_ref=f"/api/v1/streams/{camera_id}/snapshot",
                    bounding_boxes=bounding_boxes,
                    metadata={
                        "luminance": round(mean_lum, 1),
                        "processing_ms": elapsed_ms,
                    },
                )
                self._persist_event(evt)
                emitted_events.append(evt)

            if tamper_detected and self._can_emit(
                state, EventType.TAMPER_OBSTRUCTION.value, now_epoch, cfg.event_cooldown_sec
            ):
                state.tamper_events_count += 1
                evt = AnalyticsEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:10]}",
                    camera_id=camera_id,
                    camera_name=label,
                    event_type=EventType.TAMPER_OBSTRUCTION,
                    severity=EventSeverity.CRITICAL,
                    score=round(mean_lum, 2),
                    zone_name="full_frame",
                    description=(
                        f"Potential lens obstruction or signal blackout on {label} "
                        f"(luminance={mean_lum:.1f}, variance={std_dev:.1f})"
                    ),
                    bounding_boxes=[],
                    metadata={
                        "luminance": round(mean_lum, 1),
                        "std_dev": round(std_dev, 1),
                    },
                )
                self._persist_event(evt)
                emitted_events.append(evt)

        return FrameAnalysisOutput(
            camera_id=camera_id,
            camera_name=label,
            motion_detected=motion_detected,
            motion_score=motion_score,
            tamper_detected=tamper_detected,
            mean_luminance=round(mean_lum, 2),
            pixel_std_dev=round(std_dev, 2),
            bounding_boxes=bounding_boxes,
            processing_time_ms=elapsed_ms,
            events_emitted=emitted_events,
        )

    @staticmethod
    def _can_emit(
        state: CameraAnalyticsState,
        event_key: str,
        now_epoch: float,
        cooldown_sec: float,
    ) -> bool:
        last_time = state.last_event_epoch.get(event_key)
        if last_time is not None and (now_epoch - last_time) < cooldown_sec:
            return False
        state.last_event_epoch[event_key] = now_epoch
        return True

    def list_events(
        self,
        camera_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
        severity: Optional[EventSeverity] = None,
        limit: int = 50,
    ) -> List[AnalyticsEvent]:
        """Query durable events from SQLite/PostgreSQL with fallback to memory."""
        query = "SELECT * FROM analytics_events WHERE 1=1"
        params: List[Any] = []
        if camera_id:
            query += " AND device_id = ?"
            params.append(camera_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(max(1, min(500, limit)))

        rows = self.db.fetchall(query, tuple(params))
        if rows:
            return [
                AnalyticsEvent(
                    event_id=r["event_id"],
                    camera_id=r["device_id"],
                    site_id=r.get("site_id", "site-default"),
                    camera_name=r["camera_name"],
                    event_type=EventType(r["event_type"]),
                    severity=EventSeverity(r["severity"]),
                    timestamp=r["timestamp"],
                    score=float(r.get("score", 0.0)),
                    zone_name=r.get("zone_name", "full_frame"),
                    description=r["description"],
                    snapshot_ref=r.get("snapshot_ref"),
                    acknowledged=bool(r.get("acknowledged", 0)),
                    acknowledged_by=r.get("acknowledged_by"),
                    acknowledged_at=r.get("acknowledged_at"),
                    bounding_boxes=json.loads(r.get("bounding_boxes_json", "[]") or "[]"),
                    metadata=json.loads(r.get("metadata_json", "{}") or "{}"),
                )
                for r in rows
            ]

        with self._lock:
            items = list(self._events)
        if camera_id:
            items = [e for e in items if e.camera_id == camera_id]
        if event_type:
            items = [e for e in items if e.event_type == event_type]
        if severity:
            items = [e for e in items if e.severity == severity]
        return items[: max(1, min(500, limit))]

    def acknowledge_event(
        self, event_id: str, actor: str = "operator"
    ) -> Optional[AnalyticsEvent]:
        now = utc_now_iso()
        self.db.execute(
            """
            UPDATE analytics_events
            SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
            WHERE event_id = ?
            """,
            (actor, now, event_id),
        )
        with self._lock:
            for e in self._events:
                if e.event_id == event_id:
                    e.acknowledged = True
                    e.acknowledged_by = actor
                    e.acknowledged_at = now
        record_audit_event(
            action="ANALYTICS_EVENT_ACKNOWLEDGED",
            target_type="EVENT",
            target_id=event_id,
            actor=actor,
            actor_role="OPERATOR",
            db=self.db,
        )
        matches = [e for e in self.list_events(limit=200) if e.event_id == event_id]
        return matches[0] if matches else None

    def get_metrics_summary(self) -> Dict[str, Any]:
        with self._lock:
            cameras_summary = {}
            total_frames = 0
            total_motion = 0
            total_tamper = 0
            for cam_id, st in self._states.items():
                total_frames += st.frames_processed
                total_motion += st.motion_events_count
                total_tamper += st.tamper_events_count
                cameras_summary[cam_id] = {
                    "camera_id": cam_id,
                    "camera_name": st.camera_name,
                    "frames_processed": st.frames_processed,
                    "motion_active": st.motion_active,
                    "tamper_active": st.tamper_active,
                    "last_motion_score": st.last_motion_score,
                    "last_luminance": st.last_luminance,
                    "last_std_dev": st.last_std_dev,
                    "last_processing_ms": st.last_processing_ms,
                    "motion_events_count": st.motion_events_count,
                    "tamper_events_count": st.tamper_events_count,
                    "active_bounding_boxes": st.last_bounding_boxes,
                }
            return {
                "timestamp": utc_now_iso(),
                "total_frames_processed": total_frames,
                "total_motion_events": total_motion,
                "total_tamper_events": total_tamper,
                "stored_events_count": len(self._events),
                "cameras": cameras_summary,
            }
