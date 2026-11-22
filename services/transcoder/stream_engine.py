"""Resilient OpenCV RTSP Ingestion Engine with automatic reconnection and low-latency transcoding."""

from __future__ import annotations

import math
import os
import random
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

import cv2
import numpy as np

from shared.logger import get_logger
from shared.models import StreamMetrics, StreamRegistrationRequest, StreamState, utc_now_iso
from shared.security import inject_rtsp_credentials, mask_rtsp_credentials, validate_rtsp_source

logger = get_logger("transcoder.engine")


def configure_opencv_ffmpeg_options(rtsp_transport: str = "tcp", timeout_sec: float = 5.0) -> None:
    """Configure OpenCV FFMPEG capture options for low-latency RTSP streaming."""
    stimeout_us = int(max(1.0, timeout_sec) * 1_000_000)
    transport = "tcp" if rtsp_transport.lower() not in ("tcp", "udp") else rtsp_transport.lower()
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = (
        f"rtsp_transport;{transport}|fflags;nobuffer|flags;low_delay|stimeout;{stimeout_us}"
    )


def compute_backoff_delay(
    attempt: int,
    base_delay_sec: float = 1.0,
    max_delay_sec: float = 30.0,
    jitter_ratio: float = 0.2,
) -> float:
    """Compute exponential backoff delay with bounded random jitter."""
    exponent = min(max(0, attempt - 1), 10)
    raw_delay = min(max_delay_sec, base_delay_sec * (2 ** exponent))
    jitter = raw_delay * jitter_ratio * random.uniform(-1.0, 1.0)
    return round(max(0.1, min(max_delay_sec, raw_delay + jitter)), 3)


class SyntheticCCTVFrameGenerator:
    """
    OpenCV synthetic surveillance scene generator for demo streams (`demo://<id>`)
    and test harnesses. Produces realistic animated CCTV frames with moving subjects
    so the downstream OpenCV Analytics Processor detects real motion and bounding boxes.
    """

    def __init__(self, camera_id: str, name: str, location: str, width: int = 1280, height: int = 720) -> None:
        self.camera_id = camera_id
        self.name = name
        self.location = location
        self.width = width
        self.height = height
        self._frame_idx = 0
        self._seed = sum(ord(c) for c in camera_id)
        self._base_scene = self._build_static_background()

    def _build_static_background(self) -> np.ndarray:
        """Pre-render architectural floorplan/corridor background for fast frame synthesis."""
        bg = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        variant = self._seed % 4

        # Base dark slate architectural tone
        tones = [
            (24, 28, 22),   # Night vision green-slate
            (28, 24, 20),   # Industrial corridor cool steel
            (22, 25, 30),   # Loading dock amber-charcoal
            (26, 26, 26),   # Monochrome high-contrast camera
        ]
        base_bgr = tones[variant]
        bg[:] = base_bgr

        # Perspective corridor / zone lines
        cx, cy = self.width // 2, int(self.height * 0.38)
        line_color = (base_bgr[0] + 22, base_bgr[1] + 24, base_bgr[2] + 22)
        cv2.line(bg, (0, self.height), (cx - 120, cy), line_color, 2)
        cv2.line(bg, (self.width, self.height), (cx + 120, cy), line_color, 2)
        cv2.rectangle(bg, (cx - 120, cy - 80), (cx + 120, cy), line_color, 1)

        # Subtle perspective floor tiles
        for step in range(1, 7):
            y_pos = cy + int((self.height - cy) * (step / 6.0) ** 1.4)
            cv2.line(bg, (40, y_pos), (self.width - 40, y_pos), line_color, 1)

        # Zone perimeter markers
        roi_color = (45, 70, 55)
        cv2.rectangle(
            bg,
            (int(self.width * 0.12), int(self.height * 0.22)),
            (int(self.width * 0.88), int(self.height * 0.88)),
            roi_color,
            1,
        )
        return bg

    def next_frame(self) -> np.ndarray:
        """Render the next timestamped surveillance frame with moving patrol objects."""
        self._frame_idx += 1
        frame = self._base_scene.copy()
        t = time.time() + (self._seed * 1.7)

        # Add subtle sensor grain
        noise = np.random.randint(0, 6, (self.height // 4, self.width // 4, 1), dtype=np.uint8)
        noise_up = cv2.resize(noise, (self.width, self.height), interpolation=cv2.INTER_NEAREST)
        frame[:, :, 0] = cv2.add(frame[:, :, 0], noise_up)
        frame[:, :, 1] = cv2.add(frame[:, :, 1], noise_up)
        frame[:, :, 2] = cv2.add(frame[:, :, 2], noise_up)

        # Primary moving object (periodic motion cycle so motion detector triggers realistically)
        cycle = (t * 0.45) % (2 * math.pi)
        obj_x = int(self.width * 0.5 + math.sin(cycle) * (self.width * 0.28))
        obj_y = int(self.height * 0.56 + math.cos(cycle * 0.7) * (self.height * 0.14))
        obj_w, obj_h = 68, 118

        x1 = max(20, min(self.width - obj_w - 20, obj_x - obj_w // 2))
        y1 = max(60, min(self.height - obj_h - 30, obj_y - obj_h // 2))
        x2, y2 = x1 + obj_w, y1 + obj_h

        # Draw moving entity silhouette + high-contrast thermal core
        cv2.rectangle(frame, (x1, y1), (x2, y2), (145, 165, 150), -1)
        cv2.rectangle(frame, (x1 + 12, y1 + 10), (x2 - 12, y1 + 36), (200, 215, 205), -1)

        # Secondary intermittent vehicle/cart object every few seconds
        if int(t) % 8 < 5:
            vx = int((self.width * 0.18) + ((t * 95) % (self.width * 0.62)))
            vy = int(self.height * 0.70)
            cv2.rectangle(frame, (vx, vy), (vx + 96, vy + 54), (130, 145, 165), -1)

        return frame


class RTSPStreamWorker:
    """
    Manages a single RTSP camera ingestion lifecycle using OpenCV:
    - Dedicated thread reading from `cv2.VideoCapture` (or synthetic source)
    - Automatic reconnection with exponential backoff and error tracking
    - Low-latency resizing, OSD overlay, and JPEG frame encoding
    """

    def __init__(
        self,
        registration: StreamRegistrationRequest,
        rtsp_transport: str = "tcp",
        buffer_size: int = 2,
        read_timeout_sec: float = 8.0,
        reconnect_base_delay_sec: float = 1.0,
        reconnect_max_delay_sec: float = 30.0,
        reconnect_max_attempts: int = 0,
        capture_factory: Optional[Callable[[str], cv2.VideoCapture]] = None,
    ) -> None:
        validate_rtsp_source(registration.rtsp_url)
        self.camera_id = registration.camera_id
        self.name = registration.name
        self.location = registration.location
        self.raw_rtsp_url = inject_rtsp_credentials(
            registration.rtsp_url, registration.username, registration.password
        )
        self.masked_rtsp_url = mask_rtsp_credentials(self.raw_rtsp_url)
        self.target_fps = registration.target_fps
        self.width = registration.width
        self.height = registration.height
        self.jpeg_quality = registration.jpeg_quality
        self.enable_analytics = registration.enable_analytics

        self.rtsp_transport = rtsp_transport
        self.buffer_size = buffer_size
        self.read_timeout_sec = read_timeout_sec
        self.reconnect_base_delay_sec = reconnect_base_delay_sec
        self.reconnect_max_delay_sec = reconnect_max_delay_sec
        self.reconnect_max_attempts = reconnect_max_attempts
        self._capture_factory = capture_factory

        self._lock = threading.RLock()
        self._frame_cond = threading.Condition(self._lock)
        self._stop_event = threading.Event()
        self._force_reconnect_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._state: StreamState = StreamState.IDLE
        self._latest_frame: Optional[np.ndarray] = None
        self._latest_jpeg: Optional[bytes] = None
        self._latest_frame_seq: int = 0
        self._last_frame_epoch: float = 0.0
        self._last_frame_iso: Optional[str] = None
        self._started_epoch: float = 0.0

        self._frames_ingested: int = 0
        self._frames_dropped: int = 0
        self._reconnect_attempts: int = 0
        self._total_reconnections: int = 0
        self._last_error: Optional[str] = None
        self._fps_actual: float = 0.0
        self._latency_ms: float = 0.0
        self._bitrate_kbps: float = 0.0
        self._motion_active: bool = False
        self._motion_score: float = 0.0

        self._is_synthetic = self.raw_rtsp_url.startswith(("demo://", "synthetic://"))
        self._synthetic_gen = (
            SyntheticCCTVFrameGenerator(
                camera_id=self.camera_id,
                name=self.name,
                location=self.location,
                width=self.width,
                height=self.height,
            )
            if self._is_synthetic
            else None
        )

    def start(self) -> None:
        """Start the background OpenCV ingestion thread."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._force_reconnect_event.clear()
            self._started_epoch = time.monotonic()
            self._state = StreamState.CONNECTING
            self._thread = threading.Thread(
                target=self._run_loop,
                name=f"rtsp-worker-{self.camera_id}",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "Started RTSP stream worker for %s (%s)",
                self.camera_id,
                self.masked_rtsp_url,
            )

    def stop(self, timeout_sec: float = 3.0) -> None:
        """Signal the ingestion thread to stop and release OpenCV capture resources."""
        self._stop_event.set()
        self._force_reconnect_event.set()
        with self._frame_cond:
            self._frame_cond.notify_all()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout_sec)
        with self._lock:
            self._state = StreamState.OFFLINE
        logger.info("Stopped RTSP stream worker for %s", self.camera_id)

    def trigger_reconnect(self) -> None:
        """Force an immediate stream reconnection cycle."""
        self._force_reconnect_event.set()
        logger.info("Triggered manual reconnection for camera %s", self.camera_id)

    def update_analytics_status(self, motion_active: bool, motion_score: float) -> None:
        with self._lock:
            self._motion_active = motion_active
            self._motion_score = round(motion_score, 2)

    def get_metrics(self) -> StreamMetrics:
        with self._lock:
            uptime = (
                round(time.monotonic() - self._started_epoch, 2)
                if self._started_epoch > 0 and self._state != StreamState.OFFLINE
                else 0.0
            )
            return StreamMetrics(
                camera_id=self.camera_id,
                name=self.name,
                location=self.location,
                rtsp_url_masked=self.masked_rtsp_url,
                state=self._state,
                fps_actual=round(self._fps_actual, 2),
                fps_target=self.target_fps,
                frame_width=self.width,
                frame_height=self.height,
                frames_ingested=self._frames_ingested,
                frames_dropped=self._frames_dropped,
                reconnect_attempts=self._reconnect_attempts,
                total_reconnections=self._total_reconnections,
                last_frame_timestamp=self._last_frame_iso,
                last_error=self._last_error,
                uptime_seconds=uptime,
                latency_ms=round(self._latency_ms, 2),
                bitrate_kbps=round(self._bitrate_kbps, 1),
                motion_active=self._motion_active,
                motion_score=self._motion_score,
            )

    def get_latest_jpeg(self) -> Optional[bytes]:
        """Return the latest transcoded JPEG frame bytes (or placeholder if connecting)."""
        with self._lock:
            if self._latest_jpeg is not None:
                return self._latest_jpeg
        return self._encode_status_frame(f"CONNECTING: {self.name}")

    def get_latest_raw_frame(self) -> Optional[np.ndarray]:
        """Return a copy of the latest BGR OpenCV ndarray frame."""
        with self._lock:
            if self._latest_frame is None:
                return None
            return self._latest_frame.copy()

    def wait_for_next_jpeg(self, last_seq: int, timeout_sec: float = 1.0) -> Tuple[int, bytes]:
        """Wait for a new frame sequence number and return (seq, jpeg_bytes)."""
        with self._frame_cond:
            if self._latest_jpeg is None or self._latest_frame_seq <= last_seq:
                self._frame_cond.wait(timeout=timeout_sec)
            if self._latest_jpeg is not None:
                return (self._latest_frame_seq, self._latest_jpeg)
            current_state = self._state.value
        return (last_seq, self._encode_status_frame(f"{current_state}: {self.name}"))

    def _open_capture(self) -> cv2.VideoCapture:
        configure_opencv_ffmpeg_options(self.rtsp_transport, self.read_timeout_sec)
        if self._capture_factory is not None:
            cap = self._capture_factory(self.raw_rtsp_url)
        else:
            cap = cv2.VideoCapture(self.raw_rtsp_url, cv2.CAP_FFMPEG)
        try:
            cap.set(cv2.CAP_PROP_BUFFERSIZE, self.buffer_size)
        except Exception:
            pass
        return cap

    def _run_loop(self) -> None:
        """Main resilient ingestion loop with automatic reconnection."""
        if self._is_synthetic:
            self._run_synthetic_loop()
            return

        cap: Optional[cv2.VideoCapture] = None
        fps_window_start = time.monotonic()
        fps_frame_count = 0
        bytes_in_window = 0

        try:
            while not self._stop_event.is_set():
                if self._force_reconnect_event.is_set():
                    self._force_reconnect_event.clear()
                    if cap is not None:
                        try:
                            cap.release()
                        except Exception:
                            pass
                        cap = None

                if cap is None or not cap.isOpened():
                    with self._lock:
                        self._state = (
                            StreamState.RECONNECTING
                            if self._reconnect_attempts > 0
                            else StreamState.CONNECTING
                        )

                    try:
                        cap = self._open_capture()
                    except Exception as exc:
                        cap = None
                        self._record_failure(f"VideoCapture init error: {exc}")

                    if cap is None or not cap.isOpened():
                        if cap is not None:
                            try:
                                cap.release()
                            except Exception:
                                pass
                            cap = None
                        self._handle_reconnect_backoff("Failed to open RTSP stream")
                        continue

                    # Successfully connected
                    with self._lock:
                        if self._reconnect_attempts > 0:
                            self._total_reconnections += 1
                        self._reconnect_attempts = 0
                        self._state = StreamState.STREAMING
                        self._last_error = None
                    fps_window_start = time.monotonic()
                    fps_frame_count = 0
                    bytes_in_window = 0
                    logger.info(
                        "RTSP connection established for %s (%s)",
                        self.camera_id,
                        self.masked_rtsp_url,
                    )

                t_read_start = time.monotonic()
                ret, frame = cap.read()
                read_elapsed_ms = (time.monotonic() - t_read_start) * 1000.0

                if not ret or frame is None or frame.size == 0:
                    if cap is not None:
                        try:
                            cap.release()
                        except Exception:
                            pass
                        cap = None
                    self._handle_reconnect_backoff("RTSP frame grab failed or EOF reached")
                    continue

                # Transcode / normalize frame for low-latency web delivery
                jpeg_bytes, processed_frame = self._transcode_frame(frame)
                now_mono = time.monotonic()
                fps_frame_count += 1
                bytes_in_window += len(jpeg_bytes)
                window_elapsed = now_mono - fps_window_start

                with self._frame_cond:
                    self._latest_frame = processed_frame
                    self._latest_jpeg = jpeg_bytes
                    self._latest_frame_seq += 1
                    self._frames_ingested += 1
                    self._last_frame_epoch = now_mono
                    self._last_frame_iso = utc_now_iso()
                    self._latency_ms = read_elapsed_ms
                    self._state = StreamState.STREAMING
                    if window_elapsed >= 1.0:
                        self._fps_actual = fps_frame_count / window_elapsed
                        self._bitrate_kbps = (bytes_in_window * 8.0 / 1000.0) / window_elapsed
                        fps_window_start = now_mono
                        fps_frame_count = 0
                        bytes_in_window = 0
                    self._frame_cond.notify_all()

                # Frame rate pacing to respect target_fps
                frame_interval = 1.0 / max(1, self.target_fps)
                sleep_dur = frame_interval - (time.monotonic() - t_read_start)
                if sleep_dur > 0.002:
                    self._stop_event.wait(timeout=sleep_dur)
        finally:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass

    def _run_synthetic_loop(self) -> None:
        """Low-latency OpenCV synthetic stream loop for demo cameras."""
        assert self._synthetic_gen is not None
        with self._lock:
            self._state = StreamState.STREAMING
            self._last_error = None

        fps_window_start = time.monotonic()
        fps_frame_count = 0
        bytes_in_window = 0

        while not self._stop_event.is_set():
            if self._force_reconnect_event.is_set():
                self._force_reconnect_event.clear()
                with self._lock:
                    self._state = StreamState.RECONNECTING
                    self._total_reconnections += 1
                self._stop_event.wait(timeout=0.15)
                with self._lock:
                    self._state = StreamState.STREAMING

            t0 = time.monotonic()
            raw_frame = self._synthetic_gen.next_frame()
            jpeg_bytes, processed_frame = self._transcode_frame(raw_frame)
            render_ms = (time.monotonic() - t0) * 1000.0

            now_mono = time.monotonic()
            fps_frame_count += 1
            bytes_in_window += len(jpeg_bytes)
            window_elapsed = now_mono - fps_window_start

            with self._frame_cond:
                self._latest_frame = processed_frame
                self._latest_jpeg = jpeg_bytes
                self._latest_frame_seq += 1
                self._frames_ingested += 1
                self._last_frame_epoch = now_mono
                self._last_frame_iso = utc_now_iso()
                self._latency_ms = render_ms
                self._state = StreamState.STREAMING
                if window_elapsed >= 1.0:
                    self._fps_actual = fps_frame_count / window_elapsed
                    self._bitrate_kbps = (bytes_in_window * 8.0 / 1000.0) / window_elapsed
                    fps_window_start = now_mono
                    fps_frame_count = 0
                    bytes_in_window = 0
                self._frame_cond.notify_all()

            frame_interval = 1.0 / max(1, self.target_fps)
            sleep_dur = frame_interval - (time.monotonic() - t0)
            if sleep_dur > 0.002:
                self._stop_event.wait(timeout=sleep_dur)

    def _record_failure(self, message: str) -> None:
        safe_msg = mask_rtsp_credentials(message)
        with self._lock:
            self._last_error = safe_msg
            self._frames_dropped += 1

    def _handle_reconnect_backoff(self, reason: str) -> None:
        safe_reason = mask_rtsp_credentials(reason)
        with self._lock:
            self._reconnect_attempts += 1
            attempt = self._reconnect_attempts
            self._last_error = safe_reason
            if (
                self.reconnect_max_attempts > 0
                and attempt >= self.reconnect_max_attempts
            ):
                self._state = StreamState.OFFLINE
                logger.error(
                    "Camera %s reached max reconnect attempts (%d); marking OFFLINE",
                    self.camera_id,
                    self.reconnect_max_attempts,
                )
                self._stop_event.set()
                return
            self._state = StreamState.RECONNECTING

        delay = compute_backoff_delay(
            attempt=attempt,
            base_delay_sec=self.reconnect_base_delay_sec,
            max_delay_sec=self.reconnect_max_delay_sec,
        )
        logger.warning(
            "Stream %s disconnected (%s). Reconnect attempt #%d in %.2fs",
            self.camera_id,
            safe_reason,
            attempt,
            delay,
        )
        self._stop_event.wait(timeout=delay)

    def _transcode_frame(self, frame: np.ndarray) -> Tuple[bytes, np.ndarray]:
        """Resize, stamp telemetry OSD overlay, and encode BGR frame to web-ready JPEG."""
        h, w = frame.shape[:2]
        if w != self.width or h != self.height:
            resized = cv2.resize(
                frame, (self.width, self.height), interpolation=cv2.INTER_LINEAR
            )
        else:
            resized = frame.copy()

        # Draw crisp enterprise CCTV On-Screen Display (OSD) header & timestamp bar
        overlay_frame = resized.copy()
        cv2.rectangle(overlay_frame, (0, 0), (self.width, 36), (12, 14, 16), -1)
        cv2.addWeighted(overlay_frame, 0.72, resized, 0.28, 0, resized)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header_left = f"{self.camera_id.upper()} | {self.name} [{self.location}]"
        cv2.putText(
            resized,
            header_left,
            (14, 24),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.55,
            (225, 235, 230),
            1,
            cv2.LINE_AA,
        )
        cv2.putText(
            resized,
            now_str,
            (max(14, self.width - 255), 24),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.52,
            (180, 210, 195),
            1,
            cv2.LINE_AA,
        )

        # Motion indicator badge on OSD if active
        if self._motion_active:
            cv2.rectangle(resized, (14, 46), (165, 74), (25, 40, 190), -1)
            cv2.putText(
                resized,
                "MOTION ALERT",
                (24, 65),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.50,
                (255, 255, 255),
                1,
                cv2.LINE_AA,
            )

        encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), self.jpeg_quality]
        ok, buf = cv2.imencode(".jpg", resized, encode_params)
        if not ok:
            raise RuntimeError("OpenCV imencode('.jpg') failed on frame")
        return (buf.tobytes(), resized)

    def _encode_status_frame(self, status_label: str) -> bytes:
        canvas = np.zeros((self.height, self.width, 3), dtype=np.uint8)
        canvas[:] = (18, 20, 22)
        cv2.putText(
            canvas,
            status_label,
            (40, self.height // 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.9,
            (200, 210, 215),
            2,
            cv2.LINE_AA,
        )
        ok, buf = cv2.imencode(".jpg", canvas, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
        return buf.tobytes() if ok else b""


class StreamManager:
    """Orchestrates multiple concurrent RTSPStreamWorker pipelines."""

    def __init__(
        self,
        rtsp_transport: str = "tcp",
        buffer_size: int = 2,
        read_timeout_sec: float = 8.0,
        reconnect_base_delay_sec: float = 1.0,
        reconnect_max_delay_sec: float = 30.0,
        reconnect_max_attempts: int = 0,
    ) -> None:
        self.rtsp_transport = rtsp_transport
        self.buffer_size = buffer_size
        self.read_timeout_sec = read_timeout_sec
        self.reconnect_base_delay_sec = reconnect_base_delay_sec
        self.reconnect_max_delay_sec = reconnect_max_delay_sec
        self.reconnect_max_attempts = reconnect_max_attempts

        self._lock = threading.RLock()
        self._workers: Dict[str, RTSPStreamWorker] = {}

    def register_stream(
        self,
        req: StreamRegistrationRequest,
        capture_factory: Optional[Callable[[str], cv2.VideoCapture]] = None,
    ) -> StreamMetrics:
        with self._lock:
            existing = self._workers.get(req.camera_id)
            if existing is not None:
                existing.stop()

            worker = RTSPStreamWorker(
                registration=req,
                rtsp_transport=self.rtsp_transport,
                buffer_size=self.buffer_size,
                read_timeout_sec=self.read_timeout_sec,
                reconnect_base_delay_sec=self.reconnect_base_delay_sec,
                reconnect_max_delay_sec=self.reconnect_max_delay_sec,
                reconnect_max_attempts=self.reconnect_max_attempts,
                capture_factory=capture_factory,
            )
            self._workers[req.camera_id] = worker
            worker.start()
            return worker.get_metrics()

    def remove_stream(self, camera_id: str) -> bool:
        with self._lock:
            worker = self._workers.pop(camera_id, None)
        if worker is None:
            return False
        worker.stop()
        return True

    def get_worker(self, camera_id: str) -> Optional[RTSPStreamWorker]:
        with self._lock:
            return self._workers.get(camera_id)

    def list_metrics(self) -> List[StreamMetrics]:
        with self._lock:
            workers = list(self._workers.values())
        return [w.get_metrics() for w in workers]

    def stop_all(self) -> None:
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
        for w in workers:
            w.stop()
