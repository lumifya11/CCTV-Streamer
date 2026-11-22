"""MediaMTX Control Plane Adapter for WebRTC, HLS, RTSP restreaming, and recording."""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from shared.auth import issue_media_ticket
from shared.config import get_config
from shared.logger import get_logger
from shared.models import DeliveryProtocol
from shared.security import mask_rtsp_credentials

logger = get_logger("transcoder.mediamtx")


class MediaMTXClient:
    """
    Adapter for the private MediaMTX Control API (:9997).
    Configures camera RTSP pull paths, recording toggles, and generates short-lived
    authenticated WebRTC / HLS / MJPEG playback descriptors.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        webrtc_base_url: Optional[str] = None,
        hls_base_url: Optional[str] = None,
        rtsp_base_url: Optional[str] = None,
    ) -> None:
        cfg = get_config()
        self.api_url = (api_url or cfg.mediamtx_api_url).rstrip("/")
        self.webrtc_base_url = (webrtc_base_url or cfg.mediamtx_webrtc_url).rstrip("/")
        self.hls_base_url = (hls_base_url or cfg.mediamtx_hls_url).rstrip("/")
        self.rtsp_base_url = (rtsp_base_url or cfg.mediamtx_rtsp_url).rstrip("/")
        self._registered_paths: Dict[str, Dict[str, Any]] = {}

    def register_camera_path(
        self,
        camera_id: str,
        source_rtsp_url: str,
        record_enabled: bool = False,
        on_demand: bool = True,
    ) -> Dict[str, Any]:
        """
        Register or update a camera path in MediaMTX.
        Falls back gracefully to local state tracking when MediaMTX container is offline.
        """
        path_name = f"live/{camera_id}"
        payload = {
            "source": source_rtsp_url,
            "sourceProtocol": "tcp",
            "sourceOnDemand": on_demand,
            "record": record_enabled,
        }
        mediamtx_online = False
        if not source_rtsp_url.startswith(("demo://", "synthetic://")):
            try:
                with httpx.Client(timeout=1.5) as client:
                    resp = client.post(
                        f"{self.api_url}/v3/config/paths/add/{path_name}",
                        json=payload,
                    )
                    if resp.status_code in (200, 201):
                        mediamtx_online = True
                    elif resp.status_code == 400:
                        patch_resp = client.patch(
                            f"{self.api_url}/v3/config/paths/patch/{path_name}",
                            json=payload,
                        )
                        mediamtx_online = patch_resp.status_code == 200
            except Exception as exc:
                logger.debug(
                    "MediaMTX API at %s not reachable (%s); using OpenCV compatibility plane",
                    self.api_url,
                    exc,
                )

        active_protocol = (
            DeliveryProtocol.WEBRTC
            if mediamtx_online
            else DeliveryProtocol.MJPEG_FALLBACK
        )
        descriptor = {
            "camera_id": camera_id,
            "mediamtx_path": path_name,
            "mediamtx_synced": mediamtx_online,
            "active_protocol": active_protocol,
            "source_masked": mask_rtsp_credentials(source_rtsp_url),
            "record_enabled": record_enabled,
        }
        self._registered_paths[camera_id] = descriptor
        return descriptor

    def remove_camera_path(self, camera_id: str) -> None:
        path_name = f"live/{camera_id}"
        self._registered_paths.pop(camera_id, None)
        try:
            with httpx.Client(timeout=1.0) as client:
                client.delete(f"{self.api_url}/v3/config/paths/delete/{path_name}")
        except Exception:
            pass

    def build_playback_bundle(
        self,
        camera_id: str,
        user_id: str = "operator",
        role: str = "OPERATOR",
        ttl_sec: int = 120,
    ) -> Dict[str, Any]:
        """Issue a short-lived playback ticket and return WebRTC, HLS, MJPEG, and WS URLs."""
        ticket_info = issue_media_ticket(
            camera_id=camera_id,
            user_id=user_id,
            role=role,
            protocol="any",
            ttl_sec=ttl_sec,
        )
        tkt = ticket_info["ticket"]
        path_name = f"live/{camera_id}"
        path_meta = self._registered_paths.get(camera_id, {})
        active_proto = path_meta.get(
            "active_protocol", DeliveryProtocol.MJPEG_FALLBACK
        )

        return {
            **ticket_info,
            "active_delivery_protocol": (
                active_proto.value
                if isinstance(active_proto, DeliveryProtocol)
                else str(active_proto)
            ),
            "urls": {
                "webrtc": f"{self.webrtc_base_url}/{path_name}/whep?ticket={tkt}",
                "hls": f"{self.hls_base_url}/{path_name}/index.m3u8?ticket={tkt}",
                "mjpeg": f"/api/v1/streams/{camera_id}/mjpeg?ticket={tkt}",
                "snapshot": f"/api/v1/streams/{camera_id}/snapshot?ticket={tkt}",
                "websocket": f"/api/v1/streams/{camera_id}/ws?ticket={tkt}",
            },
        }
