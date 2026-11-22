"""Per-camera Detection Zones and Privacy Mask Zones for OpenCV Frame Analytics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import cv2
import numpy as np


@dataclass
class ZoneRect:
    """Normalized rectangle zone [x1, y1, x2, y2] in 0.0..1.0 coordinates."""

    name: str
    x1: float
    y1: float
    x2: float
    y2: float
    is_privacy_mask: bool = False

    def to_pixel_bounds(self, width: int, height: int) -> Tuple[int, int, int, int]:
        px1 = max(0, min(width, int(round(self.x1 * width))))
        py1 = max(0, min(height, int(round(self.y1 * height))))
        px2 = max(px1 + 1, min(width, int(round(self.x2 * width))))
        py2 = max(py1 + 1, min(height, int(round(self.y2 * height))))
        return (px1, py1, px2, py2)


def apply_privacy_masks(frame: np.ndarray, zones: List[ZoneRect]) -> np.ndarray:
    """Black out user-defined privacy mask zones before analysis or storage."""
    privacy_zones = [z for z in zones if z.is_privacy_mask]
    if not privacy_zones:
        return frame
    masked = frame.copy()
    h, w = masked.shape[:2]
    for z in privacy_zones:
        x1, y1, x2, y2 = z.to_pixel_bounds(w, h)
        cv2.rectangle(masked, (x1, y1), (x2, y2), (0, 0, 0), -1)
    return masked


def match_detection_zone(
    box: Dict[str, int],
    width: int,
    height: int,
    zones: List[ZoneRect],
) -> str:
    """Return the name of the detection zone containing the bounding box center (or 'full_frame')."""
    detection_zones = [z for z in zones if not z.is_privacy_mask]
    if not detection_zones:
        return "full_frame"
    cx = box["x"] + (box["width"] / 2.0)
    cy = box["y"] + (box["height"] / 2.0)
    for z in detection_zones:
        x1, y1, x2, y2 = z.to_pixel_bounds(width, height)
        if x1 <= cx <= x2 and y1 <= cy <= y2:
            return z.name
    return "outside_zone"
