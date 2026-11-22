"""Structured logging with automatic credential redaction for CCTV-Streamer."""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone

_RTSP_CRED_PATTERN = re.compile(r"(rtsp[s]?://[^:\s/]+:)([^@\s/]+)(@)", re.IGNORECASE)
_BEARER_PATTERN = re.compile(r"(Bearer\s+)([A-Za-z0-9._\-]+)", re.IGNORECASE)


def redact_sensitive_text(text: str) -> str:
    """Mask passwords embedded in RTSP URLs or Authorization headers."""
    if not text:
        return text
    redacted = _RTSP_CRED_PATTERN.sub(r"\1********\3", text)
    redacted = _BEARER_PATTERN.sub(r"\1********", redacted)
    return redacted


class CredentialRedactingFilter(logging.Filter):
    """Logging filter that ensures RTSP passwords and tokens never appear in logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    redact_sensitive_text(arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: (redact_sensitive_text(v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
        return True


class JsonLogFormatter(logging.Formatter):
    """Structured JSON log formatter for production container observability."""

    def __init__(self, service_name: str) -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service_name,
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive_text(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact_sensitive_text(
                self.formatException(record.exc_info)
            )
        return json.dumps(payload)


def get_logger(service_name: str) -> logging.Logger:
    """Create or retrieve a configured logger with credential redaction."""
    logger = logging.getLogger(service_name)
    if logger.handlers:
        return logger

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(CredentialRedactingFilter())

    log_format = os.getenv("LOG_FORMAT", "json").lower()
    if log_format == "json":
        handler.setFormatter(JsonLogFormatter(service_name))
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            )
        )

    logger.addHandler(handler)
    logger.propagate = False
    return logger
