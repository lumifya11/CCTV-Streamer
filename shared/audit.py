"""Durable security audit log recorder with automatic secret redaction."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from shared.database import DatabaseManager, get_db
from shared.logger import get_logger, redact_sensitive_text
from shared.models import utc_now_iso

logger = get_logger("shared.audit")

_SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "refresh_token",
    "access_token",
    "ticket",
    "encrypted_secret",
    "api_key",
}


def _sanitize_details(details: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not details:
        return {}
    clean: Dict[str, Any] = {}
    for k, v in details.items():
        if k.lower() in _SENSITIVE_KEYS:
            clean[k] = "********"
        elif isinstance(v, str):
            clean[k] = redact_sensitive_text(v)
        else:
            clean[k] = v
    return clean


def record_audit_event(
    action: str,
    target_type: str,
    target_id: str,
    actor: str = "system",
    actor_role: str = "SYSTEM",
    source_ip: str = "127.0.0.1",
    result: str = "SUCCESS",
    details: Optional[Dict[str, Any]] = None,
    db: Optional[DatabaseManager] = None,
) -> Dict[str, Any]:
    """Persist an immutable audit trail event in the database."""
    database = db or get_db()
    audit_id = f"aud-{uuid.uuid4().hex[:12]}"
    timestamp = utc_now_iso()
    safe_details = _sanitize_details(details)

    database.execute(
        """
        INSERT INTO audit_events (
            audit_id, actor, actor_role, action, target_type,
            target_id, source_ip, result, details_json, timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit_id,
            actor,
            actor_role,
            action,
            target_type,
            target_id,
            source_ip,
            result,
            json.dumps(safe_details),
            timestamp,
        ),
    )
    logger.info(
        "AUDIT | actor=%s (%s) action=%s target=%s:%s result=%s",
        actor,
        actor_role,
        action,
        target_type,
        target_id,
        result,
    )
    return {
        "audit_id": audit_id,
        "actor": actor,
        "actor_role": actor_role,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "source_ip": source_ip,
        "result": result,
        "details": safe_details,
        "timestamp": timestamp,
    }


def list_audit_events(
    limit: int = 100,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    db: Optional[DatabaseManager] = None,
) -> List[Dict[str, Any]]:
    database = db or get_db()
    query = "SELECT * FROM audit_events WHERE 1=1"
    params: List[Any] = []
    if action:
        query += " AND action = ?"
        params.append(action)
    if target_type:
        query += " AND target_type = ?"
        params.append(target_type)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(max(1, min(500, limit)))

    rows = database.fetchall(query, tuple(params))
    for r in rows:
        r["details"] = json.loads(r.pop("details_json", "{}") or "{}")
    return rows
