"""Authentication, RBAC, Session Management, and Short-Lived Camera Stream Tickets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from shared.audit import record_audit_event
from shared.config import get_config, is_placeholder_secret
from shared.database import DatabaseManager, get_db
from shared.models import UserRole, utc_now_iso

ROLE_HIERARCHY: Dict[str, int] = {
    UserRole.VIEWER.value: 10,
    UserRole.OPERATOR.value: 20,
    UserRole.ADMIN.value: 30,
    UserRole.OWNER.value: 40,
}

_LOGIN_FAILURES_LOCK = threading.Lock()
_LOGIN_FAILURES: Dict[str, List[float]] = {}
MAX_LOGIN_ATTEMPTS_WINDOW = 5
LOGIN_WINDOW_SEC = 60.0


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with 200,000 iterations."""
    raw_salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), raw_salt, iterations=200_000, dklen=32
    )
    return f"pbkdf2_sha256$200000${raw_salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored PBKDF2-HMAC-SHA256 hash in constant time."""
    try:
        algo, iter_str, salt_hex, hash_hex = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations=iterations, dklen=32
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def _get_signing_key() -> bytes:
    cfg = get_config()
    key = cfg.api_secret_key
    if cfg.is_production() and is_placeholder_secret(key):
        raise RuntimeError(
            "API_SECRET_KEY is missing or set to a placeholder in production mode."
        )
    if not key:
        key = "dev-ephemeral-signing-key-not-for-production-use"
    return key.encode("utf-8")


def create_signed_token(payload: Dict[str, Any], ttl_sec: int = 900) -> str:
    """Create a compact HMAC-SHA256 signed token (JWT-compatible format)."""
    now = int(time.time())
    body = dict(payload)
    body["iat"] = now
    body["exp"] = now + ttl_sec
    body.setdefault("jti", uuid.uuid4().hex[:16])

    header_b64 = (
        base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}')
        .rstrip(b"=")
        .decode("ascii")
    )
    payload_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(_get_signing_key(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_signed_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify an HMAC-SHA256 signed token and check expiration."""
    if not token or token.count(".") != 2:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(_get_signing_key(), signing_input, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(sig_b64, expected_b64):
            return None

        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def issue_media_ticket(
    camera_id: str,
    user_id: str = "operator",
    role: str = "OPERATOR",
    protocol: str = "any",
    ttl_sec: int = 120,
) -> Dict[str, Any]:
    """
    Issue a short-lived, camera-scoped playback ticket for WebSocket, MJPEG, WebRTC, or HLS.
    Prevents embedding permanent API secrets in browser/mobile URLs.
    """
    ticket_id = f"tkt-{uuid.uuid4().hex[:14]}"
    token = create_signed_token(
        {
            "sub": user_id,
            "role": role,
            "ticket_type": "media_playback",
            "camera_id": camera_id,
            "protocol": protocol,
            "jti": ticket_id,
        },
        ttl_sec=ttl_sec,
    )
    return {
        "ticket": token,
        "ticket_id": ticket_id,
        "camera_id": camera_id,
        "protocol": protocol,
        "expires_in_sec": ttl_sec,
    }


def verify_media_ticket(token: str, required_camera_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Verify a short-lived media playback ticket and enforce camera scope."""
    payload = verify_signed_token(token)
    if not payload or payload.get("ticket_type") != "media_playback":
        return None
    if required_camera_id and payload.get("camera_id") not in (required_camera_id, "*"):
        return None
    return payload


def check_login_throttled(username: str) -> bool:
    """Return True if the username has exceeded failed login attempts within the window."""
    now = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        history = [t for t in _LOGIN_FAILURES.get(username, []) if now - t < LOGIN_WINDOW_SEC]
        _LOGIN_FAILURES[username] = history
        return len(history) >= MAX_LOGIN_ATTEMPTS_WINDOW


def record_login_failure(username: str) -> None:
    now = time.monotonic()
    with _LOGIN_FAILURES_LOCK:
        history = [t for t in _LOGIN_FAILURES.get(username, []) if now - t < LOGIN_WINDOW_SEC]
        history.append(now)
        _LOGIN_FAILURES[username] = history


def clear_login_failures(username: str) -> None:
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(username, None)


def bootstrap_owner_account(
    username: str,
    password: str,
    db: Optional[DatabaseManager] = None,
) -> Dict[str, Any]:
    """One-time owner setup flow; raises ValueError if an owner already exists."""
    database = db or get_db()
    existing = database.fetchone("SELECT user_id FROM users WHERE role = 'OWNER' LIMIT 1")
    if existing:
        raise ValueError("Owner bootstrap has already been completed.")
    if len(password) < 8:
        raise ValueError("Owner password must be at least 8 characters long.")

    user_id = f"usr-{uuid.uuid4().hex[:12]}"
    pwd_hash = hash_password(password)
    now = utc_now_iso()
    database.execute(
        """
        INSERT INTO users (user_id, username, password_hash, role, mfa_enabled, status, created_at)
        VALUES (?, ?, ?, 'OWNER', 0, 'ACTIVE', ?)
        """,
        (user_id, username.strip(), pwd_hash, now),
    )
    record_audit_event(
        action="AUTH_BOOTSTRAP_OWNER",
        target_type="USER",
        target_id=user_id,
        actor=username,
        actor_role="OWNER",
        db=database,
    )
    return {
        "user_id": user_id,
        "username": username.strip(),
        "role": UserRole.OWNER.value,
        "created_at": now,
    }


def authenticate_user(
    username: str,
    password: str,
    device_name: str = "web",
    db: Optional[DatabaseManager] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Authenticate a user with throttling and issue access + refresh tokens."""
    database = db or get_db()
    clean_user = username.strip()
    if check_login_throttled(clean_user):
        record_audit_event(
            action="AUTH_LOGIN_THROTTLED",
            target_type="USER",
            target_id=clean_user,
            actor=clean_user,
            actor_role="ANONYMOUS",
            result="DENIED",
            db=database,
        )
        return (None, "Too many failed login attempts. Please wait before retrying.")

    user = database.fetchone(
        "SELECT * FROM users WHERE username = ? AND status = 'ACTIVE'", (clean_user,)
    )
    if not user or not verify_password(password, user["password_hash"]):
        record_login_failure(clean_user)
        record_audit_event(
            action="AUTH_LOGIN_FAILED",
            target_type="USER",
            target_id=clean_user,
            actor=clean_user,
            actor_role="ANONYMOUS",
            result="FAILURE",
            db=database,
        )
        return (None, "Invalid username or password.")

    clear_login_failures(clean_user)
    session_id = f"ses-{uuid.uuid4().hex[:14]}"
    refresh_token = secrets.token_urlsafe(32)
    refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
    expires_at = time.time() + (86400 * 7)

    database.execute(
        """
        INSERT INTO sessions (session_id, user_id, refresh_token_hash, device_name, expires_at, revoked, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)
        """,
        (session_id, user["user_id"], refresh_hash, device_name, expires_at, utc_now_iso()),
    )

    access_token = create_signed_token(
        {
            "sub": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "session_id": session_id,
            "token_type": "access",
        },
        ttl_sec=900,
    )
    record_audit_event(
        action="AUTH_LOGIN_SUCCESS",
        target_type="SESSION",
        target_id=session_id,
        actor=user["username"],
        actor_role=user["role"],
        db=database,
    )
    return (
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "session_id": session_id,
            "user": {
                "user_id": user["user_id"],
                "username": user["username"],
                "role": user["role"],
            },
        },
        None,
    )
