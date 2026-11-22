"""Security utilities: fail-closed auth, media route protection, SSRF allowlist, and CIDR validation."""

from __future__ import annotations

import hmac
import ipaddress
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from fastapi import Header, HTTPException, Query, status

from shared.auth import ROLE_HIERARCHY, verify_media_ticket, verify_signed_token
from shared.config import get_config, is_placeholder_secret


def mask_rtsp_credentials(url: str) -> str:
    """Replace password in an RTSP/HTTP URL with asterisks for safe API display and logging."""
    if not url or "://" not in url:
        return url
    try:
        parsed = urlparse(url)
        if parsed.password is not None:
            username = parsed.username or ""
            host_part = parsed.hostname or ""
            if parsed.port:
                host_part = f"{host_part}:{parsed.port}"
            netloc = f"{username}:********@{host_part}"
            return urlunparse(
                (
                    parsed.scheme,
                    netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
    except Exception:
        pass
    return url


def sanitize_uri_template(url: str) -> str:
    """Strip embedded username and password from an RTSP/HTTP URI before database persistence."""
    if not url or "://" not in url:
        return url
    parsed = urlparse(url)
    if parsed.username is None and parsed.password is None:
        return url
    host_part = parsed.hostname or ""
    if parsed.port:
        host_part = f"{host_part}:{parsed.port}"
    return urlunparse(
        (
            parsed.scheme,
            host_part,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def inject_rtsp_credentials(
    rtsp_url: str, username: Optional[str], password: Optional[str]
) -> str:
    """Safely inject RTSP credentials into a stream URL in memory for authorized connections."""
    if not rtsp_url or not username:
        return rtsp_url
    parsed = urlparse(rtsp_url)
    if parsed.username:
        return rtsp_url
    host_part = parsed.hostname or ""
    if parsed.port:
        host_part = f"{host_part}:{parsed.port}"
    cred_part = f"{username}:{password}@" if password else f"{username}@"
    return urlunparse(
        (
            parsed.scheme,
            f"{cred_part}{host_part}",
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def validate_subnet_cidr(
    cidr: str,
    max_hosts: int = 1024,
    allow_public: bool = False,
) -> ipaddress.IPv4Network:
    """
    Validate a subnet CIDR string:
    - Ensures it does not exceed safe scanning bounds (`max_hosts`)
    - Blocks arbitrary public internet CIDR ranges by default (`allow_public=False`)
    """
    try:
        network = ipaddress.IPv4Network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 subnet CIDR '{cidr}': {exc}") from exc

    if network.num_addresses > max_hosts:
        raise ValueError(
            f"Subnet '{cidr}' contains {network.num_addresses} addresses, "
            f"exceeding maximum allowed scan size ({max_hosts})."
        )

    if not allow_public:
        # Allow private RFC1918 networks or loopback in local test fixtures
        if not (network.is_private or network.is_loopback):
            raise ValueError(
                f"Subnet '{cidr}' is not an authorized private network range. "
                "Scanning arbitrary public internet ranges is prohibited."
            )
    return network


def validate_target_destination(
    url_or_host: str,
    approved_cidrs: Optional[List[str]] = None,
    allow_loopback: bool = False,
) -> str:
    """
    SSRF & Egress destination validator for stream sources and ONVIF XAddr URLs:
    - Resolves hostname and validates IP address
    - Rejects cloud metadata / link-local (169.254.0.0/16, fe80::/10), multicast, broadcast, unspecified
    - Rejects loopback unless explicitly permitted for local test harnesses
    - Rejects public internet addresses and enforces approved CIDR scopes if provided
    """
    clean = url_or_host.strip()
    if clean.startswith(("demo://", "synthetic://")):
        cfg = get_config()
        if cfg.is_production() and cfg.deployment_profile != "demo":
            raise ValueError("Demo/synthetic stream sources are disabled in production mode.")
        return clean

    if "://" in clean:
        parsed = urlparse(clean)
        host = parsed.hostname or ""
    else:
        host = clean

    if not host:
        raise ValueError("Target URL or destination must specify a valid hostname or IP.")

    try:
        ip_obj = ipaddress.ip_address(host)
        resolved_ips = [ip_obj]
    except ValueError:
        try:
            addr_info = socket.getaddrinfo(host, None)
            resolved_ips = [ipaddress.ip_address(item[4][0]) for item in addr_info]
        except OSError as exc:
            raise ValueError(f"Unable to resolve destination hostname '{host}': {exc}") from exc

    if not resolved_ips:
        raise ValueError(f"Destination '{host}' did not resolve to any IP address.")

    approved_networks = []
    if approved_cidrs:
        for cidr in approved_cidrs:
            try:
                approved_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

    for ip_item in resolved_ips:
        if ip_item.is_link_local or str(ip_item).startswith("169.254."):
            raise ValueError(
                f"SSRF protection blocked link-local / cloud metadata address '{ip_item}'."
            )
        if ip_item.is_multicast or ip_item.is_unspecified or ip_item == ipaddress.ip_address("255.255.255.255"):
            raise ValueError(
                f"SSRF protection blocked multicast/broadcast/unspecified address '{ip_item}'."
            )
        if ip_item.is_loopback and not allow_loopback:
            raise ValueError(
                f"SSRF protection blocked loopback destination '{ip_item}'."
            )
        if not ip_item.is_private and not (ip_item.is_loopback and allow_loopback):
            raise ValueError(
                f"SSRF protection blocked external/public internet destination '{ip_item}'."
            )
        if approved_networks:
            if not any(ip_item in net for net in approved_networks):
                raise ValueError(
                    f"Destination '{ip_item}' is outside approved site network scopes."
                )

    return str(resolved_ips[0])


def validate_onvif_xaddr(
    xaddr: str,
    expected_device_ip: Optional[str] = None,
    approved_cidrs: Optional[List[str]] = None,
    allow_loopback: bool = False,
) -> str:
    """
    Validate an untrusted ONVIF XAddr received from the network before sending SOAP requests.
    Ensures HTTP/HTTPS scheme, SSRF destination safety, and exact IP match with the device.
    """
    parsed = urlparse((xaddr or "").strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Invalid ONVIF XAddr scheme '{parsed.scheme}'. Allowed: http, https.")
    resolved_ip = validate_target_destination(
        xaddr, approved_cidrs=approved_cidrs, allow_loopback=allow_loopback
    )
    if expected_device_ip and resolved_ip != expected_device_ip:
        raise ValueError(
            f"ONVIF XAddr host '{resolved_ip}' does not match discovered device IP '{expected_device_ip}'."
        )
    return xaddr.strip()


def validate_rtsp_source(
    source: str,
    approved_cidrs: Optional[List[str]] = None,
    allow_loopback: Optional[bool] = None,
) -> str:
    """Validate an RTSP/HTTP stream source URL and apply SSRF destination checks."""
    clean = source.strip()
    cfg = get_config()
    if clean.startswith(("demo://", "synthetic://")):
        if cfg.is_production() and cfg.deployment_profile != "demo":
            raise ValueError("Demo/synthetic stream sources are disabled in production mode.")
        return clean

    parsed = urlparse(clean)
    if parsed.scheme.lower() not in ("rtsp", "rtsps", "http", "https"):
        raise ValueError(
            f"Unsupported stream scheme '{parsed.scheme}'. Allowed: rtsp, rtsps, http, https."
        )
    if not parsed.hostname:
        raise ValueError("Stream URL must include a valid hostname or IP address.")

    loopback_ok = (
        allow_loopback
        if allow_loopback is not None
        else (not cfg.is_production() and cfg.allow_loopback_in_tests)
    )
    validate_target_destination(
        clean, approved_cidrs=approved_cidrs, allow_loopback=loopback_ok
    )
    return clean


def _authenticate_request_credentials(
    x_api_key: Optional[str],
    authorization: Optional[str],
    ticket: Optional[str] = None,
    required_camera_id: Optional[str] = None,
    min_role: str = "VIEWER",
) -> Dict[str, Any]:
    """
    Core fail-closed authentication verifier:
    - In production (`ENVIRONMENT=production` or `FAIL_CLOSED_AUTH=true`), rejects requests
      with 503/401 if `API_SECRET_KEY` is missing or set to a `change-me` placeholder.
    - Accepts signed Bearer JWT tokens, short-lived camera-scoped media tickets, or valid API key.
    """
    cfg = get_config()
    expected_key = cfg.api_secret_key
    must_fail_closed = cfg.is_production() or cfg.fail_closed_auth

    if must_fail_closed and is_placeholder_secret(expected_key):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Production authentication failed closed: API_SECRET_KEY is unset or uses a placeholder.",
        )

    # 1. Check short-lived media ticket if provided
    if ticket:
        ticket_payload = verify_media_ticket(ticket, required_camera_id=required_camera_id)
        if ticket_payload:
            return {
                "sub": ticket_payload.get("sub", "ticket-user"),
                "role": ticket_payload.get("role", "VIEWER"),
                "auth_method": "media_ticket",
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or out-of-scope media playback ticket.",
        )

    # 2. Check Authorization: Bearer <jwt_or_api_key>
    bearer_token = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer_token = authorization[7:].strip()

    if bearer_token:
        jwt_payload = verify_signed_token(bearer_token)
        if jwt_payload:
            user_role = jwt_payload.get("role", "VIEWER")
            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(min_role, 10):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient role '{user_role}'. Required: '{min_role}'.",
                )
            return jwt_payload
        if not is_placeholder_secret(expected_key) and hmac.compare_digest(
            bearer_token, expected_key
        ):
            return {"sub": "api-key-client", "role": "OWNER", "auth_method": "api_key"}

    # 3. Check X-API-Key header
    if x_api_key:
        if not is_placeholder_secret(expected_key) and hmac.compare_digest(
            x_api_key, expected_key
        ):
            return {"sub": "api-key-client", "role": "OWNER", "auth_method": "api_key"}
        if must_fail_closed or not is_placeholder_secret(expected_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API authentication credentials.",
            )

    # 4. If a real secret key is configured or fail-closed mode is active, reject unauthenticated calls
    if must_fail_closed or not is_placeholder_secret(expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide Bearer token, X-API-Key, or valid playback ticket.",
        )

    # Development/test fallback only when ENVIRONMENT != production and FAIL_CLOSED_AUTH is false
    return {"sub": "dev-operator", "role": "OWNER", "auth_method": "dev_fallback"}


async def verify_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> bool:
    """FastAPI dependency enforcing fail-closed API authentication."""
    _authenticate_request_credentials(x_api_key=x_api_key, authorization=authorization)
    return True


async def verify_media_access(
    camera_id: Optional[str] = None,
    ticket: Optional[str] = Query(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> Dict[str, Any]:
    """FastAPI dependency protecting snapshot, MJPEG, WebRTC, HLS, and recording routes."""
    return _authenticate_request_credentials(
        x_api_key=x_api_key,
        authorization=authorization,
        ticket=ticket,
        required_camera_id=camera_id,
    )


def expand_subnet_hosts(
    subnets: List[str],
    max_hosts_per_subnet: int = 1024,
    allow_public: bool = False,
) -> List[str]:
    """Expand a list of approved CIDR subnets or single IPs into distinct host IP strings."""
    hosts: List[str] = []
    seen = set()
    for entry in subnets:
        item = entry.strip()
        if not item:
            continue
        if "/" not in item:
            net = validate_subnet_cidr(
                f"{item}/32", max_hosts=max_hosts_per_subnet, allow_public=allow_public
            )
            ip_str = str(net.network_address)
            if ip_str not in seen:
                seen.add(ip_str)
                hosts.append(ip_str)
        else:
            net = validate_subnet_cidr(
                item, max_hosts=max_hosts_per_subnet, allow_public=allow_public
            )
            if net.num_addresses == 1:
                ip_str = str(net.network_address)
                if ip_str not in seen:
                    seen.add(ip_str)
                    hosts.append(ip_str)
            else:
                for host in net.hosts():
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        hosts.append(ip_str)
    return hosts
