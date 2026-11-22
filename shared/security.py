"""Security utilities: credential masking, CIDR validation, RTSP URL sanitization, and API auth."""

from __future__ import annotations

import hmac
import ipaddress
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

from fastapi import Header, HTTPException, status

from shared.config import get_config


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


def inject_rtsp_credentials(
    rtsp_url: str, username: Optional[str], password: Optional[str]
) -> str:
    """Safely inject RTSP credentials into a stream URL if not already present."""
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


def validate_subnet_cidr(cidr: str, max_hosts: int = 1024) -> ipaddress.IPv4Network:
    """Validate a subnet CIDR string and ensure it does not exceed safe scanning bounds."""
    try:
        network = ipaddress.IPv4Network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 subnet CIDR '{cidr}': {exc}") from exc

    if network.num_addresses > max_hosts:
        raise ValueError(
            f"Subnet '{cidr}' contains {network.num_addresses} addresses, "
            f"exceeding maximum allowed scan size ({max_hosts})."
        )
    return network


def validate_rtsp_source(source: str) -> str:
    """Validate an RTSP URL or synthetic demo identifier to prevent command/file injection."""
    clean = source.strip()
    if clean.startswith("demo://") or clean.startswith("synthetic://"):
        return clean
    parsed = urlparse(clean)
    if parsed.scheme.lower() not in ("rtsp", "rtsps", "http", "https"):
        raise ValueError(
            f"Unsupported stream scheme '{parsed.scheme}'. Allowed: rtsp, rtsps, http, demo."
        )
    if not parsed.hostname:
        raise ValueError("Stream URL must include a valid hostname or IP address.")
    return clean


async def verify_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> bool:
    """FastAPI dependency to verify API key or Bearer token when API_SECRET_KEY is configured."""
    cfg = get_config()
    expected = cfg.api_secret_key
    # If no secret key is enforced or default placeholder is active in dev/demo mode, allow request
    if not expected or expected.startswith("change-me"):
        return True

    candidate = x_api_key or ""
    if not candidate and authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()

    if not candidate or not hmac.compare_digest(candidate, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API authentication credentials.",
        )
    return True


def expand_subnet_hosts(subnets: List[str], max_hosts_per_subnet: int = 1024) -> List[str]:
    """Expand a list of CIDR subnets or single IPs into distinct host IP strings."""
    hosts: List[str] = []
    seen = set()
    for entry in subnets:
        item = entry.strip()
        if not item:
            continue
        if "/" not in item:
            ip_obj = ipaddress.IPv4Address(item)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                hosts.append(ip_str)
        else:
            net = validate_subnet_cidr(item, max_hosts=max_hosts_per_subnet)
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
