"""ONVIF WS-Discovery multicast scanner and SOAP Media profile RTSP resolver."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import time
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from shared.logger import get_logger
from shared.models import RTSPEndpoint
from shared.security import mask_rtsp_credentials

logger = get_logger("discovery.onvif")

WS_DISCOVERY_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action a:mustUnderstand="true" xmlns:a="http://www.w3.org/2003/05/soap-envelope">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""


@dataclass
class OnvifProbeDevice:
    """Intermediate representation of an ONVIF camera discovered via WS-Discovery."""

    ip_address: str
    xaddr: str
    endpoint_reference: str = ""
    types: str = ""
    scopes: List[str] = field(default_factory=list)
    manufacturer: str = "ONVIF Camera"
    model: str = "NetworkVideoTransmitter"
    location: str = "Main Facility"
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    rtsp_endpoints: List[RTSPEndpoint] = field(default_factory=list)
    response_time_ms: float = 0.0


def build_ws_discovery_probe(message_id: Optional[str] = None) -> bytes:
    """Generate a SOAP WS-Discovery Probe payload for ONVIF NetworkVideoTransmitter devices."""
    msg_id = message_id or str(uuid.uuid4())
    xml_payload = WS_DISCOVERY_PROBE_TEMPLATE.format(message_id=msg_id)
    return xml_payload.encode("utf-8")


def build_wsse_security_header(username: str, password: str) -> str:
    """Create an ONVIF WS-UsernameToken PasswordDigest SOAP header."""
    nonce_bytes = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest_input = nonce_bytes + created.encode("utf-8") + password.encode("utf-8")
    password_digest = base64.b64encode(hashlib.sha1(digest_input).digest()).decode(
        "ascii"
    )
    nonce_b64 = base64.b64encode(nonce_bytes).decode("ascii")

    return f"""<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken>
        <Username>{username}</Username>
        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</Password>
        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</Nonce>
        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>
      </UsernameToken>
    </Security>"""


def _extract_scope_Metadata(scopes: List[str]) -> Tuple[str, str, str]:
    """Parse ONVIF scope URIs for manufacturer/name, hardware model, and location."""
    manufacturer = "ONVIF"
    model = "Network Camera"
    location = "Sector A"

    for scope in scopes:
        decoded = urllib.parse.unquote(scope)
        lower = decoded.lower()
        if "onvif://www.onvif.org/name/" in lower:
            val = decoded.split("/name/", 1)[-1].strip("/")
            if val:
                manufacturer = val
        elif "onvif://www.onvif.org/hardware/" in lower:
            val = decoded.split("/hardware/", 1)[-1].strip("/")
            if val:
                model = val
        elif "onvif://www.onvif.org/location/" in lower:
            val = decoded.split("/location/", 1)[-1].strip("/")
            if val:
                location = val.replace("_", " ")
    return manufacturer, model, location


def parse_ws_discovery_response(
    xml_bytes: bytes, sender_ip: Optional[str] = None, elapsed_ms: float = 0.0
) -> Optional[OnvifProbeDevice]:
    """Parse a WS-Discovery ProbeMatches SOAP response into an OnvifProbeDevice."""
    if not xml_bytes or b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
        # Reject XML payloads with DTD/Entity declarations to prevent XXE attacks
        logger.warning("Rejected WS-Discovery response containing DTD/ENTITY declaration")
        return None

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        logger.debug("Invalid XML in WS-Discovery response: %s", exc)
        return None

    xaddrs_text = ""
    epr_text = ""
    types_text = ""
    scopes_text = ""

    for elem in root.iter():
        tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if tag_local == "XAddrs" and elem.text:
            xaddrs_text = elem.text.strip()
        elif tag_local == "Address" and elem.text and not epr_text:
            epr_text = elem.text.strip()
        elif tag_local == "Types" and elem.text:
            types_text = elem.text.strip()
        elif tag_local == "Scopes" and elem.text:
            scopes_text = elem.text.strip()

    if not xaddrs_text and not sender_ip:
        return None

    first_xaddr = xaddrs_text.split()[0] if xaddrs_text else f"http://{sender_ip}/onvif/device_service"
    parsed_url = urllib.parse.urlparse(first_xaddr)
    ip_address = parsed_url.hostname or sender_ip or ""
    if not ip_address:
        return None

    scopes_list = [s for s in scopes_text.split() if s]
    manufacturer, model, location = _extract_scope_Metadata(scopes_list)

    return OnvifProbeDevice(
        ip_address=ip_address,
        xaddr=first_xaddr,
        endpoint_reference=epr_text,
        types=types_text,
        scopes=scopes_list,
        manufacturer=manufacturer,
        model=model,
        location=location,
        response_time_ms=round(elapsed_ms, 2),
    )


class OnvifScanner:
    """Performs WS-Discovery multicast scans and ONVIF SOAP RTSP stream URI extraction."""

    def __init__(
        self,
        multicast_host: str = "239.255.255.250",
        multicast_port: int = 3702,
        timeout_sec: float = 2.0,
        username: str = "admin",
        password: str = "",
    ) -> None:
        self.multicast_host = multicast_host
        self.multicast_port = multicast_port
        self.timeout_sec = timeout_sec
        self.username = username
        self.password = password

    def discover_multicast(self) -> List[OnvifProbeDevice]:
        """Broadcast WS-Discovery UDP Probe and collect ONVIF camera responses."""
        discovered: Dict[str, OnvifProbeDevice] = {}
        probe_payload = build_ws_discovery_probe()
        start_time = time.monotonic()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(min(0.5, self.timeout_sec))

            try:
                sock.sendto(probe_payload, (self.multicast_host, self.multicast_port))
            except OSError as exc:
                logger.warning(
                    "ONVIF multicast send to %s:%d failed (%s)",
                    self.multicast_host,
                    self.multicast_port,
                    exc,
                )
                return []

            deadline = start_time + self.timeout_sec
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(min(0.4, remaining))
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                elapsed_ms = (time.monotonic() - start_time) * 1000.0
                sender_ip = addr[0] if addr else None
                device = parse_ws_discovery_response(
                    data, sender_ip=sender_ip, elapsed_ms=elapsed_ms
                )
                if device and device.ip_address not in discovered:
                    # Query SOAP stream URI if possible
                    self.enrich_device_via_soap(device)
                    discovered[device.ip_address] = device
                    logger.info(
                        "Discovered ONVIF device at %s (%s %s) in %.1f ms",
                        device.ip_address,
                        device.manufacturer,
                        device.model,
                        device.response_time_ms,
                    )
        finally:
            sock.close()

        return list(discovered.values())

    def enrich_device_via_soap(
        self,
        device: OnvifProbeDevice,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """Attempt ONVIF GetProfiles / GetStreamUri SOAP calls to resolve RTSP endpoints."""
        user = username if username is not None else self.username
        pwd = password if password is not None else self.password
        security_block = build_wsse_security_header(user, pwd) if user else ""

        get_stream_body = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>{security_block}</s:Header>
  <s:Body>
    <trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>RTP-Unicast</tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>Profile_1</trt:ProfileToken>
    </trt:GetStreamUri>
  </s:Body>
</s:Envelope>"""

        try:
            req = urllib.request.Request(
                device.xaddr,
                data=get_stream_body.encode("utf-8"),
                headers={
                    "Content-Type": "application/soap+xml; charset=utf-8",
                    "User-Agent": "CCTV-Streamer-ONVIF/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                raw_xml = resp.read()
                rtsp_uri = self._extract_uri_from_soap(raw_xml)
                if rtsp_uri:
                    parsed = urllib.parse.urlparse(rtsp_uri)
                    device.rtsp_endpoints.append(
                        RTSPEndpoint(
                            url=mask_rtsp_credentials(rtsp_uri),
                            transport="tcp",
                            port=parsed.port or 554,
                            path=parsed.path or "/",
                            profile_token="Profile_1",
                            verified=True,
                        )
                    )
        except Exception as exc:
            logger.debug(
                "ONVIF SOAP GetStreamUri fallback for %s (%s)",
                device.ip_address,
                exc,
            )

        # Ensure a standard ONVIF RTSP endpoint candidate is attached if SOAP didn't return one
        if not device.rtsp_endpoints:
            default_url = f"rtsp://{device.ip_address}:554/Streaming/Channels/101"
            device.rtsp_endpoints.append(
                RTSPEndpoint(
                    url=default_url,
                    transport="tcp",
                    port=554,
                    path="/Streaming/Channels/101",
                    profile_token="Profile_1",
                    verified=False,
                )
            )

    @staticmethod
    def _extract_uri_from_soap(xml_bytes: bytes) -> Optional[str]:
        if not xml_bytes or b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
            return None
        try:
            root = ET.fromstring(xml_bytes)
            for elem in root.iter():
                local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if local == "Uri" and elem.text and elem.text.strip().startswith("rtsp"):
                    return elem.text.strip()
        except ET.ParseError:
            pass
        match = re.search(rb"(rtsp[s]?://[^\s<\"']+)", xml_bytes)
        if match:
            return match.group(1).decode("utf-8", errors="ignore")
        return None
