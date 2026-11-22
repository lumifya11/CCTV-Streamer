"""Unit and integration tests for the ONVIF & Port Scanner Camera Discovery Microservice."""

from __future__ import annotations

import socket
import threading
from fastapi.testclient import TestClient

from services.discovery.app import app as discovery_app
from services.discovery.onvif_scanner import (
    OnvifScanner,
    build_ws_discovery_probe,
    build_wsse_security_header,
    parse_ws_discovery_response,
)
from services.discovery.port_scanner import (
    NetworkPortScanner,
    probe_tcp_port,
    verify_rtsp_endpoint,
)


SAMPLE_ONVIF_PROBE_MATCH_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
                   xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                   xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
                   xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <SOAP-ENV:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>urn:uuid:a1b2c3d4-e5f6-7890-1234-56789abcdef0</wsa:Address>
        </wsa:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>
          onvif://www.onvif.org/type/video_encoder
          onvif://www.onvif.org/name/Axis_Communications
          onvif://www.onvif.org/hardware/Q6135-LE
          onvif://www.onvif.org/location/Perimeter_North
        </d:Scopes>
        <d:XAddrs>http://192.168.1.150:80/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""


def test_ws_discovery_probe_generation():
    probe = build_ws_discovery_probe("11111111-2222-3333-4444-555555555555")
    assert b"NetworkVideoTransmitter" in probe
    assert b"uuid:11111111-2222-3333-4444-555555555555" in probe


def test_wsse_security_header():
    hdr = build_wsse_security_header("admin", "secretPass123")
    assert "<Username>admin</Username>" in hdr
    assert "PasswordDigest" in hdr
    assert "secretPass123" not in hdr


def test_parse_ws_discovery_response_extracts_metadata():
    device = parse_ws_discovery_response(SAMPLE_ONVIF_PROBE_MATCH_XML, elapsed_ms=4.2)
    assert device is not None
    assert device.ip_address == "192.168.1.150"
    assert device.xaddr == "http://192.168.1.150:80/onvif/device_service"
    assert device.manufacturer == "Axis_Communications"
    assert device.model == "Q6135-LE"
    assert device.location == "Perimeter North"


def test_parse_ws_discovery_rejects_xxe_dtd():
    malicious_xml = b"""<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <ProbeMatches>&xxe;</ProbeMatches>"""
    assert parse_ws_discovery_response(malicious_xml) is None


def test_extract_uri_from_onvif_soap_response():
    soap_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
                xmlns:tt="http://www.onvif.org/ver10/schema">
      <s:Body>
        <trt:GetStreamUriResponse>
          <trt:MediaUri>
            <tt:Uri>rtsp://192.168.1.150:554/axis-media/media.amp</tt:Uri>
          </trt:MediaUri>
        </trt:GetStreamUriResponse>
      </s:Body>
    </s:Envelope>"""
    uri = OnvifScanner._extract_uri_from_soap(soap_xml)
    assert uri == "rtsp://192.168.1.150:554/axis-media/media.amp"


def test_tcp_port_probe_and_rtsp_handshake():
    """Spin up an ephemeral local mock RTSP server and verify port scan + RTSP OPTIONS handshake."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(5)
    port = server_sock.getsockname()[1]

    def _mock_rtsp_server():
        for _ in range(2):
            try:
                conn, _ = server_sock.accept()
            except OSError:
                break
            with conn:
                data = conn.recv(1024)
                if b"OPTIONS" in data:
                    conn.sendall(
                        b"RTSP/1.0 200 OK\r\n"
                        b"CSeq: 1\r\n"
                        b"Server: Hikvision-Enterprise-RTSP/2.0\r\n"
                        b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
                    )

    thread = threading.Thread(target=_mock_rtsp_server, daemon=True)
    thread.start()

    try:
        is_open, latency = probe_tcp_port("127.0.0.1", port, timeout_sec=1.0)
        assert is_open is True
        assert latency >= 0.0

        is_valid, server_hdr, status_code = verify_rtsp_endpoint(
            ip_address="127.0.0.1",
            port=port,
            path="/Streaming/Channels/101",
            username="admin",
            password="password",
            timeout_sec=1.0,
        )
        assert is_valid is True
        assert status_code == "200"
        assert server_hdr == "Hikvision-Enterprise-RTSP/2.0"
    finally:
        server_sock.close()


def test_discovery_api_endpoints():
    client = TestClient(discovery_app)

    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "discovery"

    cams_resp = client.get("/api/v1/cameras")
    assert cams_resp.status_code == 200
    assert len(cams_resp.json()) >= 4

    scan_resp = client.post(
        "/api/v1/discover",
        json={
            "subnets": ["127.0.0.1/32"],
            "ports": [554],
            "enable_onvif_multicast": False,
            "enable_port_scan": True,
            "verify_rtsp_endpoints": False,
            "include_simulated_if_empty": True,
            "timeout_sec": 0.3,
        },
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["subnets_scanned"] == ["127.0.0.1/32"]
    assert isinstance(scan_data["cameras"], list)
