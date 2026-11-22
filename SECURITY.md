# Security Policy & Authorization Boundaries

## Core Security Principles

`CCTV-Streamer` is a self-hosted surveillance and authorized IoT management platform designed exclusively for cameras, NVRs/DVRs, and network segments that the operator owns or is expressly authorized to administer.

### Non-Negotiable Authorization Boundaries

1. **Owner-Approved Network Scopes Only**:
   - Network discovery operates solely against saved `NetworkScope` CIDRs/IPs explicitly created and approved by an authenticated `OWNER` or `ADMIN`.
   - Public internet scanning, third-party subnet scanning, and unbounded IP sweeps are blocked by policy.
2. **Non-Authenticating Discovery**:
   - Discovery probes (ONVIF WS-Discovery, RTSP `OPTIONS`, mDNS, SSDP) never send default usernames, passwords, dictionary lists, or credential guesses.
   - Open ports or ONVIF responses are recorded as unapproved `CAMERA_CANDIDATE` evidence only.
3. **Explicit Enrollment & Encrypted Credential Vault**:
   - A candidate device must be reviewed and transitioned to `USER_APPROVED` before credentials can be attached or streams ingested.
   - Camera credentials are encrypted at rest using authenticated encryption (`VAULT_MASTER_KEY`) and are never exposed in API responses, logs, or frontend state.
4. **Fail-Closed Authentication & Protected Media Plane**:
   - In `production` mode, the platform fails closed if `API_SECRET_KEY` or `VAULT_MASTER_KEY` is unset or left as a `change-me` placeholder.
   - Every live video, snapshot, MJPEG, WebSocket, WebRTC, HLS, and recording endpoint requires authentication (`Bearer` session token, `X-API-Key`, or a short-lived, camera-scoped playback ticket).
5. **SSRF & Destination Validation**:
   - All camera stream URIs and ONVIF `XAddr` endpoints are validated against approved site scopes, blocking loopback, link-local/cloud-metadata (`169.254.0.0/16`), multicast, broadcast, and HTTP redirects.

## Reporting a Vulnerability

If you discover a security vulnerability in `CCTV-Streamer`:
- Do **not** open a public issue containing exploit details.
- Report the finding privately via GitHub Security Advisories on `https://github.com/lumifya11/CCTV-Streamer/security/advisories`.
- Include reproduction steps, affected service/file paths, and impact assessment.
