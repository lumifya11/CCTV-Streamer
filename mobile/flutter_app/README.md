# CCTV-Streamer Flutter Android Client

This directory contains the Android-first Flutter mobile application for **CCTV-Streamer**, built according to Section 10 of [`docs/architecture/ULTRA_MASTER_BLUEPRINT.md`](../../docs/architecture/ULTRA_MASTER_BLUEPRINT.md).

## Security & Architecture Highlights

- **Zero Embedded Secrets**: The mobile app never stores camera RTSP credentials or a permanent server API secret.
- **One-Time Server Pairing**: Pairs with your self-hosted Gateway over local LAN or WireGuard VPN using `POST /api/v1/mobile/pairing/start` and `POST /api/v1/mobile/pairing/complete`.
- **Short-Lived Playback Tickets**: Requests 120-second camera-scoped media playback tickets (`POST /api/v1/mobile/stream-ticket`), preferring low-latency WebRTC and falling back to HLS/MJPEG.
- **Clear Offline State**: Displays an explicit offline banner whenever the phone is disconnected from the self-hosted server or WireGuard tunnel.
