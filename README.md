# CCTV-Streamer

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)
[![OpenCV](https://img.shields.io/badge/Engine-OpenCV%204.x-green.svg)](services/transcoder/stream_engine.py)
[![Docker Compose](https://img.shields.io/badge/Deploy-Docker%20Compose-2496ED.svg)](docker-compose.yml)

**CCTV-Streamer** is an enterprise-grade, self-hosted IP camera discovery, RTSP stream ingestion, low-latency transcoding, and real-time video analytics platform built on a modular Python microservices architecture.

---

## Architecture Overview

The platform is decomposed into four decoupled microservices plus a shared core library, orchestrated via Docker Compose with strict resource quotas, container health checks, and credential-redacted structured logging.

```mermaid
flowchart LR
    subgraph LAN["Local Camera Network (VLAN / Subnet)"]
        CAM1["ONVIF IP Cameras\n(UDP 239.255.255.250:3702)"]
        CAM2["RTSP Streams\n(TCP 554 / 8554)"]
    end

    subgraph Microservices["CCTV-Streamer Containerized Microservices"]
        DISC["Discovery Service (:8001)\nONVIF WS-Discovery + TCP/RTSP Scanner"]
        TRANS["Transcoder Service (:8002)\nOpenCV RTSP Engine + Auto-Reconnect"]
        PROC["Processor Service (:8003)\nOpenCV Motion & Tamper Analytics"]
        REDIS[("Redis (:6379)\nTelemetry & State")]
        GW["API Gateway & SOC Console (:8080)\nUnified REST / MJPEG / WebSocket"]
    end

    CAM1 <-->|"SOAP ProbeMatches &\nGetStreamUri"| DISC
    CAM2 <-->|"TCP Handshake &\nRTSP OPTIONS"| DISC
    CAM2 -->|"RTSP H.264/H.265\n(Low-Latency FFMPEG)"| TRANS
    TRANS -->|"Frame Snapshots"| PROC
    PROC -->|"Motion/OSD Feedback"| TRANS
    PROC --> REDIS
    DISC --> GW
    TRANS -->|"Multipart MJPEG &\nWebSocket Frames"| GW
    PROC -->|"Incident Events &\nTelemetry"| GW
```

### Microservices Breakdown

| Service | Port | Source Directory | Core Responsibilities |
| :--- | :--- | :--- | :--- |
| **Discovery** | `8001` | [`services/discovery/`](services/discovery/) | Broadcasts ONVIF WS-Discovery UDP multicast probes (`239.255.255.250:3702`), resolves RTSP URIs via SOAP `GetStreamUri` with WS-UsernameToken Digest auth, and runs concurrent CIDR port scans (`554`, `8554`, `80`, `8000`, `8080`, `8899`) with RTSP `OPTIONS` protocol verification. |
| **Transcoder** | `8002` | [`services/transcoder/`](services/transcoder/) | Ingests RTSP streams using OpenCV (`cv2.VideoCapture` + `CAP_FFMPEG`) with low-latency capture flags (`nobuffer`, `low_delay`), dedicated reader threads, exponential backoff + jitter reconnection, OSD telemetry overlays, and MJPEG / WebSocket delivery. |
| **Processor** | `8003` | [`services/processor/`](services/processor/) | Executes real-time OpenCV frame analysis including Gaussian-smoothed differential motion detection, bounding-box contour extraction, lens obstruction/blackout tamper detection, and cooldown-deduplicated event logging. |
| **Gateway & UI** | `8080` | [`services/gateway/`](services/gateway/) | Aggregates microservice APIs and serves the Enterprise Security Operations Center (SOC) Web Console for live 2&times;2 / 1&times;1 video matrix monitoring, on-demand network discovery, and incident review. |
| **Shared Core** | — | [`shared/`](shared/) | Centralized `.env` configuration loader, Pydantic domain schemas, CIDR & SSRF validators, API key authentication dependency, and credential-redacting JSON logger. |

---

## Key Capabilities

### 1. Camera Discovery (`services/discovery/`)
- **ONVIF WS-Discovery Multicast**: Sends standards-compliant SOAP `Probe` datagrams for `dn:NetworkVideoTransmitter` devices and parses `ProbeMatches` (`XAddrs`, hardware scopes, and locations) while defending against XML External Entity (XXE) injection.
- **ONVIF SOAP Media Resolution**: Queries camera media endpoints using WS-Security `PasswordDigest` (`SHA-1(Nonce + Created + Password)`) to extract primary RTSP transport URIs.
- **Concurrent Port & RTSP Handshake Scanner**: Multi-threaded subnet scanner (`ThreadPoolExecutor`) that probes candidate ports and issues `RTSP/1.0 OPTIONS` handshakes across vendor URI templates (Hikvision, Dahua, Axis, Reolink, Generic ONVIF).

### 2. Resilient Stream Management (`services/transcoder/`)
- **Low-Latency OpenCV Ingestion**: Configures `OPENCV_FFMPEG_CAPTURE_OPTIONS` (`rtsp_transport;tcp|fflags;nobuffer|flags;low_delay`) and minimal internal frame buffering to eliminate queue drift.
- **Automatic Reconnection State Machine**: Tracks stream lifecycle states (`IDLE`, `CONNECTING`, `STREAMING`, `RECONNECTING`, `DEGRADED`, `OFFLINE`) and automatically recovers from socket drops or EOFs using exponential backoff with bounded jitter:
  $$\text{delay} = \min\left(T_{\max},\; T_{\text{base}} \cdot 2^{\text{attempt}-1}\right) \pm \text{jitter}$$
- **Web-Friendly Delivery**: Transcodes raw frames into low-latency `multipart/x-mixed-replace` MJPEG streams, binary WebSocket frame streams, and instant JPEG snapshots with live OSD telemetry.

### 3. Real-Time Data Processing (`services/processor/`)
- **Kinetic Motion Detection**: Performs inter-frame Gaussian-blurred grayscale differencing, binary thresholding, morphological dilation, and contour area filtering to compute motion scores and object bounding boxes.
- **Tamper & Obstruction Detection**: Evaluates frame luminance mean and pixel standard deviation (`cv2.meanStdDev`) to trigger `CRITICAL` alerts when a lens is covered, spray-painted, or experiences signal blackout.

### 4. System Stability, Configuration & Security
- **Docker Resource Governance**: [`docker-compose.yml`](docker-compose.yml) enforces CPU and memory limits/reservations, `unless-stopped` restart policies, `no-new-privileges` security options, log rotation, and `service_healthy` startup ordering.
- **Zero Hardcoded Secrets**: All credentials (`ONVIF_PASSWORD`, `RTSP_DEFAULT_PASSWORD`, `API_SECRET_KEY`, `REDIS_PASSWORD`) are injected via environment variables ([`.env.example`](.env.example)).
- **Automatic Credential Redaction**: Embedded RTSP credentials (`rtsp://user:password@host:554/...`) and Bearer tokens are automatically masked (`rtsp://user:********@host:554/...`) across all API responses and log outputs.

---

## Quick Start

### 1. Configure Environment Variables

```bash
cp .env.example .env
# Edit .env to set production secrets (API_SECRET_KEY, ONVIF_PASSWORD, REDIS_PASSWORD, etc.)
```

### 2. Launch with Docker Compose (Recommended for Production)

```bash
docker compose up --build -d
docker compose ps
```

### 3. Run Locally for Development & Testing

```bash
pip install -r requirements.txt

# Run the unified Gateway & SOC Operations Console on port 8080:
uvicorn services.gateway.app:app --host 0.0.0.0 --port 8080

# Or run individual microservices separately:
uvicorn services.discovery.app:app --host 0.0.0.0 --port 8001
uvicorn services.transcoder.app:app --host 0.0.0.0 --port 8002
uvicorn services.processor.app:app --host 0.0.0.0 --port 8003
```

---

## API Reference Summary

### Discovery Service (`:8001` or via Gateway `:8080`)
- `GET /health` — Service health and registered camera count.
- `GET /api/v1/cameras` — List all discovered ONVIF and RTSP camera devices.
- `POST /api/v1/discover` — Trigger an immediate ONVIF multicast + CIDR port scan.
- `POST /api/v1/cameras/probe` — Probe a specific IP address and port list for RTSP endpoints.

### Transcoder Service (`:8002` or via Gateway `:8080`)
- `GET /api/v1/streams` — List all active OpenCV stream pipelines with FPS, bitrate, and reconnection counters.
- `POST /api/v1/streams` — Register and start a new RTSP camera ingestion pipeline.
- `POST /api/v1/streams/{camera_id}/reconnect` — Force an immediate stream reconnection cycle.
- `GET /api/v1/streams/{camera_id}/mjpeg` — Low-latency multipart MJPEG video stream.
- `GET /api/v1/streams/{camera_id}/snapshot` — Latest transcoded JPEG frame.
- `WS /api/v1/streams/{camera_id}/ws` — Binary JPEG WebSocket stream.

### Data Processor Service (`:8003` or via Gateway `:8080`)
- `POST /api/v1/process/frame` — Analyze a base64-encoded JPEG frame for motion and tamper events.
- `GET /api/v1/events` — Query detected motion and tamper events (`camera_id`, `event_type`, `severity`).
- `GET /api/v1/metrics` — Per-camera and aggregate frame processing metrics.
- `PUT /api/v1/config/{camera_id}` — Dynamically tune motion sensitivity, minimum contour area, and cooldowns.

---

## Running Tests

```bash
pytest -v
```

---

## License

Released under the [MIT License](LICENSE).