# Device & Protocol Compatibility Matrix

`CCTV-Streamer` classifies camera, NVR/DVR, and IoT compatibility into four explicit tiers. Visibility on a network does not imply compatibility or authorization; devices must be explicitly approved and enrolled with valid credentials.

## Compatibility Tiers

| Tier | Classification | Supported Protocols & Interfaces | Enrollment Requirement | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Standards-Based IP Cameras & NVRs** | ONVIF **Profile T** (primary H.264/H.265, events, imaging, PTZ), ONVIF **Profile S** (legacy basic streaming; ONVIF support ends **31 March 2027**), optional **Profile G** (edge storage) & **Profile M** (analytics metadata) | Owner approval + ONVIF WS-UsernameToken / Digest credentials | **Supported** |
| **Tier 2** | **Direct Stream Sources** | Authenticated `rtsp://`, `rtsps://`, `http://` / `https://` MJPEG, or HLS (`m3u8`) endpoints | Owner approval + user-supplied stream URI & credentials | **Supported** |
| **Tier 3** | **Documented Vendor & IoT Adapters** | Multi-channel NVR/DVR RTSP/ONVIF templates, MQTT telemetry (`Mosquitto`), Home Assistant local webhook/state adapter, optional Frigate NVR event adapter | Owner approval + adapter plugin enabled + valid API/broker credentials | **Supported via Plugin Interface** |
| **Tier 4** | **Unsupported Proprietary Devices** | Cloud-only P2P encrypted cameras without local ONVIF/RTSP or documented local SDK | N/A — Not supported; reported transparently in UI | **Unsupported (By Design)** |

## Tested Protocol & Profile Matrix

| Protocol / Profile | Discovery Method | Enrollment & Verification | Live Delivery | Recording & Analytics | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ONVIF Profile T** | WS-Discovery UDP Multicast (`3702`) | Explicit SOAP `GetDeviceInformation`, `GetProfiles`, `GetStreamUri` | MediaMTX WebRTC / HLS + OpenCV MJPEG fallback | Segmented recording + OpenCV motion/tamper/zones | Recommended primary profile for modern IP cameras |
| **ONVIF Profile S (Legacy)** | WS-Discovery UDP Multicast (`3702`) | Explicit SOAP `GetProfiles` & `GetStreamUri` | MediaMTX WebRTC / HLS + OpenCV MJPEG fallback | Segmented recording + OpenCV motion/tamper/zones | Marked `LEGACY` (ONVIF deprecation deadline: 2027-03-31) |
| **Generic RTSP / RTSPS** | Scoped TCP probe (`554`, `8554`) + unauthenticated `OPTIONS` | Explicit credentialed `DESCRIBE`/`SETUP` or OpenCV/FFmpeg stream probe | MediaMTX WebRTC / HLS + OpenCV MJPEG fallback | Segmented recording + OpenCV motion/tamper/zones | Works with standard IP cameras and NVR channels |
| **MQTT IoT Sensors** | Configured broker topic subscription | Broker credentials in encrypted vault | Telemetry & event stream in dashboard/mobile | Event correlation with camera zones | Requires `mqtt-iot` plugin enabled |
