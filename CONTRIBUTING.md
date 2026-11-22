# Contributing to CCTV-Streamer

Thank you for contributing to `CCTV-Streamer`. All contributions must adhere to the architectural and security requirements defined in [`docs/architecture/ULTRA_MASTER_BLUEPRINT.md`](docs/architecture/ULTRA_MASTER_BLUEPRINT.md).

## Engineering Rules

1. **Branching & Pull Requests**:
   - Keep `main` stable at all times.
   - Develop changes in focused feature or security branches (e.g., `security/fail-closed-media-auth`, `feature/device-registry`, `feature/mediamtx-integration`).
2. **Safety & Authorization Compliance**:
   - Never introduce default-password guessing, credential spraying, authentication bypasses, or unscoped internet scanning.
   - Never expose unauthenticated media endpoints (snapshots, MJPEG, WebSockets, WebRTC, HLS, or recordings).
   - Never commit `.env` files, real camera credentials, JWT secrets, vault keys, or private surveillance footage.
3. **Testing Requirements**:
   - Every change must include automated `pytest` tests covering both happy-path functionality and security/authorization boundaries.
   - Run the full suite locally before opening a pull request:
     ```bash
     pytest -v
     ```
4. **Honest Compatibility Claims**:
   - Document exact tested camera protocols and profiles in [`docs/compatibility/COMPATIBILITY_MATRIX.md`](docs/compatibility/COMPATIBILITY_MATRIX.md).
   - Never claim universal access to proprietary or encrypted cameras lacking a documented interface.
