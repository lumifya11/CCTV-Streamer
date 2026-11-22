(() => {
  const matrixGrid = document.getElementById("camera-matrix-grid");
  const discoveredList = document.getElementById("discovered-cameras-list");
  const eventsList = document.getElementById("analytics-events-list");
  const scanBadge = document.getElementById("scan-status-badge");
  const eventsCountBadge = document.getElementById("events-count-badge");

  const metricActiveStreams = document.getElementById("metric-active-streams");
  const metricTotalCameras = document.getElementById("metric-total-cameras");
  const metricAggregateFps = document.getElementById("metric-aggregate-fps");
  const metricAggregateBitrate = document.getElementById("metric-aggregate-bitrate");
  const metricFramesAnalyzed = document.getElementById("metric-frames-analyzed");
  const metricReconnections = document.getElementById("metric-reconnections");
  const metricMotionEvents = document.getElementById("metric-motion-events");
  const metricTamperEvents = document.getElementById("metric-tamper-events");

  const renderedStreamIds = new Set();

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text == null ? "" : String(text);
    return div.innerHTML;
  }

  function renderStreams(streams) {
    const incomingIds = new Set(streams.map((s) => s.camera_id));

    // Remove cards for deleted streams
    for (const existingId of Array.from(renderedStreamIds)) {
      if (!incomingIds.has(existingId)) {
        const el = document.getElementById(`card-${existingId}`);
        if (el) el.remove();
        renderedStreamIds.delete(existingId);
      }
    }

    streams.forEach((stream) => {
      let card = document.getElementById(`card-${stream.camera_id}`);
      if (!card) {
        card = document.createElement("article");
        card.className = "camera-card";
        card.id = `card-${stream.camera_id}`;
        card.innerHTML = `
          <div class="camera-viewport">
            <img
              class="camera-feed-img"
              id="feed-${escapeHtml(stream.camera_id)}"
              src="/api/v1/streams/${encodeURIComponent(stream.camera_id)}/mjpeg"
              alt="${escapeHtml(stream.name)} live stream"
            />
            <div class="viewport-badges">
              <span class="badge badge-live" id="state-${escapeHtml(stream.camera_id)}">${escapeHtml(stream.state)}</span>
              <span class="badge" id="fps-${escapeHtml(stream.camera_id)}">${stream.fps_actual.toFixed(1)} FPS</span>
              <span class="badge badge-motion" id="motion-${escapeHtml(stream.camera_id)}" style="display:none;">MOTION</span>
            </div>
          </div>
          <div class="camera-footer">
            <div>
              <div class="camera-meta-title">${escapeHtml(stream.name)}</div>
              <div class="camera-meta-sub" id="sub-${escapeHtml(stream.camera_id)}">
                ${escapeHtml(stream.rtsp_url_masked)} &bull; ${stream.bitrate_kbps.toFixed(0)} kbps
              </div>
            </div>
            <div class="camera-actions">
              <button type="button" class="btn btn-sm" data-action="snapshot" data-id="${escapeHtml(stream.camera_id)}">Snapshot</button>
              <button type="button" class="btn btn-sm" data-action="reconnect" data-id="${escapeHtml(stream.camera_id)}">Reconnect</button>
            </div>
          </div>
        `;
        matrixGrid.appendChild(card);
        renderedStreamIds.add(stream.camera_id);
      } else {
        const stateEl = document.getElementById(`state-${stream.camera_id}`);
        const fpsEl = document.getElementById(`fps-${stream.camera_id}`);
        const motionEl = document.getElementById(`motion-${stream.camera_id}`);
        const subEl = document.getElementById(`sub-${stream.camera_id}`);

        if (stateEl) stateEl.textContent = stream.state;
        if (fpsEl) fpsEl.textContent = `${stream.fps_actual.toFixed(1)} FPS`;
        if (subEl) {
          subEl.textContent = `${stream.rtsp_url_masked} • ${stream.bitrate_kbps.toFixed(0)} kbps • ${stream.frames_ingested} frames`;
        }
        if (motionEl) {
          motionEl.style.display = stream.motion_active ? "inline-block" : "none";
        }
        card.classList.toggle("motion-alert", Boolean(stream.motion_active));
      }
    });
  }

  function renderDiscoveredCameras(cameras) {
    discoveredList.innerHTML = cameras
      .map(
        (cam) => `
        <div class="discovered-item">
          <div>
            <div class="discovered-item-title">${escapeHtml(cam.name)}</div>
            <div class="discovered-item-sub">
              ${escapeHtml(cam.ip_address)} &bull; ${cam.onvif_supported ? "ONVIF" : "RTSP"} &bull; Ports: ${(cam.open_ports || []).join(",")}
            </div>
          </div>
          <span class="badge">${cam.latency_ms.toFixed(1)} ms</span>
        </div>
      `
      )
      .join("");
  }

  function renderEvents(events) {
    eventsCountBadge.textContent = `${events.length} EVENTS`;
    if (!events.length) {
      eventsList.innerHTML = `<div class="discovered-item-sub">Monitoring active streams for motion and tamper anomalies...</div>`;
      return;
    }
    eventsList.innerHTML = events
      .slice(0, 20)
      .map((ev) => {
        const timeStr = new Date(ev.timestamp).toLocaleTimeString();
        return `
          <div class="event-item">
            <div class="event-item-top">
              <span class="event-tag ${escapeHtml(ev.severity)}">${escapeHtml(ev.event_type)}</span>
              <span>${escapeHtml(timeStr)}</span>
            </div>
            <div class="event-desc">${escapeHtml(ev.description)}</div>
          </div>
        `;
      })
      .join("");
  }

  async function refreshOverview() {
    try {
      const resp = await fetch("/api/v1/overview");
      if (!resp.ok) return;
      const data = await resp.json();

      const streams = data.streams || [];
      const cameras = data.cameras || [];
      const events = data.events || [];
      const analytics = data.analytics || {};

      const activeCount = streams.filter((s) => s.state === "STREAMING").length;
      const totalFps = streams.reduce((acc, s) => acc + (s.fps_actual || 0), 0);
      const totalBitrate = streams.reduce((acc, s) => acc + (s.bitrate_kbps || 0), 0);
      const totalReconn = streams.reduce((acc, s) => acc + (s.total_reconnections || 0), 0);

      metricActiveStreams.textContent = `${activeCount} / ${streams.length}`;
      metricTotalCameras.textContent = `${cameras.length} discovered ONVIF/RTSP devices`;
      metricAggregateFps.textContent = `${totalFps.toFixed(1)} FPS`;
      metricAggregateBitrate.textContent = `${totalBitrate.toFixed(0)} kbps transcoded`;
      metricFramesAnalyzed.textContent = `${analytics.total_frames_processed || 0}`;
      metricReconnections.textContent = `${totalReconn} auto-reconnections`;
      metricMotionEvents.textContent = `${analytics.total_motion_events || 0}`;
      metricTamperEvents.textContent = `${analytics.total_tamper_events || 0} tamper alerts`;

      renderStreams(streams);
      renderDiscoveredCameras(cameras);
      renderEvents(events);
    } catch (err) {
      console.error("Overview refresh error:", err);
    }
  }

  matrixGrid.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const cameraId = btn.dataset.id;
    if (action === "reconnect") {
      btn.disabled = true;
      btn.textContent = "Reconnecting...";
      await fetch(`/api/v1/streams/${encodeURIComponent(cameraId)}/reconnect`, {
        method: "POST",
      });
      setTimeout(() => {
        btn.disabled = false;
        btn.textContent = "Reconnect";
        refreshOverview();
      }, 450);
    } else if (action === "snapshot") {
      window.open(`/api/v1/streams/${encodeURIComponent(cameraId)}/snapshot`, "_blank");
    }
  });

  async function runDiscoveryScan(e) {
    if (e) e.preventDefault();
    const subnetsRaw = document.getElementById("input-scan-subnets").value;
    const portsRaw = document.getElementById("input-scan-ports").value;
    const subnets = subnetsRaw.split(",").map((s) => s.trim()).filter(Boolean);
    const ports = portsRaw
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((n) => !Number.isNaN(n));

    scanBadge.textContent = "SCANNING...";
    try {
      const resp = await fetch("/api/v1/discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subnets,
          ports,
          enable_onvif_multicast: true,
          enable_port_scan: true,
          verify_rtsp_endpoints: true,
          include_simulated_if_empty: true,
          timeout_sec: 0.8,
        }),
      });
      if (resp.ok) {
        const res = await resp.json();
        scanBadge.textContent = `FOUND ${res.cameras.length} (${res.duration_ms.toFixed(0)}ms)`;
        await refreshOverview();
      } else {
        scanBadge.textContent = "SCAN ERROR";
      }
    } catch (err) {
      scanBadge.textContent = "SCAN FAILED";
    }
  }

  document.getElementById("discovery-scan-form").addEventListener("submit", runDiscoveryScan);
  document.getElementById("btn-trigger-scan").addEventListener("click", runDiscoveryScan);

  document.getElementById("btn-grid-2x2").addEventListener("click", () => {
    matrixGrid.classList.remove("single-view");
  });
  document.getElementById("btn-grid-1x1").addEventListener("click", () => {
    matrixGrid.classList.add("single-view");
  });

  const modal = document.getElementById("modal-add-stream");
  document.getElementById("btn-open-add-stream").addEventListener("click", () => {
    modal.classList.add("open");
  });
  document.getElementById("btn-close-add-stream").addEventListener("click", () => {
    modal.classList.remove("open");
  });

  document.getElementById("form-register-stream").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      camera_id: document.getElementById("reg-camera-id").value.trim(),
      name: document.getElementById("reg-camera-name").value.trim(),
      location: document.getElementById("reg-camera-location").value.trim(),
      rtsp_url: document.getElementById("reg-rtsp-url").value.trim(),
      target_fps: 20,
      width: 1280,
      height: 720,
      jpeg_quality: 80,
    };
    const resp = await fetch("/api/v1/streams", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (resp.ok) {
      modal.classList.remove("open");
      e.target.reset();
      await refreshOverview();
    }
  });

  refreshOverview();
  setInterval(refreshOverview, 2000);
})();
