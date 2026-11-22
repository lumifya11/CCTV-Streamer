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
  const metricMotionEvents = document.getElementById("metric-motion-events");
  const metricStorageFree = document.getElementById("metric-storage-free");
  const metricStorageEstimate = document.getElementById("metric-storage-estimate");

  const renderedStreamIds = new Set();

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text == null ? "" : String(text);
    return div.innerHTML;
  }

  function renderStreams(streams) {
    const incomingIds = new Set(streams.map((s) => s.camera_id));

    for (const existingId of Array.from(renderedStreamIds)) {
      if (!incomingIds.has(existingId)) {
        const el = document.getElementById(`card-${existingId}`);
        if (el) el.remove();
        renderedStreamIds.delete(existingId);
      }
    }

    streams.forEach((stream) => {
      let card = document.getElementById(`card-${stream.camera_id}`);
      const mjpegUrl = stream.mjpeg_ticket_url || `/api/v1/streams/${encodeURIComponent(stream.camera_id)}/mjpeg`;
      const snapshotUrl = stream.snapshot_ticket_url || `/api/v1/streams/${encodeURIComponent(stream.camera_id)}/snapshot`;
      const proto = stream.delivery_protocol || "MJPEG";

      if (!card) {
        card = document.createElement("article");
        card.className = "camera-card";
        card.id = `card-${stream.camera_id}`;
        card.innerHTML = `
          <div class="camera-viewport">
            <img
              class="camera-feed-img"
              id="feed-${escapeHtml(stream.camera_id)}"
              src="${escapeHtml(mjpegUrl)}"
              alt="${escapeHtml(stream.name)} live stream"
            />
            <div class="viewport-badges">
              <span class="badge badge-live" id="state-${escapeHtml(stream.camera_id)}">${escapeHtml(stream.state)}</span>
              <span class="badge">${escapeHtml(proto)}</span>
              <span class="badge" id="fps-${escapeHtml(stream.camera_id)}">${stream.fps_actual.toFixed(1)} FPS</span>
              <span class="badge badge-motion" id="motion-${escapeHtml(stream.camera_id)}" style="display:none;">MOTION</span>
            </div>
          </div>
          <div class="camera-footer">
            <div>
              <div class="camera-meta-title">${escapeHtml(stream.name)}</div>
              <div class="camera-meta-sub" id="sub-${escapeHtml(stream.camera_id)}">
                ${escapeHtml(stream.location)} &bull; ${stream.bitrate_kbps.toFixed(0)} kbps &bull; Ticket Protected
              </div>
            </div>
            <div class="camera-actions">
              <button type="button" class="btn btn-sm" data-action="snapshot" data-url="${escapeHtml(snapshotUrl)}" data-id="${escapeHtml(stream.camera_id)}">Snapshot</button>
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
          subEl.textContent = `${stream.location} • ${stream.bitrate_kbps.toFixed(0)} kbps • ${stream.frames_ingested} frames`;
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
      .map((cam) => {
        const stateBadge = cam.approved
          ? `<span class="badge badge-live">${escapeHtml(cam.lifecycle_state)}</span>`
          : `<button type="button" class="btn btn-sm btn-primary" data-approve-id="${escapeHtml(cam.camera_id)}">Approve</button>`;
        const profileLabel = (cam.onvif_profiles || [])[0] || (cam.onvif_supported ? "ONVIF" : "RTSP");
        return `
          <div class="discovered-item">
            <div>
              <div class="discovered-item-title">${escapeHtml(cam.name)}</div>
              <div class="discovered-item-sub">
                ${escapeHtml(cam.ip_address)} &bull; ${escapeHtml(profileLabel)} &bull; ${escapeHtml(cam.compatibility_tier)}
              </div>
            </div>
            <div>${stateBadge}</div>
          </div>
        `;
      })
      .join("");
  }

  discoveredList.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-approve-id]");
    if (!btn) return;
    const candidateId = btn.dataset.approveId;
    btn.disabled = true;
    btn.textContent = "Approving...";
    await fetch(`/api/v1/discovery/candidates/${encodeURIComponent(candidateId)}/approve`, {
      method: "POST",
    });
    await refreshOverview();
  });

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
        const ackLabel = ev.acknowledged ? "ACKED" : "NEW";
        return `
          <div class="event-item">
            <div class="event-item-top">
              <span class="event-tag ${escapeHtml(ev.severity)}">${escapeHtml(ev.event_type)} [${ackLabel}]</span>
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
      const storage = data.storage || {};

      const activeCount = streams.filter((s) => s.state === "STREAMING").length;
      const approvedCount = cameras.filter((c) => c.approved).length;
      const candidateCount = cameras.length - approvedCount;
      const totalFps = streams.reduce((acc, s) => acc + (s.fps_actual || 0), 0);
      const totalBitrate = streams.reduce((acc, s) => acc + (s.bitrate_kbps || 0), 0);

      metricActiveStreams.textContent = `${activeCount} / ${streams.length}`;
      metricTotalCameras.textContent = `${approvedCount} approved • ${candidateCount} candidates`;
      metricAggregateFps.textContent = `${totalFps.toFixed(1)} FPS`;
      metricAggregateBitrate.textContent = `${totalBitrate.toFixed(0)} kbps transcoded`;
      metricFramesAnalyzed.textContent = `${analytics.total_frames_processed || 0}`;
      metricMotionEvents.textContent = `${analytics.total_motion_events || 0} motion • ${analytics.total_tamper_events || 0} tamper`;

      if (storage.disk_free_gb != null) {
        metricStorageFree.textContent = `${storage.disk_free_gb.toFixed(1)} GB free`;
      }
      if (storage.capacity_estimate) {
        metricStorageEstimate.textContent = `14d est: ${storage.capacity_estimate.estimated_gb} GB`;
      }

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
      const snapUrl = btn.dataset.url || `/api/v1/streams/${encodeURIComponent(cameraId)}/snapshot`;
      window.open(snapUrl, "_blank");
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
      const resp = await fetch("/api/v1/discovery/jobs", {
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
        scanBadge.textContent = "SCOPE BLOCKED";
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

  const modalStream = document.getElementById("modal-add-stream");
  document.getElementById("btn-open-add-stream").addEventListener("click", () => {
    modalStream.classList.add("open");
  });
  document.getElementById("btn-close-add-stream").addEventListener("click", () => {
    modalStream.classList.remove("open");
  });

  const modalMobile = document.getElementById("modal-mobile-pair");
  document.getElementById("btn-open-mobile-pair").addEventListener("click", () => {
    modalMobile.classList.add("open");
  });
  document.getElementById("btn-close-mobile-pair").addEventListener("click", () => {
    modalMobile.classList.remove("open");
  });

  document.getElementById("btn-generate-pairing-code").addEventListener("click", async () => {
    const resp = await fetch("/api/v1/mobile/pairing/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device_label: "Flutter Android App",
        server_url: window.location.origin,
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      document.getElementById("mobile-pairing-code-display").textContent = data.pairing_code;
      document.getElementById("mobile-pairing-qr-payload").textContent = `Server: ${data.server_url} (Expires in ${data.expires_in_sec}s)`;
    }
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
      modalStream.classList.remove("open");
      e.target.reset();
      await refreshOverview();
    }
  });

  refreshOverview();
  setInterval(refreshOverview, 2000);
})();
