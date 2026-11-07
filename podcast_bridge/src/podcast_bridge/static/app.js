"use strict";

const state = {
  hostIp: "127.0.0.1",
  webPort: 8788,
  ffmpegAvailable: true,
  activeReceivers: 0,
  auth: { mode: "self_signed", bundle_name: null, bundle_windows_count: 0 },
  ha: { enabled: true, url: "", connected: false, discovered_entities: [] },
  audio: { codec: "wav", sample_rate: 44100, bitrate: "320k" },
  devices: [],
  events: [],
  activeTab: "speakers",
  eventFilter: "all",
};

function apiUrl(path) {
  const clean = path.startsWith("/") ? path.slice(1) : path;
  return `./${clean}`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(ts) {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function showDiagnostic(title, message, isError = false) {
  const banner = document.getElementById("diagnostic-banner");
  const titleEl = document.getElementById("diag-title");
  const msgEl = document.getElementById("diag-message");
  banner.classList.remove("hidden");
  banner.style.borderColor = isError ? "var(--signal-red)" : "var(--signal-green)";
  titleEl.style.color = isError ? "var(--signal-red)" : "var(--signal-green)";
  titleEl.textContent = title;
  msgEl.textContent = message;
}

function applySummaryState(summary) {
  state.hostIp = summary.host_ip || "127.0.0.1";
  state.webPort = summary.web_port || 8788;
  state.ffmpegAvailable = Boolean(summary.ffmpeg_available);
  state.activeReceivers = summary.active_receivers || 0;
  state.auth = summary.auth || state.auth;
  state.ha = summary.ha || state.ha;
  state.audio = summary.audio || state.audio;
  state.devices = summary.devices || [];
  if (Array.isArray(summary.events)) {
    state.events = summary.events;
  }
  renderAll();
  populateSettingsFields();
}

function renderHeader() {
  document.getElementById("val-host-ip").textContent = state.hostIp;
  document.getElementById("val-active-receivers").textContent = `${state.activeReceivers} Active`;
  document.getElementById("val-auth-mode").textContent = (state.auth.mode || "self_signed").toUpperCase();
  document.getElementById("val-ffmpeg").textContent = state.ffmpegAvailable
    ? `FFmpeg ${state.audio.codec.toUpperCase()} (${state.audio.sample_rate / 1000}kHz)`
    : "Fallback PCM";

  document.getElementById("count-speakers").textContent = String(state.devices.length);
  document.getElementById("count-events").textContent = String(state.events.length);
}

function renderDevices() {
  const grid = document.getElementById("devices-grid");
  if (!state.devices.length) {
    grid.innerHTML = `
      <div class="settings-card">
        <h3>No HomePod Minis Bridged Yet</h3>
        <p class="card-description">Click <strong>Scan LAN &amp; HA</strong> to auto-discover HomePod Minis on your subnet, or click <strong>Add HomePod Mini</strong> to register one manually.</p>
      </div>
    `;
    return;
  }

  grid.innerHTML = state.devices
    .map((dev) => {
      const pState = dev.player_state || "IDLE";
      const badgeClass =
        pState === "PLAYING" ? "badge-playing" : pState === "PAUSED" ? "badge-paused" : "badge-idle";
      const cardPlayingClass = pState === "PLAYING" ? "is-playing" : "";
      const volPct = Math.round((dev.volume || 0) * 100);
      const media = dev.media || {};
      const appName = media.app_name || "Backdrop";
      const title = media.title || "Ready to Cast";
      const artist = media.artist || "Waiting for Google Cast sender...";

      return `
        <article class="speaker-card ${cardPlayingClass}" id="device-card-${escapeHtml(dev.id)}">
          <div class="speaker-top">
            <div class="speaker-identity">
              <div class="speaker-title-row">
                <h3 class="speaker-name">${escapeHtml(dev.name)}</h3>
                <span class="badge badge-cast">Chromecast Audio</span>
                <span class="badge ${badgeClass}">${escapeHtml(pState)}</span>
              </div>
              <div class="speaker-cast-alias">
                mDNS Service: <code>${escapeHtml(dev.cast_name)}</code> &bull; Model: <code>${escapeHtml(dev.model)}</code>
              </div>
            </div>
            <div>
              <button type="button" class="btn btn-secondary btn-sm" data-action="toggle-enable" data-id="${escapeHtml(dev.id)}">
                ${dev.enabled ? "Receiver Enabled" : "Receiver Paused"}
              </button>
            </div>
          </div>

          <div class="port-matrix">
            <div class="matrix-cell">
              <span class="matrix-label">AIRPLAY TARGET</span>
              <span class="matrix-val">${escapeHtml(dev.ip_address)}:${dev.airplay_port}</span>
            </div>
            <div class="matrix-cell">
              <span class="matrix-label">CASTV2 TLS PORT</span>
              <span class="matrix-val">${escapeHtml(state.hostIp)}:${dev.cast_port}</span>
            </div>
            <div class="matrix-cell">
              <span class="matrix-label">EUREKA / DIAL HTTP</span>
              <span class="matrix-val">:${dev.eureka_port}/setup/eureka_info</span>
            </div>
            <div class="matrix-cell">
              <span class="matrix-label">CAST UUID (ca=199428)</span>
              <span class="matrix-val" title="${escapeHtml(dev.cast_uuid)}">${escapeHtml((dev.cast_uuid || "").slice(0, 12))}...</span>
            </div>
          </div>

          <div class="now-playing-lcd">
            <div class="lcd-track">
              <span class="lcd-app-tag">CAST APP: ${escapeHtml(appName.toUpperCase())} ${media.current_time ? `(${media.current_time.toFixed(1)}s)` : ""}</span>
              <div class="lcd-title">${escapeHtml(title)}</div>
              <div class="lcd-artist">${escapeHtml(artist)}</div>
            </div>
            <div class="transport-controls">
              <button type="button" class="btn btn-secondary btn-sm" data-action="play" data-id="${escapeHtml(dev.id)}" title="Resume Playback">Play</button>
              <button type="button" class="btn btn-secondary btn-sm" data-action="pause" data-id="${escapeHtml(dev.id)}" title="Pause Playback">Pause</button>
              <button type="button" class="btn btn-secondary btn-sm" data-action="stop" data-id="${escapeHtml(dev.id)}" title="Stop Playback">Stop</button>
            </div>
          </div>

          ${dev.last_error ? `
            <div style="color:#ff6b6b;font-size:12px;margin:10px 0;background:rgba(255,107,107,0.1);padding:8px 12px;border-radius:4px;border-left:3px solid #ff6b6b;">
              <strong>Speaker Delivery Notice:</strong> ${escapeHtml(dev.last_error)}
              <div style="margin-top:4px;color:var(--text-muted);font-size:11px;">Tip: Change Audio Delivery Transport below to <strong>Home Assistant (${escapeHtml(dev.ha_entity_id || "media_player")})</strong>, or set Apple Home App &rarr; Home Settings &rarr; Speakers &amp; TV &rarr; "Anyone on the Same Network".</div>
            </div>
          ` : ""}

          <div class="controls-strip">
            <div class="volume-box">
              <span class="volume-label" id="vol-label-${escapeHtml(dev.id)}">VOL ${dev.muted ? "MUTE" : `${volPct}%`}</span>
              <input
                type="range"
                min="0"
                max="100"
                value="${volPct}"
                class="volume-slider"
                data-action="volume-change"
                data-id="${escapeHtml(dev.id)}"
                aria-label="Volume for ${escapeHtml(dev.name)}"
              />
            </div>
            <div class="transport-select-box">
              <select class="form-control" data-action="transport-change" data-id="${escapeHtml(dev.id)}" aria-label="Transport Mode">
                <option value="pyatv_stream" ${dev.transport_mode === "pyatv_stream" ? "selected" : ""}>AirPlay Stream (pyatv + FFmpeg)</option>
                <option value="pyatv_url" ${dev.transport_mode === "pyatv_url" ? "selected" : ""}>AirPlay URL Relay (pyatv)</option>
                <option value="ha_media_player" ${dev.transport_mode === "ha_media_player" ? "selected" : ""}>Home Assistant (${escapeHtml(dev.ha_entity_id || "media_player")}) ${dev.ha_entity_id ? "★ Recommended" : ""}</option>
                <option value="simulated" ${dev.transport_mode === "simulated" ? "selected" : ""}>Simulated HomePod Sink (Diagnostic)</option>
              </select>
            </div>
          </div>

          <div class="speaker-footer">
            <div class="footer-left">
              <button type="button" class="btn btn-primary btn-sm" data-action="test-cast" data-id="${escapeHtml(dev.id)}">
                Test CastV2 Session
              </button>
              <button type="button" class="btn btn-secondary btn-sm" data-action="open-custom-cast" data-id="${escapeHtml(dev.id)}" data-name="${escapeHtml(dev.name)}">
                Cast Audio URL...
              </button>
              <button type="button" class="btn btn-secondary btn-sm" data-action="open-pair" data-id="${escapeHtml(dev.id)}" data-name="${escapeHtml(dev.name)}">
                AirPlay PIN Pair
              </button>
            </div>
            <div class="footer-right">
              <button type="button" class="btn btn-danger btn-sm" data-action="delete-device" data-id="${escapeHtml(dev.id)}">
                Remove
              </button>
            </div>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderEvents() {
  const tbody = document.getElementById("protocol-log-body");
  const filtered = state.events.filter((ev) => {
    if (state.eventFilter === "all") return true;
    if (state.eventFilter === "cast") return ev.direction.startsWith("cast");
    if (state.eventFilter === "airplay") return ev.direction.startsWith("airplay");
    if (state.eventFilter === "ha") return ev.direction.startsWith("ha");
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px;">
          No protocol frames recorded for this filter yet. Click "Test CastV2 Session" on any speaker to inspect live CastV2 &amp; AirPlay packets.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered
    .map((ev) => {
      const dirClass = `dir-${escapeHtml(ev.direction)}`;
      const payloadHtml = ev.payload_preview
        ? `<span class="payload-sub">${escapeHtml(ev.payload_preview)}</span>`
        : "";
      return `
        <tr>
          <td>${escapeHtml(formatTime(ev.timestamp))}</td>
          <td><strong>${escapeHtml(ev.device_name)}</strong></td>
          <td><span class="dir-pill ${dirClass}">${escapeHtml(ev.direction.toUpperCase())}</span></td>
          <td><code>${escapeHtml(ev.namespace)}</code></td>
          <td>
            ${escapeHtml(ev.summary)}
            ${payloadHtml}
          </td>
        </tr>
      `;
    })
    .join("");
}

function populateSettingsFields() {
  document.getElementById("select-auth-mode").value = state.auth.mode || "self_signed";
  document.getElementById("auth-bundle-name").textContent =
    state.auth.bundle_name || "Dynamic Self-Signed Cast PKI (RSA-2048)";
  document.getElementById("auth-bundle-count").textContent = String(state.auth.bundle_windows_count || 0);

  document.getElementById("input-ha-url").value = state.ha.url || "http://supervisor/core";
  const haBadge = document.getElementById("ha-conn-badge");
  if (state.ha.connected) {
    haBadge.textContent = "CONNECTED TO HOME ASSISTANT";
    haBadge.style.color = "var(--signal-green)";
  } else {
    haBadge.textContent = "STANDALONE MODE (HA API IDLE)";
    haBadge.style.color = "var(--accent-amber)";
  }
  const entitiesCount = (state.ha.discovered_entities || []).length;
  document.getElementById("ha-entities-summary").textContent = `${entitiesCount} media_player entities discovered`;

  document.getElementById("input-host-ip").value = state.hostIp;
  document.getElementById("select-audio-codec").value = state.audio.codec || "wav";
  document.getElementById("select-sample-rate").value = String(state.audio.sample_rate || 44100);
  document.getElementById("select-bitrate").value = state.audio.bitrate || "320k";
}

function renderAll() {
  renderHeader();
  renderDevices();
  renderEvents();
}

// --- API Actions ---

async function fetchInitialStatus() {
  const res = await fetch(apiUrl("api/status"));
  if (res.ok) {
    const data = await res.json();
    applySummaryState(data);
  }
}

async function handleDeviceAction(action, deviceId, extra = {}) {
  if (action === "test-cast") {
    showDiagnostic(
      "Running CastV2 TLS Handshake...",
      `Connecting to 127.0.0.1 on virtual Chromecast port for ${deviceId}...`
    );
    const res = await fetch(apiUrl(`api/devices/${deviceId}/test-cast`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(extra),
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.playback_error || data.device_last_error) {
        const errMsg = data.playback_error || data.device_last_error;
        showDiagnostic(
          "Cast Handshake Verified, but HomePod Mini Notice",
          `${errMsg}. Fix: In Apple Home app -> Home Settings -> Speakers & TV -> set 'Allow Speaker Access' to 'Anyone on the Same Network', or change Transport to Home Assistant.`,
          true
        );
      } else {
        const destDesc = data.ha_entity_id ? ` (via ${data.ha_entity_id})` : "";
        showDiagnostic(
          `CastV2 Session Verified (${data.elapsed_ms} ms)`,
          `Audio active on ${data.transport_mode.toUpperCase()}${destDesc}. Cast Handshake: ` + data.steps.join(" → ")
        );
      }
      await fetchInitialStatus();
    } else {
      showDiagnostic("CastV2 Test Failed", data.detail || "Connection error", true);
    }
    return;
  }

  if (action === "play" || action === "pause" || action === "stop") {
    await fetch(apiUrl(`api/devices/${deviceId}/control`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    await fetchInitialStatus();
    return;
  }

  if (action === "volume") {
    await fetch(apiUrl(`api/devices/${deviceId}/control`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "volume", value: extra.value }),
    });
    return;
  }

  if (action === "transport") {
    await fetch(apiUrl(`api/devices/${deviceId}`), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ transport_mode: extra.transport_mode }),
    });
    await fetchInitialStatus();
    return;
  }

  if (action === "toggle-enable") {
    const dev = state.devices.find((d) => d.id === deviceId);
    if (!dev) return;
    await fetch(apiUrl(`api/devices/${deviceId}`), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !dev.enabled }),
    });
    await fetchInitialStatus();
    return;
  }

  if (action === "delete-device") {
    await fetch(apiUrl(`api/devices/${deviceId}`), { method: "DELETE" });
    await fetchInitialStatus();
  }
}

function connectWebSocket() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const basePath = window.location.pathname.endsWith("/")
    ? window.location.pathname
    : `${window.location.pathname}/`;
  const wsUrl = `${proto}//${window.location.host}${basePath}api/ws`;
  const dot = document.getElementById("ws-status-dot");
  const label = document.getElementById("ws-status-text");

  const ws = new WebSocket(wsUrl);
  ws.onopen = () => {
    dot.classList.add("connected");
    label.textContent = "Live Telemetry Connected";
  };

  ws.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === "initial_state" && msg.state) {
        applySummaryState(msg.state);
      } else if (msg.type === "protocol_event" && msg.event) {
        state.events.unshift(msg.event);
        if (state.events.length > 200) state.events.pop();
        renderHeader();
        renderEvents();
      } else if (msg.type === "device_updated" && msg.device) {
        const idx = state.devices.findIndex((d) => d.id === msg.device.id);
        if (idx >= 0) {
          state.devices[idx] = msg.device;
        } else {
          state.devices.push(msg.device);
        }
        renderHeader();
        renderDevices();
      } else if (msg.type === "device_deleted" && msg.device_id) {
        state.devices = state.devices.filter((d) => d.id !== msg.device_id);
        renderHeader();
        renderDevices();
      }
    } catch (e) {
      console.error("WS parse error", e);
    }
  };

  ws.onclose = () => {
    dot.classList.remove("connected");
    label.textContent = "Reconnecting Telemetry...";
    setTimeout(connectWebSocket, 3000);
  };
}

// --- Event Listeners Setup ---

document.addEventListener("DOMContentLoaded", () => {
  fetchInitialStatus();
  connectWebSocket();

  // Tab navigation
  document.querySelectorAll(".nav-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-tab").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");

      const tab = btn.dataset.tab;
      state.activeTab = tab;
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
      document.getElementById(`panel-${tab}`).classList.remove("hidden");
    });
  });

  // Close diagnostic banner
  document.getElementById("btn-close-diag").addEventListener("click", () => {
    document.getElementById("diagnostic-banner").classList.add("hidden");
  });

  // Preview built-in calibration chime in browser
  document.getElementById("btn-preview-chime").addEventListener("click", () => {
    const audioEl = document.getElementById("browser-audio-preview");
    audioEl.src = apiUrl("api/relay/test-chime.wav");
    audioEl.play().catch(() => {});
    showDiagnostic(
      "Auditioning 44.1kHz Stereo Calibration Chime",
      "Playing /api/relay/test-chime.wav (same stream delivered over CastV2 LOAD to HomePod Minis)."
    );
  });

  // Scan LAN & Home Assistant
  document.getElementById("btn-scan-network").addEventListener("click", async () => {
    showDiagnostic("Scanning LAN & Home Assistant...", "Querying mDNS (_airplay._tcp, _raop._tcp) and Home Assistant /api/states...");
    const res = await fetch(apiUrl("api/scan"), { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      await fetchInitialStatus();
      showDiagnostic(
        "Discovery Scan Complete",
        `Found ${data.airplay_discovered.length} AirPlay devices on LAN and ${data.ha_entities.length} Home Assistant media_player entities.`
      );
    }
  });

  // Delegated speaker card actions
  const devicesGrid = document.getElementById("devices-grid");
  devicesGrid.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;

    if (action === "open-custom-cast") {
      document.getElementById("cast-target-device-id").value = id;
      document.getElementById("modal-cast-title").textContent = `Cast Stream to ${btn.dataset.name}`;
      document.getElementById("modal-custom-cast").classList.remove("hidden");
      return;
    }

    if (action === "open-pair") {
      document.getElementById("pair-target-device-id").value = id;
      document.getElementById("modal-pair-title").textContent = `Pair AirPlay with ${btn.dataset.name}`;
      document.getElementById("modal-pair-device").classList.remove("hidden");
      return;
    }

    handleDeviceAction(action, id);
  });

  devicesGrid.addEventListener("input", (e) => {
    const slider = e.target.closest("input[data-action='volume-change']");
    if (!slider) return;
    const id = slider.dataset.id;
    const lbl = document.getElementById(`vol-label-${id}`);
    if (lbl) lbl.textContent = `VOL ${slider.value}%`;
  });

  devicesGrid.addEventListener("change", (e) => {
    const slider = e.target.closest("input[data-action='volume-change']");
    if (slider) {
      const id = slider.dataset.id;
      const val = parseFloat(slider.value) / 100.0;
      handleDeviceAction("volume", id, { value: val });
      return;
    }
    const sel = e.target.closest("select[data-action='transport-change']");
    if (sel) {
      handleDeviceAction("transport", sel.dataset.id, { transport_mode: sel.value });
    }
  });

  // Add Device Modal
  const addModal = document.getElementById("modal-add-device");
  document.getElementById("btn-open-add-modal").addEventListener("click", () => {
    addModal.classList.remove("hidden");
  });
  document.getElementById("btn-close-add-modal").addEventListener("click", () => addModal.classList.add("hidden"));
  document.getElementById("btn-cancel-add").addEventListener("click", () => addModal.classList.add("hidden"));

  document.getElementById("form-add-device").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      name: document.getElementById("add-name").value.trim(),
      cast_name: document.getElementById("add-cast-name").value.trim() || null,
      ip_address: document.getElementById("add-ip").value.trim(),
      airplay_port: parseInt(document.getElementById("add-port").value, 10) || 7000,
      transport_mode: document.getElementById("add-transport").value,
      ha_entity_id: document.getElementById("add-ha-entity").value.trim() || null,
    };
    const res = await fetch(apiUrl("api/devices"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      addModal.classList.add("hidden");
      e.target.reset();
      await fetchInitialStatus();
      showDiagnostic("HomePod Mini Added", `Created virtual Chromecast Audio receiver for ${payload.name}.`);
    }
  });

  // Custom Cast Modal
  const castModal = document.getElementById("modal-custom-cast");
  document.getElementById("btn-close-cast-modal").addEventListener("click", () => castModal.classList.add("hidden"));
  document.getElementById("btn-cancel-cast").addEventListener("click", () => castModal.classList.add("hidden"));
  document.getElementById("form-custom-cast").addEventListener("submit", async (e) => {
    e.preventDefault();
    const devId = document.getElementById("cast-target-device-id").value;
    const title = document.getElementById("cast-stream-title").value.trim();
    const customUrl = document.getElementById("cast-stream-url").value.trim() || null;
    castModal.classList.add("hidden");
    await handleDeviceAction("test-cast", devId, { custom_url: customUrl, title });
  });

  // Pairing Modal
  const pairModal = document.getElementById("modal-pair-device");
  document.getElementById("btn-close-pair-modal").addEventListener("click", () => pairModal.classList.add("hidden"));
  document.getElementById("btn-start-pair-req").addEventListener("click", async () => {
    const devId = document.getElementById("pair-target-device-id").value;
    const statusText = document.getElementById("pair-status-text");
    statusText.textContent = "Contacting HomePod Mini via pyatv...";
    const res = await fetch(apiUrl(`api/devices/${devId}/pair/start`), { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      statusText.textContent = `Pairing initiated (${data.protocol}). Enter the 4-digit PIN shown on your HomePod/HomeKit:`;
    } else {
      statusText.textContent = `Pairing request notice: ${data.detail}`;
    }
  });

  document.getElementById("form-pair-device").addEventListener("submit", async (e) => {
    e.preventDefault();
    const devId = document.getElementById("pair-target-device-id").value;
    const pin = document.getElementById("pair-pin-input").value.trim();
    const res = await fetch(apiUrl(`api/devices/${devId}/pair/finish`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pin }),
    });
    const data = await res.json();
    if (res.ok) {
      pairModal.classList.add("hidden");
      showDiagnostic("AirPlay Pairing Saved", "Stored pyatv credentials for HomePod Mini.");
      await fetchInitialStatus();
    } else {
      document.getElementById("pair-status-text").textContent = `Pairing error: ${data.detail}`;
    }
  });

  // Protocol Inspector Filters
  document.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.eventFilter = btn.dataset.filter;
      renderEvents();
    });
  });

  document.getElementById("btn-clear-events").addEventListener("click", () => {
    state.events = [];
    renderEvents();
    renderHeader();
  });

  // Settings Save
  document.getElementById("btn-save-settings").addEventListener("click", async () => {
    const payload = {
      host_ip: document.getElementById("input-host-ip").value.trim(),
      auth_mode: document.getElementById("select-auth-mode").value,
      ha_url: document.getElementById("input-ha-url").value.trim(),
      ha_token: document.getElementById("input-ha-token").value.trim(),
      audio_codec: document.getElementById("select-audio-codec").value,
      audio_sample_rate: parseInt(document.getElementById("select-sample-rate").value, 10),
      audio_bitrate: document.getElementById("select-bitrate").value,
    };
    const res = await fetch(apiUrl("api/settings"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const data = await res.json();
      applySummaryState(data);
      showDiagnostic("Configuration Saved", "Updated CastV2 authentication, Home Assistant, and FFmpeg relay settings.");
    }
  });

  // Upload Precomputed Auth Bundle
  document.getElementById("input-bundle-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      json.name = file.name;
      const res = await fetch(apiUrl("api/auth/bundle"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(json),
      });
      const data = await res.json();
      if (res.ok) {
        await fetchInitialStatus();
        showDiagnostic(
          "CastV2 Auth Bundle Imported",
          `Loaded ${data.windows_count} certificate window(s) from ${data.bundle_name}.`
        );
      } else {
        showDiagnostic("Bundle Import Error", data.detail || "Invalid JSON bundle", true);
      }
    } catch (err) {
      showDiagnostic("Bundle Parse Error", String(err), true);
    }
  });

  // Activate Built-in 773-Window Eureka Gen1 ICA Bundle
  const loadEurekaBtn = document.getElementById("btn-load-eureka-bundle");
  if (loadEurekaBtn) {
    loadEurekaBtn.addEventListener("click", async () => {
      const res = await fetch(apiUrl("api/auth/bundle/load-eureka"), { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        await fetchInitialStatus();
        showDiagnostic(
          "Eureka Gen1 ICA Hardware Bundle Active",
          `Activated ${data.bundle_name} with ${data.windows_count} hardware-signed certificate windows through Dec 2030.`
        );
      }
    });
  }

  // Generate Sample Precomputed Window Bundle
  document.getElementById("btn-gen-sample-bundle").addEventListener("click", async () => {
    const res = await fetch(apiUrl("api/auth/bundle/generate-sample"), { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      await fetchInitialStatus();
      showDiagnostic(
        "Precomputed Window Bundle Active",
        `Generated ${data.bundle_name} with ${data.windows_count} time-windowed peer cert + signature entry.`
      );
    }
  });

  // Publish to GitHub Modal
  const ghModal = document.getElementById("modal-github-publish");
  const openGhBtn = document.getElementById("btn-open-github-modal");
  if (openGhBtn && ghModal) {
    openGhBtn.addEventListener("click", () => ghModal.classList.remove("hidden"));
    document.getElementById("btn-close-gh-modal").addEventListener("click", () => ghModal.classList.add("hidden"));
    document.getElementById("btn-cancel-gh").addEventListener("click", () => ghModal.classList.add("hidden"));
    document.getElementById("form-github-publish").addEventListener("submit", async (e) => {
      e.preventDefault();
      const repoName = document.getElementById("gh-repo-name").value.trim() || "homepod-chromecast-bridge";
      const token = document.getElementById("gh-token-input").value.trim();
      const submitBtn = document.getElementById("btn-submit-gh");
      submitBtn.disabled = true;
      submitBtn.textContent = "Publishing to GitHub...";
      try {
        const res = await fetch(apiUrl("api/github/publish"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, repo_name: repoName, private: false }),
        });
        const data = await res.json();
        document.getElementById("gh-token-input").value = "";
        if (res.ok && data.ok) {
          ghModal.classList.add("hidden");
          showDiagnostic(
            `Published to GitHub: ${data.owner}/${data.repo}`,
            `Paste ${data.url} into Home Assistant -> Settings -> Add-ons -> Add-on Store -> Repositories!`
          );
        } else {
          showDiagnostic("GitHub Publish Error", data.detail || "Failed to publish repository", true);
        }
      } catch (err) {
        showDiagnostic("GitHub Publish Error", String(err), true);
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = "Create & Push Repository";
      }
    });
  }
});
