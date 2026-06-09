/**
 * WineShield Dashboard — Frontend Application
 * =============================================
 *
 * Handles:
 *   - Socket.IO connection to /ws/events
 *   - API calls (fetch) for initial data loading
 *   - Event handlers for WebSocket messages
 *   - DOM manipulation for live updates
 *   - Toggle button click handlers
 *   - Filter functionality for event feed
 */

(function () {
  'use strict';

  // ────────────────────────────────────────────────────────────────
  //  Configuration
  // ────────────────────────────────────────────────────────────────

  const CONFIG = {
    apiBase: '',
    wsNamespace: '/ws/events',
    reconnectDelay: 2000,
    formatTimeOptions: { hour: '2-digit', minute: '2-digit', second: '2-digit' },
    layerNameMap: {
      syscall_filter: 'syscall',
      filesystem_guard: 'fs',
      network_guard: 'network',
      behavior_analyzer: 'behavior',
      xephyr_guard: 'xephyr',
      apparmor: 'apparmor',
    },
    displayNameMap: {
      syscall_filter: 'Syscall Filter',
      filesystem_guard: 'Filesystem Guard',
      network_guard: 'Network Guard',
      behavior_analyzer: 'Behavior Analyzer',
      xephyr_guard: 'Xephyr Guard',
      apparmor: 'AppArmor',
    },
  };

  // ────────────────────────────────────────────────────────────────
  //  State
  // ────────────────────────────────────────────────────────────────

  const state = {
    events: [],
    layers: [],
    stats: { events_by_severity: {}, events_by_layer: {}, total_events: 0 },
    status: {},
    socket: null,
    connected: false,
    serverStartTime: null,
    uptimeInterval: null,
    version: '—',
  };

  // ────────────────────────────────────────────────────────────────
  //  DOM References
  // ────────────────────────────────────────────────────────────────

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const dom = {};

  function cacheDom() {
    dom.statusIndicator = $('#statusIndicator');
    dom.statusText = $('#statusText');
    dom.versionBadge = $('#versionBadge');
    dom.statTotalEvents = $('#statTotalEventsValue');
    dom.statActiveSessions = $('#statActiveSessionsValue');
    dom.statSecurityMode = $('#statSecurityModeValue');
    dom.statUptime = $('#statUptimeValue');
    dom.layerList = $('#layerList');
    dom.eventList = $('#eventList');
    dom.eventEmpty = $('#eventEmpty');
    dom.eventCountBadge = $('#eventCountBadge');
    dom.filterSeverity = $('#filterSeverity');
    dom.filterLayer = $('#filterLayer');
    dom.severityChart = $('#severityChart');
    dom.layerChart = $('#layerChart');
    dom.footerVersion = $('#footerVersion');
    dom.footerTime = $('#footerTime');
  }

  // ────────────────────────────────────────────────────────────────
  //  Utilities
  // ────────────────────────────────────────────────────────────────

  function formatTimestamp(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString('en-US', CONFIG.formatTimeOptions);
    } catch {
      return iso;
    }
  }

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
      return iso;
    }
  }

  function formatUptime(seconds) {
    if (seconds == null || isNaN(seconds)) return '00:00:00';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  function capitalize(str) {
    return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
  }

  function severityClass(sev) {
    return 'severity-' + (sev || 'info');
  }

  function fillClass(key) {
    return 'fill-' + key;
  }

  function getDisplayName(apiName) {
    return CONFIG.displayNameMap[apiName] || apiName.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function getShortName(apiName) {
    return CONFIG.layerNameMap[apiName] || apiName;
  }

  function layerColor(index) {
    const colors = ['#00d4aa', '#4a9eff', '#f0b400', '#ff6b35', '#e04040', '#a855f7'];
    return colors[index % colors.length];
  }

  // ────────────────────────────────────────────────────────────────
  //  API Calls
  // ────────────────────────────────────────────────────────────────

  async function fetchJSON(url) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (err) {
      console.warn(`API fetch failed: ${url}`, err);
      return null;
    }
  }

  async function loadStatus() {
    const data = await fetchJSON('/api/status');
    if (!data) return;
    state.status = data;
    state.version = data.version || '—';
    state.serverStartTime = data.uptime != null ? Date.now() - data.uptime * 1000 : null;
    dom.statTotalEvents.textContent = data.total_events ?? '—';
    dom.statActiveSessions.textContent = data.active_sessions ?? '—';
    dom.statSecurityMode.textContent = capitalize(data.current_mode || data.dashboard?.current_mode || 'monitor');
    dom.versionBadge.textContent = 'v' + (data.version || '—');
    dom.footerVersion.textContent = data.version || '—';
  }

  async function loadLayers() {
    const data = await fetchJSON('/api/layers');
    if (!data || !data.layers) return;
    state.layers = data.layers;
    renderLayers();
    populateLayerFilter();
  }

  async function loadEvents() {
    const data = await fetchJSON('/api/events/latest?n=100');
    if (!data || !data.events) return;
    state.events = data.events;
    renderEvents();
  }

  async function loadStats() {
    const data = await fetchJSON('/api/stats');
    if (!data) return;
    state.stats = data;
    renderStats();
  }

  async function toggleLayer(name) {
    const toggleEl = document.querySelector(`[data-layer-toggle="${name}"]`);
    if (toggleEl) toggleEl.disabled = true;
    const data = await fetchJSON(`/api/layers/${encodeURIComponent(name)}/toggle`);
    if (toggleEl) toggleEl.disabled = false;
    if (data && data.new_mode != null) {
      // The toggle was successful — update UI from API response
      updateLayerInState(name, data.new_mode);
      renderLayers();
      // The toggle already wrote to events.log, so the watcher will pick it up
      // and broadcast via WebSocket too. We've already updated locally.
    } else {
      // Reload layers on failure to sync
      await loadLayers();
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  Render Functions
  // ────────────────────────────────────────────────────────────────

  function renderLayers() {
    if (!dom.layerList) return;
    dom.layerList.innerHTML = '';
    state.layers.forEach((layer) => {
      const isEnabled = layer.enabled === true;
      const statusText = layer.status || (isEnabled ? 'enabled' : 'disabled');
      const isChecked = isEnabled;
      const item = document.createElement('div');
      item.className = 'layer-item';
      item.innerHTML = `
        <div class="layer-info">
          <div class="layer-name">${getDisplayName(layer.name)}</div>
          <div class="layer-desc">${layer.description || ''}</div>
        </div>
        <span class="layer-status ${statusText}">${statusText}</span>
        <label class="toggle">
          <input type="checkbox" data-layer-toggle="${layer.name}" ${isChecked ? 'checked' : ''}>
          <span class="toggle-slider"></span>
        </label>
      `;
      const checkbox = item.querySelector('input');
      checkbox.addEventListener('change', () => {
        toggleLayer(layer.name);
      });
      dom.layerList.appendChild(item);
    });
  }

  function populateLayerFilter() {
    const select = dom.filterLayer;
    if (!select) return;
    const currentVal = select.value;
    select.innerHTML = '<option value="all">All Layers</option>';
    state.layers.forEach((layer) => {
      const opt = document.createElement('option');
      opt.value = layer.name;
      opt.textContent = getDisplayName(layer.name);
      select.appendChild(opt);
    });
    select.value = currentVal;
  }

  function renderEvents() {
    const list = dom.eventList;
    if (!list) return;
    const sevFilter = dom.filterSeverity ? dom.filterSeverity.value : 'all';
    const layerFilter = dom.filterLayer ? dom.filterLayer.value : 'all';

    const filtered = state.events.filter((ev) => {
      if (sevFilter !== 'all' && ev.severity !== sevFilter) return false;
      if (layerFilter !== 'all' && ev.layer !== layerFilter) return false;
      return true;
    });

    // Remove empty state if present
    const empty = dom.eventEmpty;
    if (empty) empty.style.display = 'none';

    list.innerHTML = '';

    if (filtered.length === 0) {
      const div = document.createElement('div');
      div.className = 'event-empty';
      div.innerHTML = `
        <svg viewBox="0 0 40 40" width="40" height="40">
          <circle cx="20" cy="20" r="16" fill="none" stroke="#00d4aa" stroke-width="2" opacity="0.3"/>
          <path d="M20 12v8l4 4" fill="none" stroke="#00d4aa" stroke-width="2" stroke-linecap="round" opacity="0.4"/>
        </svg>
        <p>No events match filter</p>
      `;
      list.appendChild(div);
      dom.eventCountBadge.textContent = '0';
      return;
    }

    // Show only first 200 events in DOM for performance
    const displayEvents = filtered.slice(0, 200);

    displayEvents.forEach((ev) => {
      const detailsStr = typeof ev.details === 'object' && ev.details !== null
        ? JSON.stringify(ev.details).slice(0, 120)
        : String(ev.details || '').slice(0, 120);
      const item = document.createElement('div');
      item.className = 'event-item';
      item.innerHTML = `
        <span class="event-severity ${severityClass(ev.severity)}"></span>
        <div class="event-body">
          <div class="event-meta">
            <span class="event-timestamp">${formatTimestamp(ev.timestamp)}</span>
            <span class="event-layer-badge">${getShortName(ev.layer)}</span>
          </div>
          <div class="event-action">${escapeHtml(ev.action || '')}</div>
          ${detailsStr ? `<div class="event-details">${escapeHtml(detailsStr)}</div>` : ''}
        </div>
      `;
      list.appendChild(item);
    });

    dom.eventCountBadge.textContent = filtered.length;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function renderStats() {
    renderSeverityChart();
    renderLayerChart();
  }

  function renderSeverityChart() {
    const chart = dom.severityChart;
    if (!chart) return;
    const bySeverity = state.stats.events_by_severity || {};
    const order = ['critical', 'error', 'warning', 'info'];
    const maxVal = Math.max(1, ...order.map((k) => bySeverity[k] || 0));
    chart.innerHTML = '';
    order.forEach((sev) => {
      const count = bySeverity[sev] || 0;
      const pct = (count / maxVal) * 100;
      const row = document.createElement('div');
      row.className = 'chart-bar-row';
      row.innerHTML = `
        <span class="chart-bar-label">${sev}</span>
        <div class="chart-bar-track">
          <div class="chart-bar-fill ${fillClass(sev)}" style="width:${pct}%"></div>
        </div>
        <span class="chart-bar-count">${count}</span>
      `;
      chart.appendChild(row);
    });
  }

  function renderLayerChart() {
    const chart = dom.layerChart;
    if (!chart) return;
    const byLayer = state.stats.events_by_layer || {};
    const entries = Object.entries(byLayer).sort((a, b) => b[1] - a[1]);
    const maxVal = Math.max(1, ...entries.map(([, v]) => v));
    chart.innerHTML = '';
    entries.forEach(([layer, count], idx) => {
      const pct = (count / maxVal) * 100;
      const row = document.createElement('div');
      row.className = 'chart-bar-row';
      row.innerHTML = `
        <span class="chart-bar-label" title="${getDisplayName(layer)}">${getShortName(layer)}</span>
        <div class="chart-bar-track">
          <div class="chart-bar-fill fill-layer" style="width:${pct}%;background:${layerColor(idx)}"></div>
        </div>
        <span class="chart-bar-count">${count}</span>
      `;
      chart.appendChild(row);
    });
  }

  // ────────────────────────────────────────────────────────────────
  //  Uptime Clock
  // ────────────────────────────────────────────────────────────────

  function updateUptime() {
    if (state.serverStartTime != null) {
      const elapsed = (Date.now() - state.serverStartTime) / 1000;
      dom.statUptime.textContent = formatUptime(elapsed);
    }
    // Update footer clock
    dom.footerTime.textContent = new Date().toLocaleTimeString('en-US', CONFIG.formatTimeOptions);
  }

  function startUptimeClock() {
    if (state.uptimeInterval) clearInterval(state.uptimeInterval);
    updateUptime();
    state.uptimeInterval = setInterval(updateUptime, 1000);
  }

  // ────────────────────────────────────────────────────────────────
  //  WebSocket (Socket.IO)
  // ────────────────────────────────────────────────────────────────

  function connectSocket() {
    if (state.socket && state.socket.connected) return;

    setStatus('connecting', 'Connecting...');

    state.socket = io(CONFIG.wsNamespace, {
      transports: ['websocket', 'polling'],
      reconnectionDelay: CONFIG.reconnectDelay,
    });

    state.socket.on('connect', () => {
      setStatus('connected', 'Connected');
      state.connected = true;
    });

    state.socket.on('disconnect', () => {
      setStatus('disconnected', 'Disconnected');
      state.connected = false;
    });

    state.socket.on('connect_error', () => {
      setStatus('disconnected', 'Connection error');
      state.connected = false;
    });

    state.socket.on('connected', (data) => {
      // Initial handshake from server
      console.log('WS handshake:', data);
    });

    state.socket.on('new_event', (event) => {
      // Prepend new event to our list
      state.events.unshift(event);
      // Keep only last 1000
      if (state.events.length > 1000) {
        state.events.length = 1000;
      }
      renderEvents();
      // Update total_events count in stats bar
      const cur = parseInt(dom.statTotalEvents.textContent, 10) || 0;
      dom.statTotalEvents.textContent = cur + 1;
    });

    state.socket.on('stats_update', (stats) => {
      if (stats) {
        state.stats = stats;
        renderStats();
      }
    });

    state.socket.on('layer_change', (data) => {
      if (data && data.layer && data.new_mode != null) {
        updateLayerInState(data.layer, data.new_mode);
        renderLayers();
      }
    });
  }

  function updateLayerInState(name, newMode) {
    const layer = state.layers.find((l) => l.name === name);
    if (layer) {
      layer.status = newMode;
      layer.enabled = newMode !== 'disabled';
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  Status Indicator
  // ────────────────────────────────────────────────────────────────

  function setStatus(cls, text) {
    const indicator = dom.statusIndicator;
    const textEl = dom.statusText;
    if (indicator) {
      indicator.className = 'status-indicator ' + cls;
    }
    if (textEl) {
      textEl.textContent = text;
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  Filter Handlers
  // ────────────────────────────────────────────────────────────────

  function setupFilters() {
    if (dom.filterSeverity) {
      dom.filterSeverity.addEventListener('change', renderEvents);
    }
    if (dom.filterLayer) {
      dom.filterLayer.addEventListener('change', renderEvents);
    }
  }

  // ────────────────────────────────────────────────────────────────
  //  Initial Load
  // ────────────────────────────────────────────────────────────────

  async function init() {
    cacheDom();
    setupFilters();
    startUptimeClock();

    // Load data in parallel
    await Promise.all([
      loadStatus(),
      loadLayers(),
      loadEvents(),
      loadStats(),
    ]);

    // Connect WebSocket after initial data load
    connectSocket();

    // Periodic full refresh as fallback (every 30s)
    setInterval(async () => {
      await Promise.all([
        loadStatus(),
        loadStats(),
      ]);
    }, 30000);
  }

  // ────────────────────────────────────────────────────────────────
  //  Boot
  // ────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
