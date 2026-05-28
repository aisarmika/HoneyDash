(function () {
  const sidebar = document.querySelector('.main-sidebar .sidebar');
  if (!sidebar || document.getElementById('hdSocSidebar')) return;

  const API = window._HD_API || `${location.protocol}//${location.hostname}:8000`;
  const token = localStorage.getItem('token');

  function headers() {
    return token ? { Authorization: 'Bearer ' + token } : {};
  }

  function timeAgo(value) {
    if (!value) return 'never';
    const ts = new Date(value).getTime();
    if (!Number.isFinite(ts)) return 'unknown';
    const seconds = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function setState(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = 'hd-soc-state hd-soc-state-' + state;
  }

  function updateAlertBadges(count) {
    const n = Number(count || 0);
    const labels = document.querySelectorAll('#sidebarAlertBadge, a[href="alerts.html"] .badge, .main-header .navbar-badge');
    labels.forEach((badge) => {
      badge.textContent = String(n);
      badge.style.display = n > 0 ? '' : 'none';
      badge.classList.remove('badge-info', 'badge-warning');
      badge.classList.add(n > 0 ? 'badge-danger' : 'badge-secondary');
    });
  }

  function installNavGroups() {
    const nav = sidebar.querySelector('.nav-sidebar');
    if (!nav || nav.dataset.hdGrouped === '1') return;
    nav.dataset.hdGrouped = '1';

    const items = Array.from(nav.children);
    const label = (text) => {
      const li = document.createElement('li');
      li.className = 'nav-header hd-nav-section';
      li.textContent = text;
      return li;
    };

    const byHref = (href) => items.find((li) => li.querySelector(`a[href="${href}"]`));
    const dashboard = byHref('dashboard.html');
    const sessions = byHref('sessions.html');
    const alerts = byHref('alerts.html');
    const globe = byHref('globe.html');
    const reports = byHref('reports.html');
    const configuration = byHref('configuration.html');
    const users = byHref('users.html');

    nav.innerHTML = '';
    nav.appendChild(label('Monitor'));
    [dashboard, sessions, alerts, globe].filter(Boolean).forEach((li) => nav.appendChild(li));
    nav.appendChild(label('Manage'));
    [reports, configuration, users].filter(Boolean).forEach((li) => nav.appendChild(li));
  }

  function installPanel() {
    const panel = document.createElement('div');
    panel.id = 'hdSocSidebar';
    panel.className = 'hd-soc-sidebar';
    panel.innerHTML = `
      <div class="hd-soc-title">
        <span><i class="fas fa-shield-alt"></i> SOC Operations</span>
        <span class="hd-soc-live" id="hdSocLive">SYNC</span>
      </div>
      <div class="hd-soc-row">
        <span>Backend API</span>
        <span><i id="hdSocApiDot" class="hd-soc-state hd-soc-state-warn"></i><strong id="hdSocApi">checking</strong></span>
      </div>
      <div class="hd-soc-row">
        <span>Sensors Online</span>
        <strong id="hdSocSensors">-</strong>
      </div>
      <div class="hd-soc-row">
        <span>Active Alerts</span>
        <strong id="hdSocAlerts">-</strong>
      </div>
      <div class="hd-soc-row">
        <span>Events 24h</span>
        <strong id="hdSocEvents">-</strong>
      </div>
      <div class="hd-soc-remote">
        <div class="hd-soc-remote-head">
          <span><i class="fas fa-satellite-dish"></i> Remote Sensor</span>
          <span id="hdSocRemoteState" class="hd-soc-chip hd-soc-chip-muted">waiting</span>
        </div>
        <div class="hd-soc-muted">Last event: <span id="hdSocRemoteLast">never</span></div>
        <div class="hd-soc-muted">Ingest: <code id="hdSocIngestPath">/api/ingest/event</code></div>
      </div>
      <div class="hd-soc-footer">
        <i class="fas fa-key"></i> X-Sensor-Key protected
      </div>
    `;
    sidebar.appendChild(panel);
  }

  async function refreshSidebar() {
    if (!token) return;

    try {
      const health = await fetch(API + '/health');
      if (!health.ok) throw new Error('health failed');
      setText('hdSocApi', 'online');
      setState('hdSocApiDot', 'ok');
    } catch (e) {
      setText('hdSocApi', 'offline');
      setState('hdSocApiDot', 'bad');
    }

    try {
      const [statsRes, sensorsRes] = await Promise.all([
        fetch(API + '/api/dashboard/stats', { headers: headers() }),
        fetch(API + '/api/dashboard/sensors', { headers: headers() }),
      ]);
      if (!statsRes.ok || !sensorsRes.ok) throw new Error('sidebar data failed');
      const stats = await statsRes.json();
      const sensorData = await sensorsRes.json();
      const remote = (sensorData.sensors || []).find((s) => s.name === 'remote');

      setText('hdSocSensors', `${sensorData.online || 0}/${sensorData.total || 0}`);
      setText('hdSocAlerts', Number(stats.active_alerts || 0).toLocaleString());
      setText('hdSocEvents', Number(stats.total_attacks_24h || 0).toLocaleString());
      updateAlertBadges(stats.active_alerts || 0);

      if (remote && remote.last_seen) {
        setText('hdSocRemoteLast', timeAgo(remote.last_seen));
        const state = remote.online ? 'online' : 'idle';
        const chip = document.getElementById('hdSocRemoteState');
        if (chip) {
          chip.textContent = state;
          chip.className = 'hd-soc-chip ' + (remote.online ? 'hd-soc-chip-ok' : 'hd-soc-chip-warn');
        }
      } else {
        setText('hdSocRemoteLast', 'never');
        const chip = document.getElementById('hdSocRemoteState');
        if (chip) {
          chip.textContent = 'waiting';
          chip.className = 'hd-soc-chip hd-soc-chip-muted';
        }
      }
      setText('hdSocLive', 'LIVE');
      setText('hdSocIngestPath', new URL('/api/ingest/event', API).href.replace(/^https?:\/\//, ''));
    } catch (e) {
      setText('hdSocLive', 'STALE');
    }
  }

  installNavGroups();
  installPanel();
  refreshSidebar();
  setInterval(refreshSidebar, 30000);
})();
