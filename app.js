// Sentinel Console EDR - Real Host Telemetry & SOC Engine
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

let token = sessionStorage.getItem('tok');
let me = JSON.parse(sessionStorage.getItem('me') || 'null');
let es = null;
let soundEnabled = true;
let isStreamPaused = false;
let currentStreamFilter = 'all';

// Cached data
let currentAlerts = [];
let currentDevices = [];
let currentEvents = [];
let currentRules = [];
let currentProcesses = [];
let currentConnections = [];
let currentModalAlert = null;
let localHostInfo = null;

// Escaping
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

// Formatting
const when = iso => {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

// Web Audio API Cyber Sound Synthesizer
let audioCtx = null;
function playAlertChime(isCritical = false) {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();

    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    const now = audioCtx.currentTime;
    if (isCritical) {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(440, now + 0.22);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc.start(now);
      osc.stop(now + 0.22);
    } else {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(580, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.15);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  } catch (_) {}
}

function toggleAudio() {
  soundEnabled = !soundEnabled;
  $('#soundIconOn').style.display = soundEnabled ? 'block' : 'none';
  $('#soundIconOff').style.display = soundEnabled ? 'none' : 'block';
  toast(`Alert audio ${soundEnabled ? 'enabled' : 'muted'}`);
}

// Toast notification
function toast(msg, isCrit = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (isCrit ? ' toast-crit' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove('show'), 3400);
}

// API Helper
async function api(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;

  const r = await fetch(url, {
    ...opts,
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });

  const data = await r.json().catch(() => ({}));
  if (r.status === 401) {
    logout();
    throw new Error(data.error || 'Authentication required');
  }
  if (!r.ok) {
    throw new Error(data.error || 'Request failed');
  }
  return data;
}

// ---------- Authentication ----------
function fillCreds(u, p) {
  $('#user').value = u;
  $('#pass').value = p;
}

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('#loginErr').textContent = '';
  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: { username: $('#user').value.trim(), password: $('#pass').value }
    });
    token = data.token;
    me = { username: data.username, role: data.role, name: data.name };
    sessionStorage.setItem('tok', token);
    sessionStorage.setItem('me', JSON.stringify(me));
    start();
  } catch (err) {
    $('#loginErr').textContent = err.message;
  }
});

function logout() {
  sessionStorage.clear();
  token = null;
  me = null;
  if (es) { es.close(); es = null; }
  $('#app').hidden = true;
  $('#login').hidden = false;
}
$('#logout').onclick = logout;

// ---------- Navigation ----------
$('#nav').addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b || !b.dataset.tab) return;
  switchTab(b.dataset.tab);
});

function switchTab(tabId) {
  $$('#nav button').forEach(x => x.classList.toggle('on', x.dataset.tab === tabId));
  $$('[data-panel]').forEach(p => {
    p.hidden = p.dataset.panel !== tabId;
  });
  if (tabId === 'alerts') filterAlertsList();
  if (tabId === 'events') filterStreamDisplay();
  if (tabId === 'processes') loadRealProcesses();
  if (tabId === 'network') loadRealConnections();
}

// ---------- Real-Time Canvas Timeline Chart ----------
const chartCanvas = $('#liveChart');
const chartCtx = chartCanvas ? chartCanvas.getContext('2d') : null;
const CHART_POINTS = 60;
const eventHistory = new Array(CHART_POINTS).fill(1);
const threatHistory = new Array(CHART_POINTS).fill(0);

function resizeCanvas() {
  if (!chartCanvas) return;
  chartCanvas.width = chartCanvas.parentElement.clientWidth * window.devicePixelRatio;
  chartCanvas.height = chartCanvas.parentElement.clientHeight * window.devicePixelRatio;
}
window.addEventListener('resize', resizeCanvas);

function renderChart() {
  if (!chartCtx || !chartCanvas) return;
  const w = chartCanvas.width;
  const h = chartCanvas.height;

  chartCtx.clearRect(0, 0, w, h);

  // Background grid lines
  chartCtx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
  chartCtx.lineWidth = 1;
  const gridRows = 3;
  for (let i = 1; i <= gridRows; i++) {
    const y = (h / (gridRows + 1)) * i;
    chartCtx.beginPath();
    chartCtx.moveTo(0, y);
    chartCtx.lineTo(w, y);
    chartCtx.stroke();
  }

  const maxVal = Math.max(8, ...eventHistory, ...threatHistory.map(v => v * 3));
  const stepX = w / (CHART_POINTS - 1);

  // 1. Ingested Events (Cyan filled line)
  chartCtx.beginPath();
  eventHistory.forEach((val, i) => {
    const x = i * stepX;
    const y = h - (val / maxVal) * (h * 0.8) - 10;
    if (i === 0) chartCtx.moveTo(x, y);
    else chartCtx.lineTo(x, y);
  });
  chartCtx.strokeStyle = '#38bdf8';
  chartCtx.lineWidth = 2.5 * window.devicePixelRatio;
  chartCtx.stroke();

  // Gradient fill under cyan line
  chartCtx.lineTo(w, h);
  chartCtx.lineTo(0, h);
  chartCtx.closePath();
  const grad = chartCtx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(56, 189, 248, 0.25)');
  grad.addColorStop(1, 'rgba(56, 189, 248, 0.0)');
  chartCtx.fillStyle = grad;
  chartCtx.fill();

  // 2. Threat Spikes (Crimson bars/dots)
  threatHistory.forEach((count, i) => {
    if (count > 0) {
      const x = i * stepX;
      const barHeight = Math.min(h * 0.85, (count / maxVal) * (h * 1.4) + 20);
      const y = h - barHeight;

      // Spike glow bar
      chartCtx.fillStyle = 'rgba(244, 63, 94, 0.4)';
      chartCtx.fillRect(x - 3 * window.devicePixelRatio, y, 6 * window.devicePixelRatio, barHeight);

      // Spike beacon dot
      chartCtx.beginPath();
      chartCtx.arc(x, y, 4.5 * window.devicePixelRatio, 0, Math.PI * 2);
      chartCtx.fillStyle = '#f43f5e';
      chartCtx.fill();
      chartCtx.strokeStyle = '#fff';
      chartCtx.lineWidth = 1 * window.devicePixelRatio;
      chartCtx.stroke();
    }
  });
}

function pushChartData(eventDelta, threatDelta) {
  eventHistory.shift();
  eventHistory.push(eventDelta);
  threatHistory.shift();
  threatHistory.push(threatDelta);
  renderChart();
}

let pendingChartEvents = 0;
let pendingChartThreats = 0;
setInterval(() => {
  pushChartData(pendingChartEvents, pendingChartThreats);
  pendingChartEvents = 0;
  pendingChartThreats = 0;
}, 1000);

// ---------- Render Functions ----------
function renderAlertItem(a, showActions = true) {
  const isResolved = a.status === 'resolved';
  return `
    <div class="alert-item ${a.severity} ${isResolved ? 'resolved' : ''}" id="alert-${a.id}">
      <div class="alert-main">
        <div class="alert-topline">
          <span class="tag ${a.severity}">${a.severity}</span>
          <span class="tag-mitre">${esc(a.mitre || 'T1059')}</span>
          <strong class="alert-rule-title">${esc(a.rule)}</strong>
        </div>
        <div class="alert-meta">
          <span><strong>Host:</strong> ${esc(a.device)}</span>
          <span>&bull;</span>
          <span><strong>Engine:</strong> ${esc(a.ruleType)}</span>
          <span>&bull;</span>
          <span>${when(a.time)}</span>
          <span>&bull;</span>
          <span class="tag ${isResolved ? 'protected' : 'critical'}">${a.status}</span>
        </div>
      </div>
      <div class="alert-actions">
        <button class="btn btn-xs btn-outline" onclick="openInvestigateModal('${a.id}')">Investigate</button>
        ${showActions && !isResolved ? `
          <button class="btn btn-xs btn-secondary" onclick="resolveSingleAlert('${a.id}')">Resolve</button>
        ` : ''}
      </div>
    </div>
  `;
}

function renderDeviceCard(d) {
  const cpuClass = d.cpu > 75 ? 'crit' : d.cpu > 50 ? 'warn' : '';
  const memClass = d.mem > 80 ? 'crit' : d.mem > 60 ? 'warn' : '';
  return `
    <div class="device-card ${d.isolated ? 'isolated' : ''}">
      <div class="device-card-header">
        <div>
          <div class="device-id">${esc(d.id)} ${d.isLocal ? '<span class="tag-mitre">LOCAL SENSOR</span>' : ''}</div>
          <div class="device-sub">${esc(d.name || d.id)} &bull; ${esc(d.os)}</div>
        </div>
        <span class="tag ${d.isolated ? 'isolated' : 'protected'}">
          ${d.isolated ? 'QUARANTINED' : 'PROTECTED'}
        </span>
      </div>

      <div class="device-metrics">
        <div class="load-bar-wrap">
          <div class="load-label"><span>CPU LOAD</span><span>${d.cpu || 20}%</span></div>
          <div class="progress-track"><div class="progress-fill ${cpuClass}" style="width: ${d.cpu || 20}%"></div></div>
        </div>
        <div class="load-bar-wrap">
          <div class="load-label"><span>MEMORY</span><span>${d.mem || 45}%</span></div>
          <div class="progress-track"><div class="progress-fill ${memClass}" style="width: ${d.mem || 45}%"></div></div>
        </div>
      </div>

      <div style="font-size:12px; color:var(--text-muted); display:flex; justify-content:space-between;">
        <span>IP: <code class="mono" style="color:var(--text-main);">${esc(d.ip || '10.0.4.1')}</code></span>
        <span>Owner: ${esc(d.owner || 'System')}</span>
      </div>

      <div class="device-card-actions">
        ${me.role === 'admin' ? `
          <button class="btn btn-xs ${d.isolated ? 'btn-secondary' : 'btn-danger'}" onclick="toggleDeviceIsolation('${d.id}')">
            ${d.isolated ? 'Release Network Isolation' : 'Quarantine Endpoint'}
          </button>
        ` : ''}
        ${d.isLocal ? `
          <button class="btn btn-xs btn-primary" onclick="switchTab('processes')">Inspect Processes</button>
        ` : `
          <button class="btn btn-xs btn-outline" onclick="triggerDeviceScan('${d.id}')">Remote Scan</button>
        `}
      </div>
    </div>
  `;
}

function formatStreamEvent(e) {
  let catClass = 'cat-process';
  if (e.type === 'network') catClass = 'cat-network';
  else if (e.type === 'file') catClass = 'cat-file';
  else if (e.type === 'registry') catClass = 'cat-registry';

  let detail = '';
  if (e.type === 'process') {
    detail = `EXEC: <strong>${esc(e.name || '')}</strong> ${e.pid ? `[PID: ${e.pid}]` : ''} ${e.parent ? `[parent: ${esc(e.parent)}]` : ''} ${e.cmd ? `<span style="color:#94a3b8">${esc(e.cmd.slice(0, 90))}</span>` : ''}`;
  } else if (e.type === 'network') {
    detail = `CONNECT: <strong>${esc(e.domain || e.ip || '')}</strong> ${e.port ? `:${e.port}` : ''} ${e.protocol ? `(${e.protocol})` : ''}`;
  } else if (e.type === 'file') {
    detail = `FILE I/O: <strong>${esc(e.name || '')}</strong> ${e.entropy ? `[entropy: ${e.entropy}]` : ''} ${e.renames ? `[renames: ${e.renames}]` : ''} ${e.source ? `[sensor: ${esc(e.source)}]` : ''}`;
  } else if (e.type === 'registry') {
    detail = `REGISTRY: <strong>${esc(e.key || '')}</strong> &rarr; ${esc(e.value || '')}`;
  } else {
    detail = esc(JSON.stringify(e));
  }

  return `
    <div class="stream-row" data-type="${esc(e.type)}" data-host="${esc(e.device)}">
      <span class="stream-time mono">${when(e.time)}</span>
      <span class="stream-device mono">${esc(e.device)}</span>
      <span class="stream-category ${catClass}">${esc(e.type)}</span>
      <span class="stream-detail">${detail}</span>
    </div>
  `;
}

// ---------- Main Refresh Data Flow ----------
async function refresh() {
  try {
    const [summary, alerts, devices, events, rules, realHost] = await Promise.all([
      api('/api/summary'),
      api('/api/alerts'),
      api('/api/devices'),
      api('/api/events'),
      api('/api/rules'),
      api('/api/real/system-info').catch(() => null)
    ]);

    currentAlerts = alerts;
    currentDevices = devices;
    currentEvents = events;
    currentRules = rules;
    localHostInfo = realHost;

    // 1. Topbar & DEFCON
    const defconPill = $('#defconPill');
    const defconText = $('#defconText');
    defconText.textContent = summary.defcon;
    if (summary.critical > 0) {
      defconPill.className = 'defcon-pill defcon-critical';
    } else {
      defconPill.className = 'defcon-pill defcon-normal';
    }
    $('#epsVal').textContent = summary.eps;

    // 2. Local Host Banner
    if (realHost) {
      $('#topHostId').textContent = realHost.id;
      $('#rhName').textContent = realHost.id;
      $('#rhOs').textContent = realHost.os;
      $('#rhIp').textContent = realHost.ip;

      const cpuEl = $('#rhCpuBadge');
      cpuEl.textContent = `${realHost.cpu}%`;
      cpuEl.className = `badge ${realHost.cpu > 75 ? 'badge-crimson' : realHost.cpu > 50 ? 'badge-orange' : 'badge-success'}`;

      const memEl = $('#rhMemBadge');
      memEl.textContent = `${realHost.mem}% (${realHost.ramUsedMB} / ${realHost.ramTotalMB} MB)`;
      memEl.className = `badge ${realHost.mem > 80 ? 'badge-crimson' : realHost.mem > 60 ? 'badge-orange' : 'badge-success'}`;
    }

    // 3. Overview Stat Cards
    $('#valDevices').textContent = summary.devices;
    $('#valProtected').textContent = `${summary.devices - summary.isolated} Healthy`;
    $('#valIsolated').textContent = `${summary.isolated} Quarantined`;

    $('#valOpenAlerts').textContent = summary.openAlerts;
    $('#valCritCount').textContent = `${summary.critical} Critical`;
    $('#valHighCount').textContent = `${summary.high} High`;
    $('#valMedCount').textContent = `${summary.medium} Medium`;

    const cardAlerts = $('#cardAlerts');
    cardAlerts.classList.toggle('has-critical', summary.critical > 0);

    $('#valEvents').textContent = summary.events;
    $('#valRulesActive').textContent = `${summary.activeRules} / ${summary.totalRules}`;

    // Nav Badges
    $('#badgeAlerts').textContent = summary.openAlerts;
    $('#badgeDevices').textContent = summary.devices;

    // 4. Overview Lists
    const openAlerts = alerts.filter(a => a.status === 'open');
    $('#ovAlerts').innerHTML = openAlerts.slice(0, 5).map(a => renderAlertItem(a, true)).join('')
      || '<p class="text-muted" style="padding:16px 0;">No active threats detected. Monitored host and fleet secure.</p>';

    $('#ovDevices').innerHTML = devices.slice(0, 4).map(d => `
      <div class="device-mini-row">
        <div class="device-mini-info">
          <h4>${esc(d.id)} ${d.isLocal ? '<span class="tag-mitre">LOCAL SENSOR</span>' : ''}</h4>
          <span class="device-mini-sub">${esc(d.os)} &bull; IP: ${esc(d.ip || '10.0.0.1')}</span>
        </div>
        <span class="tag ${d.isolated ? 'isolated' : 'protected'}">${d.isolated ? 'ISOLATED' : 'PROTECTED'}</span>
      </div>
    `).join('');

    // 5. Full Device Grid
    $('#devices').innerHTML = devices.map(renderDeviceCard).join('');

    // 6. Detection Rules
    $('#rules').innerHTML = rules.map(r => `
      <div class="rule-card">
        <div class="rule-card-header">
          <div>
            <div class="rule-name">${esc(r.name)}</div>
            <div style="margin-top:4px; display:flex; gap:6px;">
              <span class="tag ${r.severity}">${r.severity}</span>
              <span class="tag-mitre">${esc(r.mitre || 'T1059')}</span>
              <span class="tag low">${esc(r.type)}</span>
            </div>
          </div>
          ${me.role === 'admin' ? `
            <button class="btn btn-xs ${r.enabled ? 'btn-primary' : 'btn-outline'}" onclick="toggleRule('${r.id}')">
              ${r.enabled ? 'Active' : 'Disabled'}
            </button>
          ` : `<span class="tag ${r.enabled ? 'protected' : ''}">${r.enabled ? 'on' : 'off'}</span>`}
        </div>
        <p class="rule-desc">${esc(r.description)}</p>
        <div class="rule-foot">
          <span class="rule-hits">Triggers: <strong>${r.hits || 0}</strong> hits</span>
          <span class="mono text-muted" style="font-size:11px;">${r.id}</span>
        </div>
      </div>
    `).join('');

    // 7. Audit tab
    if (me.role === 'admin') {
      const audit = await api('/api/audit');
      $('#audit').innerHTML = audit.map(a => `
        <div class="audit-row">
          <span class="audit-time">${when(a.time)}</span>
          <span class="audit-user">${esc(a.user)}</span>
          <span class="audit-action">${esc(a.action)}</span>
          <span class="audit-detail">${esc(a.detail)}</span>
        </div>
      `).join('') || '<div style="padding:20px; color:var(--text-muted);">No audit entries recorded yet.</div>';
    }

    filterAlertsList();
  } catch (err) {
    console.error('Refresh error:', err);
  }
}

// ==================== REAL PROCESS EXPLORER ====================
async function loadRealProcesses() {
  const tbody = $('#processTableBody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px;">Fetching live host processes...</td></tr>';
  try {
    const procs = await api('/api/real/processes');
    currentProcesses = procs;
    $('#procCountLabel').textContent = `${procs.length} processes running on host`;
    renderProcessTable(procs);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--crimson); text-align:center; padding:20px;">Failed to load processes: ${esc(err.message)}</td></tr>`;
  }
}

function renderProcessTable(procs) {
  const tbody = $('#processTableBody');
  if (!procs || procs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px;">No processes found.</td></tr>';
    return;
  }
  tbody.innerHTML = procs.map(p => `
    <tr>
      <td><strong class="text-cyan">${p.pid}</strong></td>
      <td><strong>${esc(p.name)}</strong></td>
      <td>${p.ramMB} MB</td>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(p.path)}">${esc(p.path)}</td>
      <td>
        ${p.suspicious ? '<span class="tag critical">SUSPICIOUS_PATH</span>' : '<span class="tag low">VERIFIED</span>'}
      </td>
      <td>
        <button class="btn btn-xs btn-danger" onclick="killProcessPrompt(${p.pid}, '${esc(p.name)}')">
          Kill Process
        </button>
      </td>
    </tr>
  `).join('');
}

function filterProcessTable() {
  const q = ($('#processSearch').value || '').toLowerCase().trim();
  if (!q) return renderProcessTable(currentProcesses);
  const filtered = currentProcesses.filter(p =>
    String(p.pid).includes(q) ||
    p.name.toLowerCase().includes(q) ||
    (p.path && p.path.toLowerCase().includes(q))
  );
  renderProcessTable(filtered);
}

async function killProcessPrompt(pid, name) {
  if (!confirm(`Are you sure you want to terminate real process ${name} (PID: ${pid}) on this computer?`)) {
    return;
  }
  try {
    const res = await api('/api/real/kill-process', {
      method: 'POST',
      body: { pid }
    });
    toast(`Terminated process ${name} (PID ${pid})`);
    loadRealProcesses();
  } catch (err) {
    toast(err.message, true);
  }
}

// ==================== REAL SOCKETS & PORTS ====================
async function loadRealConnections() {
  const tbody = $('#connTableBody');
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px;">Fetching active TCP connections...</td></tr>';
  try {
    const conns = await api('/api/real/connections');
    currentConnections = conns;
    if (conns.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px;">No active connections returned.</td></tr>';
      return;
    }
    tbody.innerHTML = conns.map(c => `
      <tr>
        <td>
          <span class="tag ${c.state === 'LISTENING' ? 'medium' : c.state === 'ESTABLISHED' ? 'low' : ''}">${esc(c.state)}</span>
        </td>
        <td><code>${esc(c.localAddress)}:${c.localPort}</code></td>
        <td><code>${esc(c.remoteAddress)}:${c.remotePort}</code></td>
        <td><strong class="text-cyan">${c.pid || '-'}</strong></td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:var(--crimson); text-align:center; padding:20px;">Failed to load connections: ${esc(err.message)}</td></tr>`;
  }
}

// ==================== REAL FILE SCANNER & CANARY TRAP ====================
$('#fileScanForm').addEventListener('submit', async e => {
  e.preventDefault();
  const filePath = $('#fileScanInput').value.trim();
  if (!filePath) return;

  const resDiv = $('#fileScanResult');
  resDiv.style.display = 'block';
  resDiv.innerHTML = '<div style="padding:14px; text-align:center;">Calculating Shannon entropy and cryptographic SHA-256 hash...</div>';

  try {
    const r = await api('/api/real/scan-file', {
      method: 'POST',
      body: { filePath }
    });

    const isSusp = r.verdict !== 'clean';
    resDiv.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
        <div>
          <h4 style="font-size:16px; color:#fff;">${esc(r.fileName)}</h4>
          <span class="text-muted" style="font-size:12px;">${esc(r.filePath)} &bull; ${r.sizeFormatted}</span>
        </div>
        <span class="tag ${r.verdict === 'clean' ? 'low' : 'critical'}">${r.verdict.toUpperCase()}</span>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:12px; margin-bottom:14px;">
        <div style="background:#090e1c; padding:10px 14px; border-radius:6px; border:1px solid var(--border);">
          <span style="font-size:11px; color:var(--text-sub);">SHANNON ENTROPY</span>
          <div style="font-size:20px; font-weight:800; font-family:var(--font-mono); color:${r.entropy > 7.2 ? 'var(--crimson)' : 'var(--cyan)'};">
            ${r.entropy} <span style="font-size:12px; color:var(--text-sub);">/ 8.0 bits/byte</span>
          </div>
        </div>
        <div style="background:#090e1c; padding:10px 14px; border-radius:6px; border:1px solid var(--border);">
          <span style="font-size:11px; color:var(--text-sub);">MAGIC BYTES / FORMAT</span>
          <div style="font-size:14px; font-weight:700; color:#fff; margin-top:4px;">${esc(r.magic)}</div>
        </div>
      </div>

      <div style="margin-bottom:12px;">
        <span style="font-size:11px; color:var(--text-sub);">SHA-256 HASH:</span>
        <code class="mono" style="display:block; background:#090e1c; padding:6px 10px; border-radius:4px; font-size:11px; color:#93c5fd; word-break:break-all;">${r.sha256}</code>
      </div>

      ${r.reasons && r.reasons.length ? `
        <div style="margin-bottom:14px;">
          <strong style="font-size:12px; color:var(--text-muted);">HEURISTIC SIGNALS:</strong>
          <ul style="padding-left:18px; font-size:12px; margin-top:4px; color:${isSusp ? 'var(--crimson)' : 'inherit'};">
            ${r.reasons.map(x => `<li>${esc(x)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}

      <div style="display:flex; justify-content:flex-end; gap:8px;">
        <button class="btn btn-xs btn-danger" onclick="quarantineFilePrompt('${esc(r.filePath)}')">
          Quarantine File to Vault
        </button>
      </div>
    `;
  } catch (err) {
    resDiv.innerHTML = `<div style="color:var(--crimson); padding:14px;">Inspection Error: ${esc(err.message)}</div>`;
  }
});

async function quarantineFilePrompt(filePath) {
  if (!confirm(`Quarantine file "${filePath}"? It will be moved into the secure quarantine vault.`)) return;
  try {
    const res = await api('/api/real/quarantine-file', {
      method: 'POST',
      body: { filePath }
    });
    toast(`File moved to quarantine vault: ${res.quarantinedPath}`);
    $('#fileScanForm').dispatchEvent(new Event('submit'));
  } catch (err) {
    toast(err.message, true);
  }
}

async function testCanaryDrop(scenario) {
  try {
    const res = await api('/api/real/test-canary', {
      method: 'POST',
      body: { scenario }
    });
    toast(`Canary drop written: ${res.fileName} (${res.size} bytes). Background sensor evaluating!`, true);
    playAlertChime(true);
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

// ---------- Alerts Filter & Export ----------
function filterAlertsList() {
  const query = ($('#alertSearch').value || '').toLowerCase().trim();
  const sev = $('#severityFilter').value;
  const stat = $('#statusFilter').value;

  const filtered = currentAlerts.filter(a => {
    if (sev !== 'all' && a.severity !== sev) return false;
    if (stat !== 'all' && a.status !== stat) return false;
    if (query) {
      const matchText = `${a.rule} ${a.device} ${a.ruleType} ${a.mitre} ${JSON.stringify(a.evidence)}`.toLowerCase();
      if (!matchText.includes(query)) return false;
    }
    return true;
  });

  $('#alerts').innerHTML = filtered.map(a => renderAlertItem(a, true)).join('')
    || '<div style="padding:30px; text-align:center; color:var(--text-muted);">No incidents match the active filter criteria.</div>';
}

function exportAlerts() {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(currentAlerts, null, 2));
  const a = document.createElement('a');
  a.setAttribute('href', dataStr);
  a.setAttribute('download', `sentinel_alerts_export_${Date.now()}.json`);
  document.body.appendChild(a);
  a.click();
  a.remove();
  toast('Alerts exported as JSON');
}

// ---------- Live Stream Handling ----------
function appendStreamEvent(ev) {
  pendingChartEvents++;
  if (isStreamPaused) return;

  const eventsBody = $('#events');
  if (!eventsBody) return;

  const html = formatStreamEvent(ev);
  eventsBody.insertAdjacentHTML('afterbegin', html);

  if (eventsBody.children.length > 150) {
    eventsBody.removeChild(eventsBody.lastChild);
  }
}

function toggleStreamPause() {
  isStreamPaused = !isStreamPaused;
  $('#pauseStreamText').textContent = isStreamPaused ? 'Resume Stream' : 'Pause Stream';
  toast(isStreamPaused ? 'Live telemetry stream paused' : 'Live stream resumed');
}

function clearLiveEvents() {
  $('#events').innerHTML = '';
  toast('Terminal stream buffer cleared');
}

function filterStream(type) {
  currentStreamFilter = type;
  $$('#streamFilters button').forEach(b => b.classList.toggle('on', b.dataset.type === type));
  filterStreamDisplay();
}

function filterStreamDisplay() {
  const query = ($('#eventSearch').value || '').toLowerCase().trim();
  $$('#events .stream-row').forEach(row => {
    const rowType = row.dataset.type;
    const rowText = row.textContent.toLowerCase();
    const typeMatch = currentStreamFilter === 'all' || rowType === currentStreamFilter;
    const queryMatch = !query || rowText.includes(query);
    row.style.display = (typeMatch && queryMatch) ? 'flex' : 'none';
  });
}

// ---------- Incident Investigation Modal ----------
function openInvestigateModal(alertId) {
  const alert = currentAlerts.find(a => a.id === alertId);
  if (!alert) return;
  currentModalAlert = alert;

  $('#modalSeverity').textContent = alert.severity.toUpperCase();
  $('#modalSeverity').className = `modal-badge tag ${alert.severity}`;
  $('#modalTitle').textContent = alert.rule;
  $('#modalHost').textContent = alert.device;
  $('#modalMitre').textContent = alert.mitre || 'T1059';
  $('#modalType').textContent = alert.ruleType;
  $('#modalTime').textContent = new Date(alert.time).toLocaleString();
  $('#modalDesc').textContent = alert.description || 'Heuristic intrusion trigger matched threat behavior pattern.';

  const ev = alert.evidence || {};
  const treeEl = $('#modalProcessTree');
  if (ev.type === 'process') {
    treeEl.innerHTML = `
      <div>[PID ${ev.ppid || 1000}] <strong>${esc(ev.parent || 'explorer.exe')}</strong></div>
      <div style="padding-left: 20px;">&boxur;&HorizontalLine; [PID ${ev.pid || 4892}] <strong style="color:#f43f5e;">${esc(ev.name || 'powershell.exe')}</strong></div>
      ${ev.cmd ? `<div style="padding-left: 40px; color:#cbd5e1; font-size:11px; margin-top:4px;">Commandline: <code>${esc(ev.cmd)}</code></div>` : ''}
    `;
    $('#modalProcessTreeSection').style.display = 'block';
  } else if (ev.type === 'network') {
    treeEl.innerHTML = `
      <div>Outbound Socket: <strong style="color:#38bdf8;">${esc(alert.device)}</strong> &rarr; <strong style="color:#f43f5e;">${esc(ev.domain || ev.ip)}:${ev.port || 443}</strong></div>
      <div style="padding-left: 20px; font-size:11px; color:#94a3b8;">Protocol: ${esc(ev.protocol || 'HTTPS')} &bull; Payload Size: ${esc(ev.bytesSent || 0)} bytes</div>
    `;
    $('#modalProcessTreeSection').style.display = 'block';
  } else if (ev.type === 'file') {
    treeEl.innerHTML = `
      <div>File Target: <strong style="color:#f43f5e;">${esc(ev.path || '')}${esc(ev.name || '')}</strong></div>
      <div style="padding-left: 20px; font-size:11px; color:#94a3b8;">Entropy: <strong>${esc(ev.entropy)}</strong> &bull; Rename Frequency: <strong>${esc(ev.renames || 0)} ops</strong></div>
    `;
    $('#modalProcessTreeSection').style.display = 'block';
  } else {
    $('#modalProcessTreeSection').style.display = 'none';
  }

  $('#modalEvidence').textContent = JSON.stringify(alert.evidence, null, 2);

  const dev = currentDevices.find(d => d.id === alert.device);
  const isolateBtn = $('#modalIsolateBtn');
  if (dev) {
    isolateBtn.textContent = dev.isolated ? 'Release Host from Quarantine' : 'Quarantine Host from Subnet';
    isolateBtn.onclick = () => {
      toggleDeviceIsolation(dev.id);
      closeModal();
    };
  }

  const resolveBtn = $('#modalResolveBtn');
  resolveBtn.onclick = () => {
    resolveSingleAlert(alert.id);
    closeModal();
  };

  $('#investigateModal').hidden = false;
}

function closeModal() {
  $('#investigateModal').hidden = true;
  currentModalAlert = null;
}

function copyEvidence() {
  if (!currentModalAlert) return;
  navigator.clipboard.writeText(JSON.stringify(currentModalAlert.evidence, null, 2))
    .then(() => toast('Evidence JSON copied to clipboard'))
    .catch(() => toast('Failed to copy to clipboard'));
}

// ---------- Actions: Alert Resolution & Device Isolation ----------
async function resolveSingleAlert(id) {
  try {
    await api(`/api/alerts/${id}/resolve`, { method: 'POST' });
    toast('Alert status updated to Resolved');
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

async function resolveAllAlerts() {
  try {
    const res = await api('/api/alerts/resolve-all', { method: 'POST' });
    toast(`Resolved ${res.count || 0} active alerts`);
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

async function toggleDeviceIsolation(id) {
  try {
    const dev = await api(`/api/devices/${id}/isolate`, { method: 'POST' });
    toast(`Host ${dev.id} network status: ${dev.isolated ? 'QUARANTINED' : 'PROTECTED'}`);
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

async function triggerDeviceScan(id) {
  try {
    const res = await api(`/api/devices/${id}/scan`, { method: 'POST' });
    toast(res.message || `Heuristic scan completed on ${id}`);
  } catch (err) {
    toast(err.message);
  }
}

async function toggleRule(id) {
  try {
    await api(`/api/rules/${id}/toggle`, { method: 'POST' });
    toast('Detection rule state updated');
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

// ---------- Threat Simulation Lab ----------
async function runSimulation(scenario) {
  const targetDevice = $('#simTargetDevice') ? $('#simTargetDevice').value : (localHostInfo ? localHostInfo.id : 'WIN-0142');
  try {
    const res = await api('/api/simulate', {
      method: 'POST',
      body: { scenario, device: targetDevice === 'LOCAL_HOST' ? (localHostInfo?.id || 'LOCAL_HOST') : targetDevice }
    });
    toast(`Simulated threat launched: ${scenario}`, true);
    playAlertChime(true);
    refresh();
  } catch (err) {
    toast(err.message);
  }
}

function quickSim(scenario) {
  runSimulation(scenario);
}

// ---------- Threat Intelligence Scanner ----------
$('#urlForm').addEventListener('submit', async e => {
  e.preventDefault();
  const url = $('#urlIn').value.trim();
  if (!url) return;
  try {
    const r = await api('/api/scan-url', { method: 'POST', body: { url } });
    renderScanResult(r);
  } catch (err) {
    toast(err.message);
  }
});

function checkSample(sample) {
  $('#urlIn').value = sample;
  $('#urlForm').dispatchEvent(new Event('submit'));
}

function renderScanResult(r) {
  const scoreColor = r.score >= 60 ? 'var(--crimson)' : r.score >= 25 ? 'var(--orange)' : 'var(--emerald)';
  const reasonsHtml = (r.reasons && r.reasons.length)
    ? r.reasons.map(x => `<li>${esc(x)}</li>`).join('')
    : '<li>No malicious heuristics or reputation flags identified.</li>';

  $('#urlOut').innerHTML = `
    <div class="verdict-card">
      <div class="verdict-header">
        <div>
          <span class="text-muted" style="font-size:12px;">TARGET HOST / IOC:</span>
          <div class="verdict-title">${esc(r.host)}</div>
        </div>
        <span class="tag ${r.verdict}">${r.verdict.toUpperCase()}</span>
      </div>

      <div class="risk-meter">
        <div>
          <span style="font-size:11px; font-weight:700; color:var(--text-muted); display:block;">THREAT RISK SCORE</span>
          <span class="risk-score-num" style="color:${scoreColor};">${r.score}</span>
          <span style="color:var(--text-sub); font-size:12px;">/ 100</span>
        </div>
        <div style="flex:1;">
          <div class="progress-track" style="height:10px;">
            <div class="progress-fill" style="width:${r.score}%; background:${scoreColor};"></div>
          </div>
        </div>
      </div>

      <div>
        <h4 style="font-size:12px; font-weight:700; color:var(--text-muted); margin-bottom:8px;">HEURISTIC REASONS & INDICATORS</h4>
        <ul class="reasons-list">${reasonsHtml}</ul>
      </div>
    </div>
  `;
}

// ---------- Create Custom Rule Modal ----------
function openCreateRuleModal() {
  $('#createRuleModal').hidden = false;
}
function closeCreateRuleModal() {
  $('#createRuleModal').hidden = true;
}

$('#createRuleForm').addEventListener('submit', async e => {
  e.preventDefault();
  const ruleData = {
    name: $('#newRuleName').value.trim(),
    type: $('#newRuleType').value,
    severity: $('#newRuleSev').value,
    mitre: $('#newRuleMitre').value.trim(),
    customPattern: $('#newRulePattern').value.trim(),
    description: $('#newRuleDesc').value.trim()
  };
  try {
    await api('/api/rules', { method: 'POST', body: ruleData });
    toast('Custom rule deployed to detection engine');
    closeCreateRuleModal();
    refresh();
  } catch (err) {
    toast(err.message);
  }
});

// ---------- Start Application Engine ----------
function start() {
  $('#login').hidden = true;
  $('#app').hidden = false;

  $('#userName').textContent = me.name || me.username;
  $('#userRole').textContent = me.role;
  $('#userInitial').textContent = (me.username || 'A')[0].toUpperCase();
  $('#auditTab').hidden = me.role !== 'admin';

  resizeCanvas();
  refresh();

  // Connect SSE live stream
  if (es) es.close();
  es = new EventSource('/api/stream?token=' + encodeURIComponent(token));

  es.onmessage = m => {
    try {
      const { kind, data } = JSON.parse(m.data);
      if (kind === 'alert') {
        pendingChartThreats++;
        playAlertChime(data.severity === 'critical');
        toast(`Threat Alert [${data.severity.toUpperCase()}]: ${data.rule} on ${data.device}`, data.severity === 'critical');
      } else if (kind === 'event') {
        appendStreamEvent(data);
      } else if (kind === 'host_update') {
        // Live CPU/Mem update from real host sensor
        const cpuEl = $('#rhCpuBadge');
        if (cpuEl) {
          cpuEl.textContent = `${data.cpu}%`;
          cpuEl.className = `badge ${data.cpu > 75 ? 'badge-crimson' : data.cpu > 50 ? 'badge-orange' : 'badge-success'}`;
        }
        const memEl = $('#rhMemBadge');
        if (memEl) {
          memEl.textContent = `${data.mem}% (${data.ramUsedMB} / ${data.ramTotalMB} MB)`;
          memEl.className = `badge ${data.mem > 80 ? 'badge-crimson' : data.mem > 60 ? 'badge-orange' : 'badge-success'}`;
        }
      }
      clearTimeout(start.debouncedRefresh);
      start.debouncedRefresh = setTimeout(refresh, 800);
    } catch (_) {}
  };

  es.onerror = () => {};
}

if (token && me) {
  start();
}
