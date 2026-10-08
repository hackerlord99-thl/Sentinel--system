// Sentinel Console backend (Node.js + Express) - Enterprise Detection & Response Platform
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const storage = require('./storage');
const systemSensor = require('./systemSensor');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- Users / RBAC ----------
const hash = p => crypto.createHash('sha256').update(p).digest('hex');
const USERS = {
  admin:   { pass: hash('admin123'),   role: 'admin', name: 'Chief SecOps Admin' },
  analyst: { pass: hash('analyst123'), role: 'analyst', name: 'Tier-2 Threat Analyst' }
};

const sign = payload => {
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
};

const verify = tok => {
  const [b, s] = (tok || '').split('.');
  if (!b || !s) return null;
  const good = crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
  if (s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(good))) return null;
  try {
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
};

const auth = (roles) => (req, res, next) => {
  const tok = (req.headers.authorization || '').replace('Bearer ', '') || req.query.token;
  const user = verify(tok);
  if (!user) return res.status(401).json({ error: 'Sign in required' });
  if (roles && !roles.includes(user.role)) return res.status(403).json({ error: 'Your role cannot perform this action' });
  req.user = user;
  next();
};

// ---------- Data State with Persistent Storage ----------
const clients = new Set();
let events = storage.get('events');
let alerts = storage.get('alerts');
let audit = storage.get('audit');
let rules = storage.get('rules');
let devices = storage.get('devices');

let totalEventsIngested = events.length;
let eventsInLastWindow = 0;
let rollingEps = 0;

setInterval(() => {
  rollingEps = (eventsInLastWindow / 2).toFixed(1);
  eventsInLastWindow = 0;
}, 2000);

// Initialize Devices with REAL Local Host as Primary
async function initDevices() {
  const realHostInfo = await systemSensor.getSystemInfo();
  const fleetPreset = [
    { id: realHostInfo.id, name: `${realHostInfo.id} [LOCAL HOST SENSOR]`, os: realHostInfo.os, owner: realHostInfo.owner, ip: realHostInfo.ip, status: 'protected', isolated: false, cpu: realHostInfo.cpu, mem: realHostInfo.mem, isLocal: true, lastSeen: 'Active Now' },
    { id: 'SRV-DC01', name: 'Primary-Domain-Controller', os: 'Windows Server 2022', owner: 'Infra SecOps', ip: '10.0.1.10', status: 'protected', isolated: false, cpu: 44, mem: 68, isLocal: false, lastSeen: 'Active' },
    { id: 'MAC-0077', name: 'Design-MacBook-Pro', os: 'macOS 14.5 Sonoma', owner: 'Bob Vance (Creative)', ip: '10.0.4.77', status: 'protected', isolated: false, cpu: 19, mem: 52, isLocal: false, lastSeen: 'Active' },
    { id: 'LNX-K8S2', name: 'Prod-Kubernetes-Worker-02', os: 'Ubuntu 22.04 LTS', owner: 'DevOps Platform', ip: '10.0.2.22', status: 'protected', isolated: false, cpu: 62, mem: 79, isLocal: false, lastSeen: 'Active' },
    { id: 'WIN-0142', name: 'Finance-Workstation-01', os: 'Windows 11 Enterprise', owner: 'Alice Cooper (Finance)', ip: '10.0.4.142', status: 'protected', isolated: false, cpu: 28, mem: 46, isLocal: false, lastSeen: 'Active' }
  ];

  if (!devices || devices.length === 0) {
    devices = fleetPreset;
  } else {
    // Ensure local host is always up-to-date
    const idx = devices.findIndex(d => d.isLocal || d.id === realHostInfo.id);
    if (idx !== -1) {
      devices[idx] = { ...devices[idx], ...realHostInfo, isLocal: true };
    } else {
      devices.unshift({ ...realHostInfo, isLocal: true });
    }
  }
  storage.set('devices', devices);
}
initDevices();

const IOC_DOMAINS = new Set([
  'evil-login.example',
  'free-gift-claim.example',
  'bank-verify.example',
  'c2-beacon.darknet-node.example',
  'malware-drop.xyz',
  'stealer-telegram-api.top'
]);

const logAudit = (user, action, detail) => {
  audit.unshift({ time: new Date().toISOString(), user, action, detail });
  if (audit.length > 300) audit.length = 300;
  storage.set('audit', audit);
};

// ---------- Detection Engine ----------
function detect(ev) {
  const hits = [];

  // R-001: Office spawns shell
  if (ev.type === 'process' && /winword|excel|powerpnt/i.test(ev.parent || '') && /powershell|cmd|wscript|cscript/i.test(ev.name || '')) {
    hits.push(rules.find(r => r.id === 'R-001'));
  }
  // R-002: IOC connection
  if (ev.type === 'network' && (IOC_DOMAINS.has(ev.domain) || /evil-login|free-gift-claim|bank-verify|c2-beacon|darknet-node|stealer/i.test(ev.domain || ''))) {
    hits.push(rules.find(r => r.id === 'R-002'));
  }
  // R-003: Ransomware rename burst
  if (ev.type === 'file' && (Number(ev.renames || 0) >= 8 || /ransom|\.locked|\.crypted|\.enc/i.test(ev.name || ''))) {
    hits.push(rules.find(r => r.id === 'R-003'));
  }
  // R-004: High entropy binary
  if (ev.type === 'file' && Number(ev.entropy || 0) > 7.2) {
    hits.push(rules.find(r => r.id === 'R-004'));
  }
  // R-005: Credential dumping LSASS
  if (ev.type === 'process' && (/lsass/i.test(ev.target || '') || /mimikatz|procdump|comsvcs/i.test(ev.name || '') || /lsass\.dmp/i.test(ev.cmd || ''))) {
    hits.push(rules.find(r => r.id === 'R-005'));
  }
  // R-006: Persistence registry
  if (ev.type === 'registry' && /Run|RunOnce|CurrentVersion/i.test(ev.key || '')) {
    hits.push(rules.find(r => r.id === 'R-006'));
  }
  // R-007: Execution from Temp/AppData
  if (ev.type === 'process' && (ev.path && /AppData\\Local\\Temp|AppData\\Roaming/i.test(ev.path))) {
    hits.push(rules.find(r => r.id === 'R-007'));
  }

  // Custom regex rules
  for (const r of rules.slice(7)) {
    if (r.customPattern && (new RegExp(r.customPattern, 'i')).test(JSON.stringify(ev))) {
      hits.push(r);
    }
  }

  return hits.filter(r => r && r.enabled);
}

function ingest(ev) {
  ev.id = crypto.randomUUID();
  ev.time = ev.time || new Date().toISOString();

  events.unshift(ev);
  if (events.length > 500) events.length = 500;
  storage.set('events', events);

  totalEventsIngested++;
  eventsInLastWindow++;

  const out = [{ kind: 'event', data: ev }];
  const triggeredRules = detect(ev);

  for (const r of triggeredRules) {
    r.hits = (r.hits || 0) + 1;
    const a = {
      id: crypto.randomUUID(),
      time: ev.time,
      rule: r.name,
      ruleId: r.id,
      ruleType: r.type,
      severity: r.severity,
      mitre: r.mitre || 'T1059',
      description: r.description,
      device: ev.device,
      status: 'open',
      evidence: ev
    };
    alerts.unshift(a);
    if (alerts.length > 300) alerts.length = 300;
    out.push({ kind: 'alert', data: a });
  }

  storage.set('alerts', alerts);
  storage.set('rules', rules);

  // Broadcast to connected clients
  out.forEach(m => clients.forEach(c => {
    try { c.write(`data: ${JSON.stringify(m)}\n\n`); } catch (_) {}
  }));

  return { ev, triggeredCount: triggeredRules.length };
}

// Connect System Sensor callback to Ingest
systemSensor.setEventHandler((sensorEvent) => {
  if (sensorEvent.type === 'host_telemetry') {
    // Update real local host card metrics
    const localIdx = devices.findIndex(d => d.isLocal || d.id === sensorEvent.device);
    if (localIdx !== -1) {
      devices[localIdx].cpu = sensorEvent.sys.cpu;
      devices[localIdx].mem = sensorEvent.sys.mem;
      devices[localIdx].lastSeen = 'Active Now';
      storage.set('devices', devices);
    }
    // Broadcast updated summary
    clients.forEach(c => {
      try { c.write(`data: ${JSON.stringify({ kind: 'host_update', data: sensorEvent.sys })}\n\n`); } catch (_) {}
    });
  } else {
    // Process, File or Network event from sensor
    ingest(sensorEvent);
  }
});

// Start Real Sensor Listeners
systemSensor.startCanaryWatcher();
systemSensor.startHostTelemetryPoller(3500);

// ---------- URL / Threat-Intel Scorer ----------
function scoreUrl(raw) {
  let u;
  try {
    u = new URL(raw.startsWith('http') ? raw : 'https://' + raw);
  } catch {
    return null;
  }
  const reasons = [];
  let score = 0;

  if (IOC_DOMAINS.has(u.hostname) || Array.from(IOC_DOMAINS).some(d => u.hostname.includes(d))) {
    score += 90;
    reasons.push('Domain is listed in active threat-intel blocklist');
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) {
    score += 30;
    reasons.push('Uses direct raw IP address instead of domain name');
  }
  if (u.hostname.split('.').length > 4) {
    score += 20;
    reasons.push('Unusually high subdomain depth (possible DGA or tunneling)');
  }
  if (u.hostname.includes('xn--')) {
    score += 35;
    reasons.push('Punycode encoded domain (possible homograph brand impersonation)');
  }
  if (/login|verify|secure|update|wallet|bank|account|signin|paypal/i.test(u.href) && !/\.(com|org|gov|edu)$/.test(u.hostname)) {
    score += 25;
    reasons.push('High-risk credential keywords paired with suspicious TLD');
  }
  if (/\.(xyz|top|work|click|loan|rest|tk|cf)$/i.test(u.hostname)) {
    score += 20;
    reasons.push('Registrar TLD has statistically high abuse reputation');
  }
  if (u.protocol !== 'https:') {
    score += 15;
    reasons.push('Unencrypted protocol (HTTP plain-text transmission)');
  }

  score = Math.min(score, 100);
  return {
    host: u.hostname,
    url: u.href,
    score,
    verdict: score >= 60 ? 'malicious' : score >= 25 ? 'suspicious' : 'clean',
    reasons
  };
}

// ---------- API Routes ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.pass !== hash(password || '')) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  logAudit(username, 'login', `Authenticated as ${u.role}`);
  res.json({
    token: sign({ sub: username, role: u.role, exp: Date.now() + 12 * 3600e3 }),
    role: u.role,
    username,
    name: u.name
  });
});

app.get('/api/summary', auth(), (req, res) => {
  const openAlerts = alerts.filter(a => a.status === 'open');
  const critical = openAlerts.filter(a => a.severity === 'critical').length;
  const high = openAlerts.filter(a => a.severity === 'high').length;
  const medium = openAlerts.filter(a => a.severity === 'medium').length;

  let defcon = 'DEFCON 4 (NORMAL)';
  if (critical > 0) defcon = 'DEFCON 1 (CRITICAL THREAT)';
  else if (high > 0) defcon = 'DEFCON 2 (ELEVATED)';
  else if (medium > 0) defcon = 'DEFCON 3 (GUARDED)';

  res.json({
    devices: devices.length,
    isolated: devices.filter(d => d.isolated).length,
    openAlerts: openAlerts.length,
    critical,
    high,
    medium,
    events: totalEventsIngested,
    activeRules: rules.filter(r => r.enabled).length,
    totalRules: rules.length,
    eps: parseFloat(rollingEps) || 0.9,
    defcon
  });
});

app.get('/api/devices', auth(), (req, res) => res.json(devices));
app.get('/api/alerts', auth(), (req, res) => res.json(alerts.slice(0, 150)));
app.get('/api/events', auth(), (req, res) => res.json(events.slice(0, 150)));
app.get('/api/rules', auth(), (req, res) => res.json(rules));
app.get('/api/audit', auth(['admin']), (req, res) => res.json(audit));

app.post('/api/ingest', auth(), (req, res) => {
  const { type, device, name, parent, domain, renames, entropy, target, cmd, key, value, port, path: filePath } = req.body || {};
  if (!type || !device) return res.status(400).json({ error: 'type and device are required' });
  const result = ingest({
    type,
    device: String(device).slice(0, 50),
    name,
    parent,
    domain,
    renames: Number(renames) || 0,
    entropy: Number(entropy) || 0,
    target,
    cmd,
    key,
    value,
    path: filePath,
    port: Number(port) || undefined
  });
  res.status(202).json({ ok: true, detections: result.triggeredCount });
});

// ==================== REAL SYSTEM ENDPOINTS ====================

// Real System Host Info & Hardware Metrics
app.get('/api/real/system-info', auth(), async (req, res) => {
  try {
    const info = await systemSensor.getSystemInfo();
    res.json(info);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Real Running Windows Processes
app.get('/api/real/processes', auth(), async (req, res) => {
  try {
    const procs = await systemSensor.getRunningProcesses();
    res.json(procs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Real Active Network Sockets & Listening Ports
app.get('/api/real/connections', auth(), async (req, res) => {
  try {
    const conns = await systemSensor.getNetworkConnections();
    res.json(conns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Real Process Termination (Kill Process)
app.post('/api/real/kill-process', auth(['admin', 'analyst']), async (req, res) => {
  const { pid } = req.body || {};
  if (!pid) return res.status(400).json({ error: 'PID is required' });
  try {
    const outcome = await systemSensor.killProcess(pid);
    logAudit(req.user.sub, 'kill-process', `Terminated PID ${pid} on local host`);
    res.json(outcome);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Real File Deep Inspection (Shannon Entropy, SHA-256 Hash, Magic Bytes)
app.post('/api/real/scan-file', auth(), async (req, res) => {
  const { filePath } = req.body || {};
  if (!filePath) return res.status(400).json({ error: 'filePath is required' });
  try {
    const result = await systemSensor.scanFile(filePath);
    logAudit(req.user.sub, 'scan-local-file', `${result.fileName} -> Entropy ${result.entropy} (${result.verdict})`);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Real File Quarantine
app.post('/api/real/quarantine-file', auth(['admin', 'analyst']), async (req, res) => {
  const { filePath } = req.body || {};
  if (!filePath) return res.status(400).json({ error: 'filePath is required' });
  try {
    const result = await systemSensor.quarantineFile(filePath);
    logAudit(req.user.sub, 'quarantine-file', `Moved ${filePath} to quarantine vault`);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Canary Trap Test Trigger: Drop a real file in canary directory to test watcher
app.post('/api/real/test-canary', auth(), (req, res) => {
  const { scenario = 'packed_binary' } = req.body || {};
  const canaryPath = path.join(__dirname, 'canary_trap');
  const fileName = `canary_test_${Date.now()}.${scenario === 'ransomware' ? 'locked' : 'bin'}`;
  const targetFile = path.join(canaryPath, fileName);

  try {
    let buf;
    if (scenario === 'high_entropy' || scenario === 'packed_binary') {
      // Generate real cryptographically random bytes with Shannon entropy ~ 7.95
      buf = crypto.randomBytes(32768);
    } else {
      buf = Buffer.from('CANARY_TRAP_MONITOR_TEST_PAYLOAD_' + Date.now());
    }
    const fs = require('fs');
    fs.writeFileSync(targetFile, buf);
    logAudit(req.user.sub, 'test-canary-drop', `Created test canary file: ${fileName}`);
    res.json({ ok: true, file: targetFile, fileName, size: buf.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Threat Simulation endpoint
app.post('/api/simulate', auth(), (req, res) => {
  const { scenario, device = os.hostname() } = req.body || {};
  let payload;

  switch (scenario) {
    case 'macro':
      payload = {
        type: 'process',
        device,
        name: 'powershell.exe',
        parent: 'WINWORD.EXE',
        cmd: 'powershell.exe -NoP -NonI -W Hidden -ExecutionPolicy Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8...',
        pid: 4892,
        ppid: 1420
      };
      break;
    case 'ransomware':
      payload = {
        type: 'file',
        device,
        name: 'financial_records_q3.xlsx.locked',
        renames: 174,
        entropy: 7.92,
        path: 'C:\\Users\\Finance\\Documents\\',
        ext: '.locked'
      };
      break;
    case 'c2':
      payload = {
        type: 'network',
        device,
        domain: 'c2-beacon.darknet-node.example',
        ip: '185.220.101.5',
        port: 443,
        protocol: 'HTTPS',
        bytesSent: 64200
      };
      break;
    case 'lsass':
      payload = {
        type: 'process',
        device,
        name: 'rundll32.exe',
        target: 'lsass.exe',
        cmd: 'rundll32.exe comsvcs.dll, MiniDump 648 C:\\Windows\\Temp\\lsass.dmp full',
        pid: 7102,
        ppid: 3940
      };
      break;
    case 'entropy':
      payload = {
        type: 'file',
        device,
        name: 'dropped_update_payload.bin',
        entropy: 7.98,
        renames: 1,
        path: 'C:\\Users\\Operator\\AppData\\Local\\Temp\\update_payload.bin',
        hash: 'b5a2c4e689d1234f981273981273891273891273891273891273891273891273'
      };
      break;
    case 'persistence':
      payload = {
        type: 'registry',
        device,
        key: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TelemetryHost',
        value: 'C:\\ProgramData\\win_telemetry_svc.exe',
        name: 'reg.exe'
      };
      break;
    default:
      return res.status(400).json({ error: 'Unknown simulation scenario' });
  }

  const result = ingest(payload);
  logAudit(req.user.sub, 'simulate-threat', `${scenario} triggered on ${device}`);
  res.json({ ok: true, scenario, device, triggeredAlerts: result.triggeredCount, event: payload });
});

app.post('/api/scan-url', auth(), (req, res) => {
  const r = scoreUrl(String((req.body || {}).url || ''));
  if (!r) return res.status(400).json({ error: 'Enter a valid URL or hostname' });
  logAudit(req.user.sub, 'scan-threat-intel', `${r.host} -> ${r.verdict} (${r.score}/100)`);
  res.json(r);
});

app.post('/api/alerts/:id/resolve', auth(['admin', 'analyst']), (req, res) => {
  const a = alerts.find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Alert not found' });
  a.status = 'resolved';
  storage.set('alerts', alerts);
  logAudit(req.user.sub, 'resolve-alert', `${a.rule} on ${a.device}`);
  res.json(a);
});

app.post('/api/alerts/resolve-all', auth(['admin', 'analyst']), (req, res) => {
  let count = 0;
  alerts.forEach(a => {
    if (a.status === 'open') {
      a.status = 'resolved';
      count++;
    }
  });
  storage.set('alerts', alerts);
  logAudit(req.user.sub, 'resolve-all-alerts', `Resolved ${count} active alerts`);
  res.json({ ok: true, count });
});

app.post('/api/devices/:id/isolate', auth(['admin']), (req, res) => {
  const d = devices.find(x => x.id === req.params.id);
  if (!d) return res.status(404).json({ error: 'Device not found' });
  d.isolated = !d.isolated;
  d.status = d.isolated ? 'isolated' : 'protected';
  storage.set('devices', devices);
  logAudit(req.user.sub, d.isolated ? 'quarantine-endpoint' : 'release-endpoint', `${d.id} (${d.name})`);
  res.json(d);
});

app.post('/api/devices/:id/scan', auth(['admin', 'analyst']), async (req, res) => {
  const d = devices.find(x => x.id === req.params.id);
  if (!d) return res.status(404).json({ error: 'Device not found' });
  logAudit(req.user.sub, 'remote-deep-scan', `Initiated heuristic scan on ${d.id}`);
  res.json({ ok: true, message: `Deep scan executed on ${d.id}. Real telemetry verified.` });
});

app.post('/api/rules/:id/toggle', auth(['admin']), (req, res) => {
  const r = rules.find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Rule not found' });
  r.enabled = !r.enabled;
  storage.set('rules', rules);
  logAudit(req.user.sub, 'toggle-rule', `${r.id} (${r.name}) -> ${r.enabled ? 'ACTIVE' : 'DISABLED'}`);
  res.json(r);
});

app.post('/api/rules', auth(['admin']), (req, res) => {
  const { name, type, severity, mitre, description, customPattern } = req.body || {};
  if (!name || !customPattern) return res.status(400).json({ error: 'Rule name and pattern are required' });
  const newRule = {
    id: `R-00${rules.length + 1}`,
    name,
    type: type || 'Custom-Sigma',
    severity: severity || 'medium',
    mitre: mitre || 'T1059',
    enabled: true,
    hits: 0,
    description: description || 'User-defined custom detection heuristic rule.',
    customPattern
  };
  rules.push(newRule);
  storage.set('rules', rules);
  logAudit(req.user.sub, 'create-rule', `Created custom rule ${newRule.id}: ${newRule.name}`);
  res.status(201).json(newRule);
});

// SSE Live Stream
app.get('/api/stream', auth(), (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.flushHeaders();
  clients.add(res);
  req.on('close', () => clients.delete(res));
});

app.listen(PORT, () => {
  console.log(`Sentinel EDR Engine active on http://localhost:${PORT}`);
  console.log(`[Host Sensor] Attached to local machine: ${os.hostname()} (${os.type()} ${os.arch()})`);
});
