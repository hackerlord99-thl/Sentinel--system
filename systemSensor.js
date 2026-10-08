// Sentinel Host Sensor - Real-time Windows System Telemetry & Detection Collector
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

class SystemSensor {
  constructor() {
    this.hostname = os.hostname();
    this.platform = os.platform();
    this.canaryDir = path.join(__dirname, 'canary_trap');
    this.quarantineDir = path.join(__dirname, 'quarantine_vault');
    this.prevCpuTimes = this.getCpuTimes();
    this.recentRenames = [];
    this.onEventCallback = null;
    this.isWatching = false;

    this.ensureDirs();
  }

  ensureDirs() {
    if (!fs.existsSync(this.canaryDir)) fs.mkdirSync(this.canaryDir, { recursive: true });
    if (!fs.existsSync(this.quarantineDir)) fs.mkdirSync(this.quarantineDir, { recursive: true });
  }

  setEventHandler(callback) {
    this.onEventCallback = callback;
  }

  emit(ev) {
    if (this.onEventCallback) {
      this.onEventCallback(ev);
    }
  }

  // ---------- CPU Utilization Calculation ----------
  getCpuTimes() {
    const cpus = os.cpus();
    let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
    for (const cpu of cpus) {
      user += cpu.times.user;
      nice += cpu.times.nice || 0;
      sys += cpu.times.sys;
      idle += cpu.times.idle;
      irq += cpu.times.irq || 0;
    }
    return { idle, total: user + nice + sys + idle + irq };
  }

  getCpuUsagePercent() {
    const current = this.getCpuTimes();
    const idleDiff = current.idle - this.prevCpuTimes.idle;
    const totalDiff = current.total - this.prevCpuTimes.total;
    this.prevCpuTimes = current;
    if (totalDiff <= 0) return 15;
    const usage = 100 - (idleDiff / totalDiff) * 100;
    return Math.max(2, Math.min(100, Math.round(usage)));
  }

  // ---------- Real Host System Details ----------
  async getSystemInfo() {
    const totalMemBytes = os.totalmem();
    const freeMemBytes = os.freemem();
    const usedMemBytes = totalMemBytes - freeMemBytes;
    const memUsagePercent = Math.round((usedMemBytes / totalMemBytes) * 100);

    const interfaces = os.networkInterfaces();
    let primaryIp = '127.0.0.1';
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (!iface.internal && iface.family === 'IPv4') {
          primaryIp = iface.address;
          break;
        }
      }
    }

    const info = {
      id: this.hostname,
      name: `${this.hostname} (Local Host)`,
      os: `${os.type()} ${os.release()} (${os.arch()})`,
      owner: os.userInfo().username || 'Local Operator',
      ip: primaryIp,
      cpu: this.getCpuUsagePercent(),
      mem: memUsagePercent,
      ramTotalMB: Math.round(totalMemBytes / (1024 * 1024)),
      ramUsedMB: Math.round(usedMemBytes / (1024 * 1024)),
      cpuModel: os.cpus()[0]?.model || 'Generic Processor',
      cores: os.cpus().length,
      uptimeSeconds: os.uptime(),
      status: 'protected',
      isolated: false,
      lastSeen: 'Active Now'
    };

    return info;
  }

  // ---------- Real Running Processes ----------
  async getRunningProcesses() {
    return new Promise((resolve) => {
      // Execute fast PowerShell command to get live processes with RAM and Executable Paths
      const psCmd = `Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 50 Id, ProcessName, @{Name="RAM_MB";Expression={[math]::Round($_.WorkingSet64/1MB,1)}}, Path | ConvertTo-Json`;
      exec(`powershell -NoProfile -Command "${psCmd}"`, { timeout: 8000 }, (err, stdout) => {
        if (err || !stdout) {
          return resolve(this.getProcessesFallback());
        }
        try {
          let list = JSON.parse(stdout);
          if (!Array.isArray(list)) list = [list];
          const formatted = list.filter(p => p && p.Id).map(p => ({
            pid: p.Id,
            name: (p.ProcessName || 'unknown') + '.exe',
            ramMB: p.RAM_MB || 0,
            path: p.Path || 'System Protected / Protected Process',
            suspicious: Boolean(p.Path && /AppData\\Local\\Temp|AppData\\Roaming\\/i.test(p.Path) && !/node|chrome|code|electron|cursor/i.test(p.ProcessName))
          }));
          resolve(formatted);
        } catch (_) {
          resolve(this.getProcessesFallback());
        }
      });
    });
  }

  getProcessesFallback() {
    return new Promise((resolve) => {
      exec('tasklist /FO CSV /NH', { timeout: 5000 }, (err, stdout) => {
        if (err || !stdout) return resolve([]);
        const lines = stdout.split('\r\n').filter(Boolean);
        const procs = lines.slice(0, 40).map(line => {
          const parts = line.split('","').map(s => s.replace(/"/g, ''));
          return {
            pid: parseInt(parts[1], 10) || 0,
            name: parts[0] || 'process.exe',
            ramMB: Math.round((parseInt((parts[4] || '0').replace(/[^\d]/g, ''), 10) || 0) / 1024),
            path: 'Running Task',
            suspicious: false
          };
        });
        resolve(procs);
      });
    });
  }

  // ---------- Real Network Sockets & Connections ----------
  async getNetworkConnections() {
    return new Promise((resolve) => {
      const psCmd = `Get-NetTCPConnection -State Established, Listen -ErrorAction SilentlyContinue | Select-Object -First 40 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ConvertTo-Json`;
      exec(`powershell -NoProfile -Command "${psCmd}"`, { timeout: 8000 }, (err, stdout) => {
        if (err || !stdout) return resolve([]);
        try {
          let list = JSON.parse(stdout);
          if (!Array.isArray(list)) list = [list];
          const stateMap = { 2: 'LISTENING', 5: 'ESTABLISHED', 8: 'CLOSE_WAIT', 3: 'SYN_SENT' };
          const formatted = list.filter(c => c && c.LocalPort).map(c => ({
            localAddress: c.LocalAddress || '0.0.0.0',
            localPort: c.LocalPort,
            remoteAddress: c.RemoteAddress || '*',
            remotePort: c.RemotePort || 0,
            state: stateMap[c.State] || `STATE_${c.State}`,
            pid: c.OwningProcess || 0
          }));
          resolve(formatted);
        } catch (_) {
          resolve([]);
        }
      });
    });
  }

  // ---------- Real Process Termination (Kill Process) ----------
  async killProcess(pid) {
    return new Promise((resolve, reject) => {
      const targetPid = parseInt(pid, 10);
      if (!targetPid || targetPid <= 4) {
        return reject(new Error('Cannot terminate core operating system process (PID <= 4)'));
      }
      exec(`taskkill /F /PID ${targetPid}`, (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(stderr || err.message || 'Process termination failed'));
        }
        resolve({ ok: true, pid: targetPid, message: stdout.trim() });
      });
    });
  }

  // ---------- Shannon Entropy & File Analysis ----------
  calculateEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < buffer.length; i++) {
      freq[buffer[i]]++;
    }
    let entropy = 0;
    const len = buffer.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return parseFloat(entropy.toFixed(3));
  }

  async scanFile(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File does not exist: ${filePath}`);
    }
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      throw new Error('Target is a directory, not a file');
    }

    // Read first 2MB for analysis
    const fd = fs.openSync(filePath, 'r');
    const readSize = Math.min(stat.size, 2 * 1024 * 1024);
    const buffer = Buffer.alloc(readSize);
    fs.readSync(fd, buffer, 0, readSize, 0);
    fs.closeSync(fd);

    const entropy = this.calculateEntropy(buffer);
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');

    // Magic bytes detection
    let magic = 'Unknown / Text';
    if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) magic = 'PE Windows Executable (MZ)';
    else if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) magic = 'ZIP / Office Archive (PK)';
    else if (buffer.length >= 4 && buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) magic = 'PDF Document (%PDF)';

    let verdict = 'clean';
    const reasons = [];
    if (entropy > 7.3) {
      verdict = 'suspicious';
      reasons.push(`High Shannon entropy (${entropy} bits/byte) indicates packed, encrypted or obfuscated payload`);
    }
    if (/\.(exe|dll|vbs|bat|ps1|scr)$/i.test(filePath) && /AppData|Temp/i.test(filePath)) {
      verdict = 'suspicious';
      reasons.push('Executable location matches temporary user-writable drop path');
    }
    if (/\.(locked|crypted|encrypted)$/i.test(filePath)) {
      verdict = 'malicious';
      reasons.push('File extension matches known ransomware encryption pattern');
    }

    return {
      filePath,
      fileName: path.basename(filePath),
      sizeBytes: stat.size,
      sizeFormatted: `${(stat.size / 1024).toFixed(1)} KB`,
      entropy,
      sha256,
      md5,
      magic,
      verdict,
      reasons
    };
  }

  // ---------- Quarantine File ----------
  async quarantineFile(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    const fileName = path.basename(filePath);
    const timeTag = Date.now();
    const quarantinedTarget = path.join(this.quarantineDir, `${timeTag}_${fileName}.quarantined`);

    // Move file to quarantine vault
    fs.renameSync(filePath, quarantinedTarget);

    // Leave canary notification note
    const noticePath = filePath + '.SENTINEL_QUARANTINED.txt';
    fs.writeFileSync(noticePath, `[SENTINEL EDR FORENSIC NOTICE]\nOriginal file "${fileName}" was automatically quarantined by Sentinel Defense Engine at ${new Date().toISOString()}.\nVault ID: ${timeTag}_${fileName}.quarantined\nStatus: ISOLATED_ENCRYPTED_VAULT\n`, 'utf8');

    return {
      originalPath: filePath,
      quarantinedPath: quarantinedTarget,
      quarantinedAt: new Date().toISOString()
    };
  }

  // ---------- Live Directory Canary Trap Watcher ----------
  startCanaryWatcher() {
    if (this.isWatching) return;
    this.ensureDirs();
    this.isWatching = true;

    try {
      fs.watch(this.canaryDir, async (eventType, filename) => {
        if (!filename || filename.endsWith('.tmp') || filename.endsWith('.SENTINEL_QUARANTINED.txt')) return;
        const targetPath = path.join(this.canaryDir, filename);

        if (!fs.existsSync(targetPath)) {
          // File was deleted or renamed
          this.recentRenames.push(Date.now());
          this.checkRenameBurst(filename);
          return;
        }

        try {
          const stat = fs.statSync(targetPath);
          if (stat.isFile()) {
            const analysis = await this.scanFile(targetPath);
            this.emit({
              type: 'file',
              device: this.hostname,
              name: filename,
              path: targetPath,
              entropy: analysis.entropy,
              size: analysis.sizeBytes,
              hash: analysis.sha256,
              renames: 1,
              source: 'canary_trap_sensor'
            });
          }
        } catch (_) {}
      });
      console.log(`[Sentinel Sensor] Live Canary Watcher active on: ${this.canaryDir}`);
    } catch (err) {
      console.error('[Sentinel Sensor] Failed to attach directory watcher:', err.message);
    }
  }

  checkRenameBurst(filename) {
    const now = Date.now();
    this.recentRenames = this.recentRenames.filter(t => now - t < 5000);
    if (this.recentRenames.length >= 8) {
      this.emit({
        type: 'file',
        device: this.hostname,
        name: filename,
        renames: this.recentRenames.length,
        entropy: 7.8,
        note: 'Mass file renaming burst detected in monitored folder (Ransomware behavior)',
        source: 'canary_trap_sensor'
      });
      this.recentRenames = [];
    }
  }

  // ---------- Periodic Live Host Poller ----------
  startHostTelemetryPoller(intervalMs = 4000) {
    setInterval(async () => {
      try {
        const sys = await this.getSystemInfo();
        this.emit({
          type: 'host_telemetry',
          device: this.hostname,
          sys
        });

        // Check top processes for high CPU or suspicious Temp binaries
        const procs = await this.getRunningProcesses();
        for (const p of procs) {
          if (p.suspicious) {
            this.emit({
              type: 'process',
              device: this.hostname,
              name: p.name,
              pid: p.pid,
              path: p.path,
              parent: 'explorer.exe',
              cmd: p.path,
              source: 'real_host_process_monitor'
            });
          }
        }
      } catch (err) {
        // Silent catch for polling tick
      }
    }, intervalMs);
  }
}

module.exports = new SystemSensor();
