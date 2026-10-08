// Sentinel Persistence Layer - Atomic JSON Database
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data', 'sentinel_db.json');

const INITIAL_STATE = {
  devices: [],
  alerts: [],
  events: [],
  audit: [],
  rules: [
    { id: 'R-001', name: 'Office app spawns PowerShell / Command line', type: 'Sigma', severity: 'high', mitre: 'T1059.001', enabled: true, hits: 0, description: 'Detects Word or Excel launching powershell.exe or cmd.exe, common in phishing and malicious macro execution.' },
    { id: 'R-002', name: 'Connection to known C2 / Malicious domain', type: 'IOC', severity: 'critical', mitre: 'T1071.001', enabled: true, hits: 0, description: 'Outbound network communication to known Command & Control or phishing infrastructure.' },
    { id: 'R-003', name: 'Ransomware file-rename burst', type: 'Behavior', severity: 'critical', mitre: 'T1486', enabled: true, hits: 0, description: 'Abnormal rate of rapid file extensions or renames exceeding 10 operations per 5 seconds.' },
    { id: 'R-004', name: 'Suspicious high-entropy packed binary', type: 'YARA', severity: 'medium', mitre: 'T1027', enabled: true, hits: 0, description: 'File entropy above 7.2 indicates packed, encrypted or obfuscated executable payload.' },
    { id: 'R-005', name: 'Credential dumping from LSASS memory', type: 'Behavior', severity: 'critical', mitre: 'T1003.001', enabled: true, hits: 0, description: 'Process accessed lsass.exe process memory with memory dump permissions.' },
    { id: 'R-006', name: 'Suspicious persistence via Registry Run key', type: 'Sigma', severity: 'high', mitre: 'T1547.001', enabled: true, hits: 0, description: 'Modification of Run/RunOnce registry keys by unverified non-system binary.' },
    { id: 'R-007', name: 'Process execution from Temp / AppData directory', type: 'Sigma', severity: 'high', mitre: 'T1204', enabled: true, hits: 0, description: 'Executable launched directly from user Temp or AppData writable folders.' }
  ],
  quarantinedFiles: []
};

class Storage {
  constructor() {
    this.data = this.load();
  }

  load() {
    try {
      if (fs.existsSync(DB_PATH)) {
        const raw = fs.readFileSync(DB_PATH, 'utf8');
        const parsed = JSON.parse(raw);
        return {
          ...INITIAL_STATE,
          ...parsed,
          rules: parsed.rules && parsed.rules.length ? parsed.rules : INITIAL_STATE.rules
        };
      }
    } catch (err) {
      console.error('Storage load error, initializing fresh DB:', err.message);
    }
    this.saveDirect(INITIAL_STATE);
    return JSON.parse(JSON.stringify(INITIAL_STATE));
  }

  saveDirect(data) {
    try {
      const dir = path.dirname(DB_PATH);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const tempPath = DB_PATH + '.tmp';
      fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf8');
      fs.renameSync(tempPath, DB_PATH);
    } catch (err) {
      console.error('Storage save error:', err.message);
    }
  }

  save() {
    clearTimeout(this._saveTimer);
    this._saveTimer = setTimeout(() => {
      this.saveDirect(this.data);
    }, 300);
  }

  get(key) {
    return this.data[key] || [];
  }

  set(key, val) {
    this.data[key] = val;
    this.save();
  }
}

module.exports = new Storage();
