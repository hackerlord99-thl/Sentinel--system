# Sentinel // Real-Time Endpoint Detection & Response (EDR) Platform

A full-fledged defensive system detection and threat response platform running live on Windows, with a native Windows desktop application installer, real host telemetry sensor, live process tracking, Shannon entropy file inspection, canary trap monitoring, and an interactive Security Operations Center (SOC) console.

---

## 🪟 Windows Desktop Installation (1-Click Installer)

### Method 1: Double-Click Installer (Recommended)
1. In File Explorer, navigate to this folder:
   `C:\Users\SHIVA\Downloads\Sential sytstem`
2. Double-click **`Install-Sentinel.bat`** (or right-click and select *Run as administrator*).
3. The installer will:
   - Compile the native Windows application: **`Sentinel.exe`**
   - Create a **Desktop Shortcut** with custom shield icon (`Sentinel EDR Console.lnk`)
   - Create a **Start Menu Shortcut** (`Start Menu\Programs\Sentinel EDR Console.lnk`)
   - Configure **Windows Auto-Start** (launches silently on Windows boot to protect your PC 24/7)
   - Automatically launch the desktop application window and attach the **System Tray Guard**!

### Method 2: Manual Start
You can launch the desktop app anytime by double-clicking **`Sentinel.exe`**, or starting from PowerShell:
```powershell
.\Sentinel.exe
```

---

## 🖥️ System Tray Guard & Desktop Controls

When **`Sentinel.exe`** is running, a shield icon sits in your **Windows Taskbar System Tray**:
- **Double-Click Icon**: Opens the full Sentinel EDR Console window.
- **Right-Click Context Menu**:
  - 🛡️ **Open Sentinel Console** — Brings up the native desktop application window.
  - 📁 **Open Quarantine Vault** — Opens the `quarantine_vault\` folder in Windows File Explorer.
  - 🪤 **Open Canary Trap Folder** — Opens the `canary_trap\` folder in File Explorer.
  - 🔄 **Restart Defense Engine** — Restarts the background telemetry collector and engine.
  - ❌ **Exit Sentinel** — Closes the desktop window, shuts down the tray icon, and cleans up background processes.

---

## 🔑 Authentication
| Role | Username | Password | Capabilities |
| :--- | :--- | :--- | :--- |
| **SecOps Admin** | `admin` | `admin123` | Full administrative control: Kill real processes, quarantine files, network isolation, rule deployment, audit trail |
| **SOC Analyst** | `analyst` | `analyst123` | Incident triage, file deep inspection, socket analysis, alert resolution |

*(Quick-fill buttons are provided on the login screen for convenience)*

---

## 🛡️ Real Host Security Capabilities

### 1. 🖥️ Real Host Sensor (`systemSensor.js`)
- **Live Hardware Telemetry**: Calculates real CPU utilization (via delta tick counters), physical RAM usage (Total, Free, Used MB), system uptime, and network interfaces.
- **Persistent Data Store**: All events, detections, host entries, and audit logs are safely persisted in `data/sentinel_db.json` with atomic writes.

### 2. ⚡ Live Process Explorer (Task Manager & EDR)
- Queries active running processes directly from the host.
- Displays PID, process name, real memory working set (MB), and executable path.
- **Heuristic Path Flags**: Flags binaries executing from user-writable temporary directories (`AppData\Local\Temp` or `AppData\Roaming`).
- **Real Process Termination**: Direct `[Kill Process]` button executes an authenticated `taskkill /F /PID <pid>` on the host.

### 3. 🌐 Active Sockets & Port Monitor
- Queries live TCP network connections and listening ports (`Get-NetTCPConnection`).
- Displays local listening ports, remote connections, state (`LISTENING`, `ESTABLISHED`), and owning PIDs.

### 4. 🔍 Deep File Inspector & Shannon Entropy Engine
- Inspect any file on your computer by entering its path (e.g. `C:\Windows\System32\cmd.exe` or any downloaded binary).
- Calculates:
  - **Shannon Entropy**: Measures randomness ($0.0$ to $8.0$ bits/byte). Entropy $> 7.2$ flags packed, encrypted, or obfuscated binaries.
  - **Cryptographic Hashes**: Real SHA-256 and MD5 hashes computed directly from disk.
  - **Magic Bytes**: Identifies true file formats (PE Executable, PKZip, PDF, etc.) to catch extension spoofing.
- **Physical Quarantine Vault**: Move suspicious files into `./quarantine_vault/` and generates a timestamped forensic notice.

### 5. 🪤 24/7 Canary Trap Directory Sensor
- Sentinel monitors the local directory `./canary_trap` in real time using background filesystem watchers.
- **1-Click Canary Test Drops**:
  - `[Drop High-Entropy Binary]`: Generates a real 32 KB random binary (entropy $\approx 7.95$). The background sensor detects it, assesses the high entropy, and automatically raises a high-priority YARA alert in the console!
  - `[Drop Ransomware File]`: Writes a `.locked` file to test the ransomware burst heuristic.

---

## 🗑️ Uninstallation

To remove Sentinel from Windows:
1. Double-click **`Uninstall-Sentinel.bat`**.
2. This stops all Sentinel processes, removes Desktop and Start Menu shortcuts, and clears the Windows Auto-Start registry entry.

---

## 📂 Project Structure

```
SENTINEL EDR PLATFORM
├── Sentinel.exe           # Native Windows desktop application & System Tray executable
├── SentinelLauncher.cs    # C# source code for desktop launcher & tray manager
├── sentinel.ico           # Application icon (Shield)
├── Install-Sentinel.bat   # 1-Click Windows batch installer
├── Install-Sentinel.ps1   # PowerShell automated installer script
├── Uninstall-Sentinel.bat # Windows uninstaller script
├── server.js              # Express API & Server-Sent Events (SSE) telemetry broker
├── systemSensor.js        # Real Windows host telemetry collector (processes, sockets, entropy, watcher)
├── storage.js             # Atomic JSON persistence layer
├── data/
│   └── sentinel_db.json   # Persistent database (alerts, events, audit logs, devices, rules)
├── canary_trap/           # Monitored trap directory for real-time drop detection
├── quarantine_vault/      # Secure quarantine vault for isolated suspicious binaries
├── index.html             # High-tech SOC console layout with Real EDR panels
├── style.css              # Cyber dark theme stylesheet
└── app.js                 # Frontend engine with live SSE stream and Real Process/Socket controls
```
