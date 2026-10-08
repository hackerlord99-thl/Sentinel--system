using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Threading;
using System.Windows.Forms;

namespace SentinelEDR {
    static class Program {
        private static Mutex appMutex;
        private static NotifyIcon trayIcon;
        private static Process serverProcess;
        private static string appDir;

        [STAThread]
        static void Main() {
            bool isNewInstance;
            appMutex = new Mutex(true, "Global\\SentinelEDR_SingleInstance_Mutex", out isNewInstance);
            if (!isNewInstance) {
                OpenConsoleWindow();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            appDir = AppDomain.CurrentDomain.BaseDirectory;
            Directory.SetCurrentDirectory(appDir);

            // 1. Ensure backend engine is running
            EnsureEngineRunning();

            // 2. Setup System Tray Icon
            SetupTray();

            // 3. Open Native Desktop Application Window
            OpenConsoleWindow();

            // 4. Run Message Loop for System Tray
            Application.Run();
        }

        private static bool IsPortOpen(int port) {
            try {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://localhost:" + port + "/api/summary");
                req.Timeout = 1200;
                req.Method = "GET";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse()) {
                    return true;
                }
            } catch (WebException ex) {
                // 401 Unauthorized also means the server is actively running!
                if (ex.Response is HttpWebResponse) return true;
                return false;
            } catch {
                return false;
            }
        }

        private static void EnsureEngineRunning() {
            if (IsPortOpen(3000)) {
                return; // Server already running!
            }

            try {
                string nodePath = "node";
                string serverScript = Path.Combine(appDir, "server.js");

                ProcessStartInfo psi = new ProcessStartInfo {
                    FileName = nodePath,
                    Arguments = "\"" + serverScript + "\"",
                    WorkingDirectory = appDir,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    UseShellExecute = false
                };

                serverProcess = Process.Start(psi);

                // Wait up to 6 seconds for server to respond
                for (int i = 0; i < 20; i++) {
                    Thread.Sleep(300);
                    if (IsPortOpen(3000)) break;
                }
            } catch (Exception ex) {
                MessageBox.Show("Failed to launch Sentinel Defense Engine: " + ex.Message, "Sentinel EDR Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static void OpenConsoleWindow() {
            try {
                string edgePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
                if (!File.Exists(edgePath)) {
                    edgePath = @"C:\Program Files\Microsoft\Edge\Application\msedge.exe";
                }

                string url = "http://localhost:3000";

                if (File.Exists(edgePath)) {
                    Process.Start(new ProcessStartInfo {
                        FileName = edgePath,
                        Arguments = "--app=\"" + url + "\" --window-size=1440,900",
                        UseShellExecute = true
                    });
                } else {
                    // Fallback to default browser
                    Process.Start(new ProcessStartInfo {
                        FileName = url,
                        UseShellExecute = true
                    });
                }
            } catch (Exception ex) {
                MessageBox.Show("Could not open desktop window: " + ex.Message, "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void SetupTray() {
            trayIcon = new NotifyIcon();
            trayIcon.Text = "Sentinel EDR // Real-time Host Defense";

            string iconPath = Path.Combine(appDir, "sentinel.ico");
            if (File.Exists(iconPath)) {
                trayIcon.Icon = new Icon(iconPath);
            } else {
                trayIcon.Icon = SystemIcons.Shield;
            }

            ContextMenu menu = new ContextMenu();
            menu.MenuItems.Add(new MenuItem("🛡️  Open Sentinel Console", (s, e) => OpenConsoleWindow()));
            menu.MenuItems.Add("-");
            menu.MenuItems.Add(new MenuItem("📁  Open Quarantine Vault", (s, e) => OpenFolder("quarantine_vault")));
            menu.MenuItems.Add(new MenuItem("🪤  Open Canary Trap Folder", (s, e) => OpenFolder("canary_trap")));
            menu.MenuItems.Add("-");
            menu.MenuItems.Add(new MenuItem("🔄  Restart Defense Engine", (s, e) => RestartEngine()));
            menu.MenuItems.Add(new MenuItem("❌  Exit Sentinel", (s, e) => ExitApplication()));

            trayIcon.ContextMenu = menu;
            trayIcon.Visible = true;
            trayIcon.DoubleClick += (s, e) => OpenConsoleWindow();

            // Show startup notification balloon
            trayIcon.ShowBalloonTip(3000, "Sentinel EDR Active", "Host defense sensor attached to " + Environment.MachineName + ". Double-click to open console.", ToolTipIcon.Info);
        }

        private static void OpenFolder(string relativeFolder) {
            string folderPath = Path.Combine(appDir, relativeFolder);
            if (!Directory.Exists(folderPath)) Directory.CreateDirectory(folderPath);
            Process.Start("explorer.exe", folderPath);
        }

        private static void RestartEngine() {
            try {
                if (serverProcess != null && !serverProcess.HasExited) {
                    serverProcess.Kill();
                }
            } catch {}
            EnsureEngineRunning();
            trayIcon.ShowBalloonTip(2000, "Sentinel Engine", "Defense engine restarted successfully.", ToolTipIcon.Info);
        }

        private static void ExitApplication() {
            try {
                trayIcon.Visible = false;
                trayIcon.Dispose();
                if (serverProcess != null && !serverProcess.HasExited) {
                    serverProcess.Kill();
                }
            } catch {}
            if (appMutex != null) {
                appMutex.ReleaseMutex();
                appMutex.Dispose();
            }
            Application.Exit();
            Environment.Exit(0);
        }
    }
}
