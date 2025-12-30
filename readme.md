# SoCute (Advanced Frida Injector)

**SoCute** is a powerful, native Android GUI wrapper for `frida-inject`. It allows you to create, manage, and inject Frida scripts into Android applications directly from your device, without needing a PC or typing complex commands in Termux.

**v2.3 Updated:** Now fully compatible with Android 14, supports Script Editing, Drag-and-Drop merging, and Anti-Crash mechanisms.

## 🚀 Key Features

### 🛠️ Smart Architecture & Binary Manager
* **Auto-Detect & Manual Override:** Automatically detects your CPU (arm64/arm). Allows manual switching to `arm` (32-bit) for targeting older apps on modern devices to prevent crashes.
* **Version Control:** Download any specific version of `frida-inject` (default: 17.5.2).

### 📝 Script Manager & Editor (CRUD)
* **Built-in Editor:** Create and edit `.js` scripts directly within the app.
* **Syntax Support:** Monospace font editor with Copy/Paste support.
* **Import/Export:** Import existing scripts from storage or delete unused ones.
* **Native Storage:** No sensitive storage permissions required (Uses Android Scoped Storage).

### ⚡ Payload Composer
* **Drag-and-Drop:** Reorder your scripts easily. Top scripts execute first.
* **Multi-Select:** Checkbox system to choose which scripts to inject without deleting them.
* **Smart Merger:** Automatically combines Proxy Config + Selected Scripts into a single payload.

### 🛡️ Stability & Network
* **Anti-Crash Mode (SELinux):** Toggle to temporarily disable SELinux (`setenforce 0`) to prevent kernel panic/reboots on strict ROMs (Android 13/14).
* **Proxy Injector:** Force HTTP/HTTPS proxy (e.g., for Burp Suite) via Frida script injection.

### 📟 Live Terminal
* **Real-time Logs:** View `console.log` output from your scripts.
* **Log Tools:** One-tap **Copy to Clipboard** and **Clear Logs** for easy debugging.

---

## 📥 Installation & Usage

### Prerequisites
* **Rooted Android Device** (Strictly Required).
* Android 8.0 to Android 14+.

### Quick Start Guide

1.  **Download & Install**
    * Go to the [Releases Page](../../releases) and download the latest `socute-v2.3.apk`.
    * Install and grant **Root Access (Magisk/KernelSU)** when prompted.

2.  **Setup Binary**
    * Open SoCute. Click the **Network Icon** (Top Right).
    * Tap **Download**.
    * *Tip:* If your target app is 32-bit (older app), select `arm` architecture manually.

3.  **Manage Scripts**
    * Click the **Folder Icon** (Top Right) to open **Script Manager**.
    * Tap **(+)** to create a new script or Paste your code.
    * Save it (e.g., `bypass-ssl.js`).

4.  **Launch & Inject**
    * Back to Home (Launcher).
    * **Select Target:** Tap the card to pick an app.
    * **Compose Payload:** Check the scripts you want to use. Drag to reorder them.
    * **Config:**
        * Enable **"Disable SELinux"** if your phone reboots during launch.
        * Enable **"Inject Proxy"** if you are using BurpSuite.
    * Tap **LAUNCH**.

---

## 🔧 Troubleshooting

| Problem | Solution |
| :--- | :--- |
| **Device Reboots / Kernel Panic** | Enable **"Disable SELinux (Anti-Crash)"** in Launch Config. |
| **App Crash (Memory Error)** | Your target app might be 32-bit. Go to Downloader -> Select **arm** -> Download -> Try again. |
| **Injection Failed / Timeout** | Make sure Root access is granted. Check logs for details. |
| **Logs not showing** | Ensure your script uses `console.log("message")`. |

---

## 🛠 Building from Source

### Requirements
* **Flutter SDK** (3.19.0 or higher)
* **Java 17** (Zulu/OpenJDK)

### Build Steps

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/milio48/socute.apk.git](https://github.com/milio48/socute.apk.git)
    cd socute.apk
    ```

2.  **Install Dependencies**
    ```bash
    flutter pub get
    ```

3.  **Build APK**
    ```bash
    flutter build apk --release --no-tree-shake-icons
    ```

4.  **Output**
    The APK will be located at: `build/app/outputs/flutter-apk/app-release.apk`

---

## ⚠️ Disclaimer

**For Educational and Research Purposes Only.**

This tool is intended for security analysis, debugging, and research of applications you own or have permission to test. The developer assumes no responsibility for unauthorized use, bricked devices, or bans resulting from the use of this tool. Use at your own risk.

---

## 🤝 Credits

* **Frida:** [frida.re](https://frida.re)
* **Framework:** [Flutter](https://flutter.dev)