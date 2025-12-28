# Socute (Frida Inject GUI)

**Socute** is a lightweight Android GUI wrapper for `frida-inject`. It allows you to inject Frida scripts into Android applications without typing complex commands in Termux or using a PC.

Designed for efficiency, Socute handles binary management, script merging, and proxy configuration automatically.

## 🚀 Features

* **One-Page Interface:** Simple, hacker-friendly UI.
* **Auto Binary Management:** Automatically detects CPU architecture (arm64/arm) and downloads the correct `frida-inject` binary.
* **Script Manager:** Scans for `.js` files in `/sdcard/socute-apk/scripts`. Supports multi-selection.
* **Auto-Merge:** Combines multiple selected scripts + proxy config into a single payload before injection.
* **Proxy Injector:** Easily force HTTP/HTTPS proxy (e.g., for Burp Suite or HTTP Toolkit) without system-level VPN.
* **Live Terminal:** Views standard output and error logs directly within the app.

---

## 📥 Installation & Usage

### Prerequisites
* **Rooted Android Device** (Required for `frida-inject`).
* Android 8.0 or higher recommended.

### How to Use

1.  **Download & Install**
    * Go to the [Releases Page](../../releases) and download `socute.apk`.
    * Install the APK on your device.
    * Grant **Root Access** and **Storage Permissions** when prompted.

2.  **Folder Structure**
    Upon first launch, the app will create the following directory:
    ```text
    /sdcard/socute-apk/
    ├── frida-inject         # The binary (auto-downloaded)
    ├── payload.js           # Auto-generated (do not edit)
    └── scripts/             # PUT YOUR .JS FILES HERE
    ```

3.  **Injecting Scripts**
    * **Target:** Tap the card to select a target application.
    * **Binary:** If "Binary Missing", tap the download button.
    * **Scripts:** Place your `.js` files in the `/sdcard/socute-apk/scripts/` folder. Click "Refresh" in the app to see them. Check the boxes to select.
    * **Proxy (Optional):** Enable Proxy and enter your PC's IP and Port (e.g., `192.168.1.5:8080`).
    * **Launch:** Tap **LAUNCH & INJECT**. The app will spawn the target and inject the payload.

---

## 🛠 Building Manually

If you prefer to build from source or don't trust the pre-built APK.

### Requirements
* **Flutter SDK** (3.0 or higher)
* **Android SDK Command-line Tools**
* **Java 17** (OpenJDK/Zulu)

### Build Steps

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/socute.git](https://github.com/YOUR_USERNAME/socute.git)
    cd socute
    ```

2.  **Install Dependencies**
    ```bash
    flutter pub get
    ```

3.  **Build APK**
    ```bash
    flutter build apk --release --no-tree-shake-icons
    ```

4.  **Locate APK**
    The output file will be at: `build/app/outputs/flutter-apk/app-release.apk`

---

## ⚠️ Disclaimer

**For Educational and Research Purposes Only.**

This tool is intended for security analysis, debugging, and research of applications you own or have permission to test. The developer assumes no responsibility for unauthorized use, bricked devices, or bans resulting from the use of this tool. Use at your own risk.

---

## 🤝 Credits

* Powered by [Frida](https://frida.re).
* Built with [Flutter](https://flutter.dev).
