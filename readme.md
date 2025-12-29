# SoCute APK (Frida Injector GUI)

A minimalist, Flutter-based GUI for Frida Injector on Android. 
Designed to be **Permissionless** and compatible with modern Android versions (10 - 14+).

## 🚀 Features
* **No Complex Permissions:** Uses Android's native scoped storage.
* **Auto-Download:** Fetches the correct `frida-inject` binary for your device architecture.
* **Script Manager:** Select multiple `.js` scripts to inject simultaneously.
* **Proxy Support:** Built-in option to inject HTTP proxy configurations.
* **Root Required:** Needs Root access (`su`) only for the injection process, not for file management.

## 📂 Folder Locations

Because this app follows Android 14 standards, files are stored in the app's private sandbox (which is accessible to you):

* **Script Folder:** `/sdcard/Android/data/com.socute.socute/files/scripts/`  
    *(Put your .js files here)*

* **Frida Binary:** `/sdcard/Android/data/com.socute.socute/files/frida-inject`

## 🛠️ How to Build
This project is designed to be built via **GitHub Actions** automatically.
1.  Fork this repo.
2.  Add a `v*` tag (e.g., `v1.0.0`) to trigger the build.
3.  Download the APK from the **Releases** page.

## ⚠️ Requirements
* **Rooted Android Device** (Magisk/KernelSU).
* **Android 10+** (Tested on Android 14).