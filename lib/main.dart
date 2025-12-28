import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:device_apps/device_apps.dart';

void main() {
  runApp(const MaterialApp(home: SoCuteApp(), debugShowCheckedModeBanner: false));
}

class SoCuteApp extends StatefulWidget {
  const SoCuteApp({super.key});
  @override
  State<SoCuteApp> createState() => _SoCuteAppState();
}

class _SoCuteAppState extends State<SoCuteApp> {
  // --- STATE VARIABLES ---
  String _logs = "Ready. Waiting for command...\n";
  String _targetPackage = "";
  String _targetName = "Select Target App";
  
  bool _useProxy = false;
  // Default values for Proxy
  final TextEditingController _ipCtrl = TextEditingController(text: "192.168.1.10");
  final TextEditingController _portCtrl = TextEditingController(text: "8080");
  final TextEditingController _urlCtrl = TextEditingController(); // Auto-filled later

  List<File> _scriptFiles = [];
  Map<String, bool> _selectedScripts = {}; // Tracks which script is checked

  // The external folder where user puts scripts and binary
  final String _baseFolder = "/sdcard/socute-apk";
  
  @override
  void initState() {
    super.initState();
    _initApp();
  }

  // --- INITIALIZATION ---
  Future<void> _initApp() async {
    // 1. Request Storage Permissions
    await [Permission.storage, Permission.manageExternalStorage].request();
    
    // 2. Detect CPU Arch to suggest correct binary URL
    await _detectArchAndSetUrl();
    
    // 3. Scan for existing scripts in /sdcard/socute-apk/scripts
    await _refreshFiles();
  }

  Future<void> _detectArchAndSetUrl() async {
    var androidInfo = await DeviceInfoPlugin().androidInfo;
    var abi = androidInfo.supportedAbis[0];
    
    String arch = 'arm64'; // Default for modern phones
    if (abi.contains('armeabi')) arch = 'arm';
    else if (abi.contains('x86_64')) arch = 'x86_64';
    else if (abi.contains('x86')) arch = 'x86';
    
    // Hardcoded recommended version
    String ver = "16.1.4"; 
    setState(() {
      _urlCtrl.text = "https://github.com/frida/frida/releases/download/$ver/frida-inject-$ver-android-$arch.xz";
    });
  }

  // --- FILE SYSTEM LOGIC ---
  Future<void> _refreshFiles() async {
    final dir = Directory("$_baseFolder/scripts");
    
    // Create folder if not exists
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      _log("Created folder: $_baseFolder/scripts");
    }

    // List .js files
    List<FileSystemEntity> files = dir.listSync();
    setState(() {
      _scriptFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
      
      // Initialize checkboxes for new files
      for (var f in _scriptFiles) {
        if (!_selectedScripts.containsKey(f.path)) {
          _selectedScripts[f.path] = false;
        }
      }
    });
  }

  // --- CORE LOGIC: DOWNLOAD & INSTALL BINARY ---
  Future<void> _downloadBinary() async {
    try {
      _log("[*] Downloading binary...");
      if (!mounted) return;
      var dir = await getApplicationSupportDirectory();
      String tempPath = "${dir.path}/temp.xz";
      
      // Download .xz file
      await Dio().download(_urlCtrl.text, tempPath);
      _log("[*] Download complete. Extracting...");

      // Extract .xz content
      List<int> xzBytes = File(tempPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      
      // Save raw binary to /sdcard/socute-apk/frida-inject
      File("$_baseFolder/frida-inject")
        ..createSync(recursive: true)
        ..writeAsBytesSync(tarBytes);
      
      // Cleanup temp file
      File(tempPath).deleteSync();
      _log("[*] Binary saved to $_baseFolder/frida-inject");
      if (!mounted) return;
      
      // Force UI refresh
      setState(() {}); 
    } catch (e) {
      _log("[!] Error downloading: $e");
    }
  }

  // --- CORE LOGIC: LAUNCH & INJECT ---
  Future<void> _launchAndInject() async {
    // Validation
    if (_targetPackage.isEmpty) {
      _log("[!] Please select target app first!");
      return;
    }

    File binaryExternal = File("$_baseFolder/frida-inject");
    if (!binaryExternal.existsSync()) {
      _log("[!] Binary not found. Please download first.");
      return;
    }

    try {
      _log("--- STARTING INJECTION ---");
      
      // 1. COPY BINARY TO INTERNAL STORAGE (Bypass NoExec limitation)
      _log("[1] Copying binary to internal system...");
      final internalDir = await getApplicationSupportDirectory();
      final internalBinary = File("${internalDir.path}/frida-bin");
      
      await internalBinary.writeAsBytes(await binaryExternal.readAsBytes());
      
      // Grant Execution Permission (chmod +x)
      await Process.run('chmod', ['755', internalBinary.path]);

      // 2. GENERATE PAYLOAD (MERGE SCRIPTS)
      _log("[2] Merging scripts...");
      final payloadFile = File("$_baseFolder/payload.js");
      var sink = payloadFile.openWrite();

      // A. Inject Proxy Script (if enabled)
      if (_useProxy) {
        sink.writeln('// --- PROXY HOOK ---');
        sink.writeln(_generateProxyScript(_ipCtrl.text, _portCtrl.text));
      }

      // B. Inject User Selected Scripts
      _selectedScripts.forEach((path, isSelected) {
        if (isSelected) {
          sink.writeln('\n// --- FILE: ${path.split('/').last} ---');
          sink.writeln(File(path).readAsStringSync());
        }
      });
      
      await sink.close();
      _log("    Payload saved to: ${payloadFile.path}");

      // 3. EXECUTE ROOT COMMAND
      _log("[3] Spawning Target: $_targetPackage");
      
      // Command: su -c "binary -f package -s script"
      String cmd = "${internalBinary.path} -f $_targetPackage -s ${payloadFile.path}";
      
      // Start process and stream the output logs
      Process process = await Process.start('su', ['-c', cmd]);
      
      // Listen to Standard Output (stdout)
      process.stdout.transform(utf8.decoder).listen((data) {
        _log(data); 
      });
      
      // Listen to Error Output (stderr)
      process.stderr.transform(utf8.decoder).listen((data) {
        _log("[ERR] $data");
      });

    } catch (e) {
      _log("[!] Error: $e");
    }
  }

  // Helper to generate Java Hook for Proxy
  String _generateProxyScript(String ip, String port) {
    return """
    Java.perform(function() {
      console.log("[+] Force Proxy: $ip:$port");
      var System = Java.use("java.lang.System");
      System.setProperty("http.proxyHost", "$ip");
      System.setProperty("http.proxyPort", "$port");
      System.setProperty("https.proxyHost", "$ip");
      System.setProperty("https.proxyPort", "$port");
    });
    """;
  }

  // --- UI HELPERS ---
  
  // Appends text to terminal log
  void _log(String text) {
    setState(() => _logs += "$text\n");
  }

  // Opens a dialog to pick installed apps
  Future<void> _pickApp() async {
    List<Application> apps = await DeviceApps.getInstalledApplications(includeAppIcons: true);
    
    showDialog(context: context, builder: (ctx) => AlertDialog(
      title: const Text("Select App"),
      content: SizedBox(
        width: double.maxFinite,
        height: 300,
        child: ListView.builder(
          itemCount: apps.length,
          itemBuilder: (c, i) => ListTile(
            leading: apps[i] is WithIcon ? Image.memory((apps[i] as WithIcon).icon, width: 32) : null,
            title: Text(apps[i].appName),
            subtitle: Text(apps[i].packageName),
            onTap: () {
              setState(() {
                _targetName = apps[i].appName;
                _targetPackage = apps[i].packageName;
              });
              Navigator.pop(ctx);
            },
          ),
        ),
      ),
    ));
  }

  // --- VIEW BUILDER (UI LAYOUT) ---
  @override
  Widget build(BuildContext context) {
    bool binaryExists = File("$_baseFolder/frida-inject").existsSync();

    return Scaffold(
      backgroundColor: Colors.grey[900], // Hacker theme
      appBar: AppBar(title: const Text("SoCute.apk (Frida GUI)"), backgroundColor: Colors.black),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // 1. TARGET APP SELECTION
            Card(
              color: Colors.grey[850],
              child: ListTile(
                title: Text(_targetName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                subtitle: Text(_targetPackage.isEmpty ? "Tap to select" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                trailing: const Icon(Icons.touch_app, color: Colors.white),
                onTap: _pickApp,
              ),
            ),
            
            // 2. BINARY CONFIGURATION
            Card(
              color: Colors.grey[850],
              child: Padding(
                padding: const EdgeInsets.all(10),
                child: Column(
                  children: [
                    Text(binaryExists ? "Binary Ready ✅" : "Binary Missing ❌", style: TextStyle(color: binaryExists ? Colors.green : Colors.red)),
                    if (!binaryExists) ...[
                      TextField(
                        controller: _urlCtrl, 
                        style: const TextStyle(color: Colors.white, fontSize: 10), 
                        decoration: const InputDecoration(labelText: "Binary URL")
                      ),
                      ElevatedButton(onPressed: _downloadBinary, child: const Text("Download & Install"))
                    ]
                  ],
                ),
              ),
            ),

            // 3. INJECT OPTIONS (Proxy & Scripts)
            ExpansionTile(
              title: const Text("Inject Options", style: TextStyle(color: Colors.white)),
              initiallyExpanded: true,
              children: [
                // Proxy Config
                CheckboxListTile(
                  title: const Text("Enable Proxy", style: TextStyle(color: Colors.white)),
                  value: _useProxy,
                  onChanged: (v) => setState(() => _useProxy = v!),
                ),
                if (_useProxy) Row(
                  children: [
                    Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "IP", labelStyle: TextStyle(color: Colors.grey)))),
                    const SizedBox(width: 10),
                    Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Port", labelStyle: TextStyle(color: Colors.grey)))),
                  ],
                ),
                const Divider(color: Colors.grey),
                
                // Script List from /sdcard
                Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                  const Text("  Scripts (/socute-apk/scripts)", style: TextStyle(color: Colors.grey)),
                  IconButton(icon: const Icon(Icons.refresh, color: Colors.white), onPressed: _refreshFiles)
                ]),
                ..._scriptFiles.map((f) => CheckboxListTile(
                  title: Text(f.path.split('/').last, style: const TextStyle(color: Colors.white)),
                  value: _selectedScripts[f.path],
                  onChanged: (v) => setState(() => _selectedScripts[f.path] = v!),
                  dense: true,
                )).toList(),
              ],
            ),

            const SizedBox(height: 10),
            
            // 4. LAUNCH BUTTON
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: Colors.greenAccent, padding: const EdgeInsets.symmetric(vertical: 15)),
              onPressed: _launchAndInject,
              child: const Text("LAUNCH & INJECT", style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 18)),
            ),

            const SizedBox(height: 10),

            // 5. TERMINAL LOG OUTPUT
            Container(
              height: 200,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.green)),
              child: SingleChildScrollView(
                reverse: true, // Auto scroll to bottom
                child: Text(_logs, style: const TextStyle(color: Colors.green, fontFamily: 'monospace')),
              ),
            )
          ],
        ),
      ),
    );
  }
}