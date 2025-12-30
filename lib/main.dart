import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:device_apps/device_apps.dart';
import 'package:file_picker/file_picker.dart';

void main() {
  runApp(const MaterialApp(
    home: SoCuteApp(),
    debugShowCheckedModeBanner: false,
    title: "SoCute Injector",
  ));
}

class SoCuteApp extends StatefulWidget {
  const SoCuteApp({super.key});
  @override
  State<SoCuteApp> createState() => _SoCuteAppState();
}

class _SoCuteAppState extends State<SoCuteApp> {
  // --- CORE STATE ---
  String _logs = "Initializing SoCute Core...\n";
  bool _isRunning = false;
  Process? _runningProcess;

  // --- TARGET CONFIG ---
  String _targetPackage = "";
  String _targetName = "No Target Selected";

  // --- INJECTION CONFIG ---
  bool _disableSELinux = false; // Toggle for "Anti-Crash"
  bool _useProxy = false;
  final TextEditingController _ipCtrl = TextEditingController(text: "192.168.1.10");
  final TextEditingController _portCtrl = TextEditingController(text: "8080");

  // --- DOWNLOADER CONFIG ---
  final TextEditingController _fridaVersionCtrl = TextEditingController(text: "16.2.5");
  String _selectedArch = "arm64"; // Default for modern phones
  final List<String> _archOptions = ["arm64", "arm", "x86", "x86_64"];

  // --- SCRIPT MANAGER STATE ---
  List<File> _scriptFiles = []; // The list of scripts to merge
  
  // --- PATHS ---
  String? _storageDir;  // Public: /sdcard/Android/data/com.socute.socute/files
  String? _internalDir; // Private: /data/user/0/com.socute.socute/files

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initSystem());
  }

  /// 1. SYSTEM INITIALIZATION
  /// Sets up folders and detects device architecture automatically.
  Future<void> _initSystem() async {
    try {
      // Setup Paths (Native Android 14 Way - No Permissions needed)
      final extDir = await getExternalStorageDirectory();
      final intDir = await getApplicationSupportDirectory();
      
      _storageDir = extDir!.path;
      _internalDir = intDir.path;

      // Create scripts folder if not exists
      await Directory("$_storageDir/scripts").create(recursive: true);

      _log("[*] System Ready.");
      _log("[*] Script Folder: $_storageDir/scripts");

      // Smart Architecture Detection
      var androidInfo = await DeviceInfoPlugin().androidInfo;
      var abi = androidInfo.supportedAbis[0].toLowerCase();
      
      String detectedArch = "arm64";
      if (abi.contains("arm64") || abi.contains("aarch64")) {
        detectedArch = "arm64";
      } else if (abi.contains("arm")) {
        detectedArch = "arm";
      } else if (abi.contains("x86_64")) {
        detectedArch = "x86_64";
      } else if (abi.contains("x86")) {
        detectedArch = "x86";
      }

      setState(() {
        _selectedArch = detectedArch;
      });
      _log("[*] Auto-detected Arch: $detectedArch");

      // Load existing scripts
      await _refreshScripts();

    } catch (e) {
      _log("[!] Init Failed: $e");
    }
  }

  /// 2. SCRIPT MANAGER LOGIC
  /// Loads .js files from the public folder.
  Future<void> _refreshScripts() async {
    if (_storageDir == null) return;
    try {
      final scriptDir = Directory("$_storageDir/scripts");
      List<FileSystemEntity> files = scriptDir.listSync();
      
      setState(() {
        // Filter only .js files
        var newFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
        
        // Strategy: We keep existing order if possible, append new ones.
        // For this version, we just reload. The user reorders in the UI.
        if (_scriptFiles.isEmpty) {
          _scriptFiles = newFiles;
        } else {
          // Simple refresh (resetting order for now, persistent order needs DB/JSON)
           _scriptFiles = newFiles;
        }
      });
    } catch (e) {
      _log("[!] Error loading scripts: $e");
    }
  }

  Future<void> _importScript() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['js'],
      );

      if (result != null) {
        File source = File(result.files.single.path!);
        String destPath = "$_storageDir/scripts/${result.files.single.name}";
        await source.copy(destPath);
        _log("[*] Imported: ${result.files.single.name}");
        await _refreshScripts();
      }
    } catch (e) {
      _log("[!] Import Failed: $e");
    }
  }

  void _deleteScript(File f) {
    try {
      f.deleteSync();
      _refreshScripts();
      _log("[*] Deleted: ${f.path.split('/').last}");
    } catch (e) {
      _log("[!] Delete failed: $e");
    }
  }

  /// 3. DOWNLOADER LOGIC
  /// Downloads, extracts xz, and prepares the binary.
  Future<void> _downloadBinary(BuildContext ctx) async {
    if (_storageDir == null) return;
    try {
      Navigator.pop(ctx); // Close dialog
      _log("[*] Starting Download...");
      
      String ver = _fridaVersionCtrl.text;
      String arch = _selectedArch;
      String filename = "frida-inject-$ver-android-$arch.xz";
      String url = "https://github.com/frida/frida/releases/download/$ver/$filename";
      
      _log(" -> URL: $url");

      String tempPath = "$_storageDir/temp.xz";
      
      // Download
      await Dio().download(url, tempPath, onReceiveProgress: (rec, total) {
        // Optional: Implement progress bar here if needed
      });
      _log("[*] Downloaded. Extracting...");

      // Extract .xz
      List<int> xzBytes = File(tempPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      
      // Save as standard name 'frida-inject'
      File("$_storageDir/frida-inject")
        ..createSync()
        ..writeAsBytesSync(tarBytes);
      
      // Cleanup
      File(tempPath).deleteSync();
      
      _log("[OK] Binary Ready! (Version: $ver | Arch: $arch)");
      setState(() {}); // Refresh UI to show "Ready"
      
    } catch (e) {
      _log("[!] Download Error: $e");
      _log("Tip: Check version number or internet connection.");
    }
  }

  /// 4. LAUNCHER LOGIC
  /// The robust launch sequence with SELinux handling.
  Future<void> _launchSequence() async {
    if (_targetPackage.isEmpty) { _log("[!] Select a target app first!"); return; }
    
    File binarySource = File("$_storageDir/frida-inject");
    if (!binarySource.existsSync()) { _log("[!] Binary missing. Please download it first."); return; }

    setState(() => _isRunning = true);
    _log("\n=== STARTING INJECTION SEQUENCE ===");

    try {
      // Step A: Handle SELinux (Anti-Crash)
      if (_disableSELinux) {
        _log("[*] Disabling SELinux (Anti-Crash Mode)...");
        await Process.run('su', ['-c', 'setenforce 0']);
      } else {
        _log("[*] Keeping SELinux Enforcing (Standard Mode).");
      }

      // Step B: Prepare Binary in Internal Storage (Executable Zone)
      final executable = File("$_internalDir/frida-bin");
      if (await executable.exists()) await executable.delete();
      
      _log("[*] Copying binary to internal execution sandbox...");
      await executable.writeAsBytes(await binarySource.readAsBytes());
      
      // Step C: Permission Fix
      await Process.run('chmod', ['755', executable.path]);

      // Step D: Merge Scripts & Proxy Config
      _log("[*] Merging ${_scriptFiles.length} scripts...");
      final payloadFile = File("$_internalDir/payload.js");
      var sink = payloadFile.openWrite();
      
      // Inject Proxy Config first if enabled
      if (_useProxy) {
        sink.writeln(_generateProxyScript(_ipCtrl.text, _portCtrl.text));
        _log("[+] Proxy config injected.");
      }

      // Merge user scripts in order
      for (var f in _scriptFiles) {
        sink.writeln('\n// --- START FILE: ${f.path.split('/').last} ---');
        sink.writeln(f.readAsStringSync());
        sink.writeln('// --- END FILE ---');
      }
      await sink.close();

      // Step E: EXECUTE
      _log("[*] Spawning target: $_targetPackage");
      String cmd = "${executable.path} -f $_targetPackage -s ${payloadFile.path}";
      
      // Run with SU
      _runningProcess = await Process.start('su', ['-c', cmd]);
      
      // Stream logs
      _runningProcess!.stdout.transform(utf8.decoder).listen((data) { 
        _log(data.trim()); 
      });
      _runningProcess!.stderr.transform(utf8.decoder).listen((data) { 
        _log("[ERR] ${data.trim()}"); 
      });

    } catch (e) {
      _log("[!!!] LAUNCH FAILED: $e");
      setState(() => _isRunning = false);
    }
  }

  Future<void> _stopSequence() async {
    if (_runningProcess != null) {
      _runningProcess!.kill();
    }
    // Force kill via shell to be sure
    await Process.run('su', ['-c', 'pkill -f frida-inject']);
    
    setState(() {
      _isRunning = false; 
      _runningProcess = null;
    });
    _log("[*] Process Stopped.");
  }

  String _generateProxyScript(String ip, String port) {
    return "Java.perform(function() { console.log('[+] Setting Proxy to $ip:$port'); var S = Java.use('java.lang.System'); S.setProperty('http.proxyHost','$ip'); S.setProperty('http.proxyPort','$port'); S.setProperty('https.proxyHost','$ip'); S.setProperty('https.proxyPort','$port'); });";
  }

  void _log(String text) {
    if (!mounted) return;
    setState(() => _logs += "$text\n");
  }

  // --- UI COMPONENTS ---

  void _showAppPicker() async {
    try {
      List<Application> apps = await DeviceApps.getInstalledApplications(includeAppIcons: true);
      showDialog(context: context, builder: (ctx) => AlertDialog(
        title: const Text("Select Target"),
        content: SizedBox(width: double.maxFinite, height: 400, child: ListView.builder(
          itemCount: apps.length,
          itemBuilder: (c, i) => ListTile(
            leading: apps[i] is ApplicationWithIcon ? Image.memory((apps[i] as ApplicationWithIcon).icon, width: 32) : null,
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
        )),
      ));
    } catch (e) {
      _log("[!] Failed to list apps: $e");
    }
  }

  void _showDownloaderDialog() {
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.grey[900], builder: (ctx) {
      return Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(ctx).viewInsets.bottom, left: 20, right: 20, top: 20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text("Binary Downloader", style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 20),
            
            // Arch Selector
            DropdownButtonFormField<String>(
              value: _selectedArch,
              dropdownColor: Colors.grey[800],
              decoration: const InputDecoration(labelText: "Architecture", labelStyle: TextStyle(color: Colors.grey), border: OutlineInputBorder()),
              style: const TextStyle(color: Colors.white),
              items: _archOptions.map((v) => DropdownMenuItem(value: v, child: Text(v.toUpperCase()))).toList(),
              onChanged: (v) => setState(() => _selectedArch = v!),
            ),
            const SizedBox(height: 10),
            
            // Version Input
            TextField(
              controller: _fridaVersionCtrl,
              style: const TextStyle(color: Colors.white),
              decoration: const InputDecoration(labelText: "Frida Version", labelStyle: TextStyle(color: Colors.grey), border: OutlineInputBorder(), helperText: "e.g. 16.2.5, 16.1.4"),
            ),
            const SizedBox(height: 20),
            
            ElevatedButton.icon(
              icon: const Icon(Icons.download),
              label: const Text("DOWNLOAD & INSTALL"),
              style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, padding: const EdgeInsets.all(15)),
              onPressed: () => _downloadBinary(ctx),
            ),
            const SizedBox(height: 20),
          ],
        ),
      );
    });
  }

  void _openScriptManager() {
    Navigator.push(context, MaterialPageRoute(builder: (context) => Scaffold(
      backgroundColor: Colors.grey[900],
      appBar: AppBar(title: const Text("Script Manager"), backgroundColor: Colors.black, actions: [
        IconButton(icon: const Icon(Icons.add), onPressed: _importScript, tooltip: "Import .js")
      ]),
      body: Column(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            color: Colors.blueGrey[900],
            child: const Row(children: [
              Icon(Icons.info_outline, color: Colors.white70),
              SizedBox(width: 10),
              Expanded(child: Text("Drag items to reorder execution. Top scripts run first.", style: TextStyle(color: Colors.white70)))
            ]),
          ),
          Expanded(
            child: ReorderableListView(
              onReorder: (oldIndex, newIndex) {
                setState(() {
                  if (newIndex > oldIndex) newIndex -= 1;
                  final item = _scriptFiles.removeAt(oldIndex);
                  _scriptFiles.insert(newIndex, item);
                });
              },
              children: [
                for (int i = 0; i < _scriptFiles.length; i++)
                  ListTile(
                    key: ValueKey(_scriptFiles[i].path),
                    title: Text(_scriptFiles[i].path.split('/').last, style: const TextStyle(color: Colors.white)),
                    leading: const Icon(Icons.drag_handle, color: Colors.grey),
                    trailing: IconButton(
                      icon: const Icon(Icons.delete, color: Colors.redAccent),
                      onPressed: () => _deleteScript(_scriptFiles[i]),
                    ),
                  )
              ],
            ),
          ),
        ],
      ),
    )));
  }

  @override
  Widget build(BuildContext context) {
    bool binaryReady = _storageDir != null && File("$_storageDir/frida-inject").existsSync();

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("SoCute", style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.grey[900],
        actions: [
           IconButton(icon: const Icon(Icons.settings_ethernet), tooltip: "Downloader", onPressed: _showDownloaderDialog),
           IconButton(icon: const Icon(Icons.description), tooltip: "Scripts", onPressed: _openScriptManager),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // 1. TARGET CARD
            Card(
              color: Colors.grey[900],
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10), side: const BorderSide(color: Colors.white24)),
              child: ListTile(
                title: Text(_targetName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                subtitle: Text(_targetPackage.isEmpty ? "Tap to select target app" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                trailing: const Icon(Icons.touch_app, color: Colors.blueAccent),
                onTap: _isRunning ? null : _showAppPicker,
              ),
            ),
            
            // 2. STATUS INDICATORS
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  binaryReady 
                      ? const Chip(label: Text("Binary OK", style: TextStyle(color: Colors.white)), backgroundColor: Colors.green)
                      : ActionChip(label: const Text("Download Binary", style: TextStyle(color: Colors.white)), backgroundColor: Colors.red, onPressed: _showDownloaderDialog),
                  Chip(label: Text("${_scriptFiles.length} Scripts", style: const TextStyle(color: Colors.white)), backgroundColor: Colors.blueGrey),
                ],
              ),
            ),

            // 3. ADVANCED TOGGLES (SELinux & Proxy)
            ExpansionTile(
              title: const Text("Launch Config", style: TextStyle(color: Colors.white)),
              collapsedBackgroundColor: Colors.grey[900],
              backgroundColor: Colors.grey[900],
              children: [
                SwitchListTile(
                  title: const Text("Disable SELinux (Anti-Crash)", style: TextStyle(color: Colors.orangeAccent)),
                  subtitle: const Text("Use if app crashes/reboots. Reduces security.", style: TextStyle(color: Colors.grey, fontSize: 11)),
                  value: _disableSELinux,
                  activeColor: Colors.orange,
                  onChanged: _isRunning ? null : (v) => setState(() => _disableSELinux = v),
                ),
                SwitchListTile(
                  title: const Text("Inject Proxy", style: TextStyle(color: Colors.white)),
                  value: _useProxy,
                  activeColor: Colors.blue,
                  onChanged: _isRunning ? null : (v) => setState(() => _useProxy = v),
                ),
                if (_useProxy) Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Row(children: [
                    Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "IP", labelStyle: TextStyle(color: Colors.grey)))),
                    const SizedBox(width: 10),
                    Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Port", labelStyle: TextStyle(color: Colors.grey)))),
                  ]),
                )
              ],
            ),

            const Spacer(),

            // 4. BIG LAUNCH BUTTON
            SizedBox(
              height: 55,
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: _isRunning ? Colors.red[900] : Colors.greenAccent[700],
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
                onPressed: _isRunning ? _stopSequence : _launchSequence,
                child: Text(
                  _isRunning ? "STOP & KILL" : "LAUNCH INJECTION",
                  style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold, letterSpacing: 1),
                ),
              ),
            ),

            const SizedBox(height: 15),

            // 5. TERMINAL LOGS
            Container(
              height: 180,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.white24), borderRadius: BorderRadius.circular(5)),
              child: SingleChildScrollView(
                reverse: true,
                child: Text(_logs, style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 12)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}