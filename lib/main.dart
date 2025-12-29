import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
// Permission handler kita hapus sebagian besar fungsinya karena kita pakai jalur legal
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
  String _logs = "Initializing...\n";
  String _targetPackage = "";
  String _targetName = "Select Target App";
  
  bool _useProxy = false;
  final TextEditingController _ipCtrl = TextEditingController(text: "192.168.1.10");
  final TextEditingController _portCtrl = TextEditingController(text: "8080");
  final TextEditingController _urlCtrl = TextEditingController(); 

  List<File> _scriptFiles = [];
  Map<String, bool> _selectedScripts = {}; 
  Process? _runningProcess;
  bool _isRunning = false;
  
  // paths
  String? _storageDir;  // Android/data/com.socute/files (User visible)
  String? _internalDir; // /data/user/0/... (Executable safe)
  
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initPaths());
  }

  // --- INITIALIZATION (NO PERMISSIONS NEEDED) ---
  Future<void> _initPaths() async {
    try {
      // 1. Dapatkan folder khusus aplikasi di SDCard (User bisa taruh script di sini)
      // Path: /sdcard/Android/data/com.socute.socute/files/
      final extDir = await getExternalFilesDir(null);
      _storageDir = extDir!.path;
      
      // 2. Dapatkan folder private internal (Untuk eksekusi binary)
      final intDir = await getApplicationSupportDirectory();
      _internalDir = intDir.path;

      _log("[*] Storage: $_storageDir");
      _log("[*] Internal: $_internalDir");
      _log("[*] No permissions required for these paths. ✅");

      await _detectArchAndSetUrl();
      await _refreshFiles();
    } catch (e) {
      _log("[!!!] Init Error: $e");
    }
  }

  Future<void> _detectArchAndSetUrl() async {
    try {
        var androidInfo = await DeviceInfoPlugin().androidInfo;
        var abi = androidInfo.supportedAbis[0];
        
        String arch = 'arm64'; 
        if (abi.contains('armeabi')) arch = 'arm';
        else if (abi.contains('x86_64')) arch = 'x86_64';
        else if (abi.contains('x86')) arch = 'x86';
        
        String ver = "16.1.4"; 
        setState(() {
          _urlCtrl.text = "https://github.com/frida/frida/releases/download/$ver/frida-inject-$ver-android-$arch.xz";
        });
    } catch (e) {
        _log("[!] Error Detecting Arch: $e");
    }
  }

  // --- FILE SYSTEM LOGIC ---
  Future<void> _refreshFiles() async {
    if (_storageDir == null) return;
    try {
        // Buat folder scripts di Android/data/.../files/scripts
        final scriptDir = Directory("$_storageDir/scripts");
        if (!await scriptDir.exists()) {
          await scriptDir.create(recursive: true);
          _log("[*] Created user script folder:\n$_storageDir/scripts");
        }

        List<FileSystemEntity> files = scriptDir.listSync();
        setState(() {
          _scriptFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
          for (var f in _scriptFiles) {
            if (!_selectedScripts.containsKey(f.path)) {
              _selectedScripts[f.path] = false;
            }
          }
        });
    } catch (e) {
        _log("[!] Error Accessing Files: $e");
    }
  }

  // --- DOWNLOAD LOGIC ---
  Future<void> _downloadBinary() async {
    if (_storageDir == null) return;
    try {
      _log("[*] Downloading binary...");
      
      // Download ke Public Folder dulu (supaya user bisa lihat kalau mau)
      String downloadPath = "$_storageDir/frida-inject.xz";
      await Dio().download(_urlCtrl.text, downloadPath);
      _log("[*] Download complete. Extracting...");

      List<int> xzBytes = File(downloadPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      
      // Simpan binary asli di folder storage
      File("$_storageDir/frida-inject")
        ..createSync()
        ..writeAsBytesSync(tarBytes);
      
      File(downloadPath).deleteSync();
      _log("[*] Binary saved to $_storageDir/frida-inject");
      if (!mounted) return;
      setState(() {}); 
    } catch (e) {
      _log("[!] Error downloading: $e");
    }
  }

  // --- STOP LOGIC ---
  Future<void> _stopAndKill() async {
    if (_targetPackage.isEmpty) return;
    _log("\n[!!!] STOPPING PROCESS...");
    try {
      _runningProcess?.kill();
      await Process.run('su', ['-c', 'pkill -f frida-inject']);
      await Process.run('su', ['-c', 'am force-stop $_targetPackage']);
      _log("[*] Target killed.");
    } catch (e) {
      _log("[!] Error stopping: $e");
    }
    setState(() { _isRunning = false; _runningProcess = null; });
  }

  // --- LAUNCH LOGIC (THE SMART WAY) ---
  Future<void> _launchAndInject() async {
    if (_targetPackage.isEmpty) { _log("[!] Select target app first!"); return; }
    
    // 1. Ambil binary dari Storage
    File binarySource = File("$_storageDir/frida-inject");
    if (!binarySource.existsSync()) { _log("[!] Binary not found. Please download."); return; }

    setState(() => _isRunning = true);

    try {
      _log("--- STARTING INJECTION ---");
      
      // 2. COPY ke Internal Private (Wajib agar bisa di-execute oleh Android)
      // Android modern memblokir eksekusi file langsung dari /sdcard
      final executable = File("$_internalDir/frida-bin");
      if (await executable.exists()) await executable.delete();
      await executable.writeAsBytes(await binarySource.readAsBytes());
      
      // 3. CHMOD +x (Sekarang legal karena di internal folder sendiri)
      await Process.run('chmod', ['755', executable.path]);

      // 4. Siapkan Payload
      final payloadFile = File("$_internalDir/payload.js");
      var sink = payloadFile.openWrite();
      if (_useProxy) sink.writeln(_generateProxyScript(_ipCtrl.text, _portCtrl.text));
      _selectedScripts.forEach((path, isSelected) {
        if (isSelected) {
          sink.writeln('\n// FILE: ${path.split('/').last}');
          sink.writeln(File(path).readAsStringSync());
        }
      });
      await sink.close();
      
      _log("[*] Spawning $_targetPackage...");
      
      // 5. Jalankan!
      String cmd = "${executable.path} -f $_targetPackage -s ${payloadFile.path}";
      
      // Kita tetap butuh SU untuk attach ke aplikasi lain
      _runningProcess = await Process.start('su', ['-c', cmd]);
      
      _runningProcess!.stdout.transform(utf8.decoder).listen((data) { _log(data.trim()); });
      _runningProcess!.stderr.transform(utf8.decoder).listen((data) { _log("[ERR] ${data.trim()}"); });

    } catch (e) {
      _log("[!] Error: $e");
      setState(() => _isRunning = false);
    }
  }

  String _generateProxyScript(String ip, String port) {
    return "Java.perform(function() { console.log('[+] Proxy: $ip:$port'); var S = Java.use('java.lang.System'); S.setProperty('http.proxyHost','$ip'); S.setProperty('http.proxyPort','$port'); S.setProperty('https.proxyHost','$ip'); S.setProperty('https.proxyPort','$port'); });";
  }

  void _log(String text) {
    if (!mounted) return;
    setState(() => _logs += "$text\n");
  }

  Future<void> _pickApp() async {
    try {
        List<Application> apps = await DeviceApps.getInstalledApplications(includeAppIcons: true);
        if (!mounted) return;
        showDialog(context: context, builder: (ctx) => AlertDialog(
          title: const Text("Select App"),
          content: SizedBox(
            width: double.maxFinite,
            height: 300,
            child: ListView.builder(
              itemCount: apps.length,
              itemBuilder: (c, i) => ListTile(
                leading: apps[i] is ApplicationWithIcon 
                    ? Image.memory((apps[i] as ApplicationWithIcon).icon, width: 32) 
                    : null,
                title: Text(apps[i].appName),
                subtitle: Text(apps[i].packageName),
                onTap: () {
                  setState(() { _targetName = apps[i].appName; _targetPackage = apps[i].packageName; });
                  Navigator.pop(ctx);
                },
              ),
            ),
          ),
        ));
    } catch (e) {
        _log("[!] Error listing apps: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    // Cek keberadaan binary di storage folder
    bool binaryExists = _storageDir != null && File("$_storageDir/frida-inject").existsSync();

    return Scaffold(
      backgroundColor: Colors.grey[900], 
      appBar: AppBar(title: const Text("SoCute (Clean Core)"), backgroundColor: Colors.black, actions: [IconButton(icon: const Icon(Icons.delete), onPressed: ()=>setState(()=>_logs=""))]),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // TARGET
            Card(
              color: Colors.grey[850],
              child: ListTile(
                title: Text(_targetName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                subtitle: Text(_targetPackage.isEmpty ? "Tap to select" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                trailing: const Icon(Icons.touch_app, color: Colors.white),
                onTap: _isRunning ? null : _pickApp,
              ),
            ),
            
            // BINARY CONFIG
            Card(
              color: Colors.grey[850],
              child: Padding(
                padding: const EdgeInsets.all(10),
                child: Column(
                  children: [
                    if (binaryExists) 
                      Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          const Text("Binary Ready ✅", style: TextStyle(color: Colors.green, fontWeight: FontWeight.bold)),
                          const SizedBox(width: 10),
                          IconButton(
                            icon: const Icon(Icons.delete_forever, color: Colors.red),
                            onPressed: () {
                              try { File("$_storageDir/frida-inject").deleteSync(); setState(() {}); } catch (e) { _log("[!] Failed: $e"); }
                            },
                          )
                        ],
                      ),
                    if (!binaryExists) ...[
                      const Text("Binary Missing ❌", style: TextStyle(color: Colors.red)),
                      TextField(controller: _urlCtrl, style: const TextStyle(color: Colors.white, fontSize: 12), decoration: const InputDecoration(labelText: "URL", labelStyle: TextStyle(color: Colors.grey))),
                      ElevatedButton(onPressed: _downloadBinary, child: const Text("Download"))
                    ]
                  ],
                ),
              ),
            ),

            // OPTIONS
            ExpansionTile(
              title: const Text("Inject Options", style: TextStyle(color: Colors.white)),
              initiallyExpanded: true,
              children: [
                CheckboxListTile(title: const Text("Proxy", style: TextStyle(color: Colors.white)), value: _useProxy, onChanged: _isRunning ? null : (v) => setState(() => _useProxy = v!)),
                if (_useProxy) Row(children: [Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white))), const SizedBox(width: 10), Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white)))]),
                
                const Divider(),
                // SCRIPT LOCATION INFO
                Padding(
                  padding: const EdgeInsets.all(8.0),
                  child: Text("Put .js scripts in:\nAndroid/data/com.socute.socute/files/scripts/", 
                    style: TextStyle(color: Colors.orangeAccent, fontSize: 12, fontStyle: FontStyle.italic), textAlign: TextAlign.center),
                ),
                IconButton(icon: const Icon(Icons.refresh, color: Colors.white), onPressed: _refreshFiles),
                ..._scriptFiles.map((f) => CheckboxListTile(
                  title: Text(f.path.split('/').last, style: const TextStyle(color: Colors.white)),
                  value: _selectedScripts[f.path],
                  onChanged: _isRunning ? null : (v) => setState(() => _selectedScripts[f.path] = v!),
                  dense: true,
                )).toList(),
              ],
            ),

            const SizedBox(height: 10),
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: _isRunning ? Colors.redAccent : Colors.greenAccent, padding: const EdgeInsets.symmetric(vertical: 15)),
              onPressed: _isRunning ? _stopAndKill : _launchAndInject,
              child: Text(_isRunning ? "STOP" : "LAUNCH", style: const TextStyle(color: Colors.black, fontWeight: FontWeight.bold)),
            ),

            const SizedBox(height: 10),
            Container(height: 200, padding: const EdgeInsets.all(5), color: Colors.black, child: SingleChildScrollView(reverse: true, child: Text(_logs, style: const TextStyle(color: Colors.green, fontFamily: 'monospace'))))
          ],
        ),
      ),
    );
  }
}