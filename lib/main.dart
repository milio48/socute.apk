import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:device_apps/device_apps.dart';

void main() {
  // Catch global Flutter errors
  FlutterError.onError = (FlutterErrorDetails details) {
    print("Flutter Error: ${details.exception}");
  };
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
  
  // URL Controller: Users can edit this manually before downloading
  final TextEditingController _urlCtrl = TextEditingController(); 

  List<File> _scriptFiles = [];
  Map<String, bool> _selectedScripts = {}; 
  Process? _runningProcess;
  bool _isRunning = false;
  final String _baseFolder = "/sdcard/socute-apk";
  
  @override
  void initState() {
    super.initState();
    // SAFE MODE: Wait for the first frame to render to prevent start-up crashes.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _safeInit();
    });
  }

  // --- INITIALIZATION (SAFE MODE) ---
  Future<void> _safeInit() async {
    // Delay 1 second to let the UI settle
    await Future.delayed(const Duration(seconds: 1));
    _log("[*] System Ready. Checking permissions...");
    
    try {
      // 1. Request Basic Storage Permission (Android 10 and below)
      await Permission.storage.request();
      
      // 2. Request Manage External Storage (Android 11+)
      if (await Permission.manageExternalStorage.status.isDenied) {
        try {
            await Permission.manageExternalStorage.request();
        } catch (e) {
            _log("[!] Skipped ManageStorage (Not supported on this Android version)");
        }
      }

      // 3. Continue initialization
      await _detectArchAndSetUrl();
      await _refreshFiles();
      _log("[OK] Initialization Complete.");
    } catch (e, stack) {
      _log("[!!!] CRITICAL ERROR during Init: $e");
      _log(stack.toString());
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
        
        // Latest version per user request: 17.5.2
        String ver = "17.5.2"; 
        
        // We default to 'android' build for compatibility, but user can change it to 'linux' manually.
        String defaultUrl = "https://github.com/frida/frida/releases/download/$ver/frida-inject-$ver-android-$arch.xz";
        
        setState(() {
          // Only set if empty so we don't overwrite user's manual input on reload
          if (_urlCtrl.text.isEmpty) {
            _urlCtrl.text = defaultUrl;
          }
        });
    } catch (e) {
        _log("[!] Error Detecting Arch: $e");
    }
  }

  // --- FILE SYSTEM LOGIC ---
  Future<void> _refreshFiles() async {
    try {
        final dir = Directory("$_baseFolder/scripts");
        if (!await dir.exists()) {
          try {
             await dir.create(recursive: true);
             _log("Created folder: $_baseFolder/scripts");
          } catch (e) {
             _log("[!] Failed to create folder. Permission denied?");
             return;
          }
        }

        List<FileSystemEntity> files = dir.listSync();
        setState(() {
          _scriptFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
          for (var f in _scriptFiles) {
            if (!_selectedScripts.containsKey(f.path)) {
              _selectedScripts[f.path] = false;
            }
          }
        });
    } catch (e) {
        _log("[!] Error Reading Files: $e");
    }
  }

  // --- DOWNLOAD LOGIC ---
  Future<void> _downloadBinary() async {
    try {
      _log("[*] Downloading binary...");
      if (!mounted) return;
      var dir = await getApplicationSupportDirectory();
      String tempPath = "${dir.path}/temp.xz";
      
      // Download from the URL currently in the text field (User Control)
      await Dio().download(_urlCtrl.text, tempPath);
      _log("[*] Download complete. Extracting...");

      List<int> xzBytes = File(tempPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      
      File("$_baseFolder/frida-inject")
        ..createSync(recursive: true)
        ..writeAsBytesSync(tarBytes);
      
      File(tempPath).deleteSync();
      _log("[*] Binary saved to $_baseFolder/frida-inject");
      if (!mounted) return;
      setState(() {}); 
    } catch (e) {
      _log("[!] Error downloading: $e");
    }
  }

  // --- STOP / KILL LOGIC ---
  Future<void> _stopAndKill() async {
    if (_targetPackage.isEmpty) return;
    _log("\n[!!!] STOPPING PROCESS...");
    try {
      // Kill Dart stream
      _runningProcess?.kill();
      // Kill frida-inject binary
      await Process.run('su', ['-c', 'pkill -f frida-inject']);
      // Force stop target app
      await Process.run('su', ['-c', 'am force-stop $_targetPackage']);
      _log("[*] Target killed.");
    } catch (e) {
      _log("[!] Error stopping: $e");
    }
    setState(() { _isRunning = false; _runningProcess = null; });
  }

  // --- LAUNCH LOGIC ---
  Future<void> _launchAndInject() async {
    if (_targetPackage.isEmpty) { _log("[!] Select target app first!"); return; }
    
    File binaryExternal = File("$_baseFolder/frida-inject");
    if (!binaryExternal.existsSync()) { _log("[!] Binary not found."); return; }

    setState(() => _isRunning = true);

    try {
      _log("--- STARTING INJECTION ---");
      // 1. Move binary to internal storage for execution
      final internalDir = await getApplicationSupportDirectory();
      final internalBinary = File("${internalDir.path}/frida-bin");
      await internalBinary.writeAsBytes(await binaryExternal.readAsBytes());
      await Process.run('chmod', ['755', internalBinary.path]);

      // 2. Prepare Payload
      final payloadFile = File("$_baseFolder/payload.js");
      var sink = payloadFile.openWrite();
      if (_useProxy) {
        sink.writeln(_generateProxyScript(_ipCtrl.text, _portCtrl.text));
      }
      _selectedScripts.forEach((path, isSelected) {
        if (isSelected) {
          sink.writeln('\n// FILE: ${path.split('/').last}');
          sink.writeln(File(path).readAsStringSync());
        }
      });
      await sink.close();
      
      // 3. Spawn Target
      _log("[*] Spawning $_targetPackage...");
      String cmd = "${internalBinary.path} -f $_targetPackage -s ${payloadFile.path}";
      _runningProcess = await Process.start('su', ['-c', cmd]);
      
      // 4. Listen to logs
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
    bool binaryExists = File("$_baseFolder/frida-inject").existsSync();
    return Scaffold(
      backgroundColor: Colors.grey[900], 
      appBar: AppBar(title: const Text("SoCute (SafeMode)"), backgroundColor: Colors.black, actions: [IconButton(icon: const Icon(Icons.delete), onPressed: ()=>setState(()=>_logs=""))]),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // 1. Target Selector
            Card(color: Colors.grey[850], child: ListTile(title: Text(_targetName, style: const TextStyle(color: Colors.white)), subtitle: Text(_targetPackage, style: const TextStyle(color: Colors.green)), onTap: _isRunning ? null : _pickApp)),
            
            // 2. Binary Config
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
                           const Text("Binary Ready (v17.5.2) ✅", style: TextStyle(color: Colors.green)),
                           const SizedBox(width: 10),
                           // DELETE BUTTON: Allows user to reset and change version
                           IconButton(
                             icon: const Icon(Icons.delete_forever, color: Colors.red),
                             tooltip: "Delete & Change Version",
                             onPressed: () {
                               try {
                                 File("$_baseFolder/frida-inject").deleteSync();
                                 setState(() {}); 
                               } catch (e) { _log("[!] Delete failed: $e"); }
                             },
                           )
                        ],
                      ),
                    
                    if (!binaryExists) ...[
                      const Text("Binary Missing ❌", style: TextStyle(color: Colors.red)),
                      // EDITABLE URL FIELD
                      TextField(
                        controller: _urlCtrl, 
                        style: const TextStyle(color: Colors.white, fontSize: 11), 
                        decoration: const InputDecoration(
                          labelText: "Frida Binary URL (Editable)",
                          labelStyle: TextStyle(color: Colors.grey),
                          helperText: "Suggest: 17.5.2 (android/linux)",
                          helperStyle: TextStyle(color: Colors.white30)
                        )
                      ),
                      const SizedBox(height: 5),
                      ElevatedButton(onPressed: _downloadBinary, child: const Text("Download"))
                    ]
                  ],
                ),
              ),
            ),

            // 3. Options
            ExpansionTile(title: const Text("Options", style: TextStyle(color: Colors.white)), children: [
                CheckboxListTile(title: const Text("Proxy", style: TextStyle(color: Colors.white)), value: _useProxy, onChanged: _isRunning ? null : (v) => setState(() => _useProxy = v!)),
                if(_useProxy) Row(children: [Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white))), const SizedBox(width:10), Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white)))]),
                IconButton(icon: const Icon(Icons.refresh, color: Colors.white), onPressed: _refreshFiles),
                ..._scriptFiles.map((f) => CheckboxListTile(title: Text(f.path.split('/').last, style: const TextStyle(color: Colors.white)), value: _selectedScripts[f.path], onChanged: (v) => setState(() => _selectedScripts[f.path] = v!))).toList()
            ]),
            
            // 4. Launch Button
            ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: _isRunning ? Colors.red : Colors.green), onPressed: _isRunning ? _stopAndKill : _launchAndInject, child: Text(_isRunning ? "STOP" : "LAUNCH")),
            
            // 5. Logs
            Container(height: 200, padding: const EdgeInsets.all(5), color: Colors.black, child: SingleChildScrollView(reverse: true, child: Text(_logs, style: const TextStyle(color: Colors.green, fontFamily: 'monospace'))))
          ],
        ),
      ),
    );
  }
}