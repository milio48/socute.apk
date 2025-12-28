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
  final TextEditingController _ipCtrl = TextEditingController(text: "192.168.1.10");
  final TextEditingController _portCtrl = TextEditingController(text: "8080");
  final TextEditingController _urlCtrl = TextEditingController(); 

  List<File> _scriptFiles = [];
  Map<String, bool> _selectedScripts = {}; 

  Process? _runningProcess;
  bool _isRunning = false;

  final String _baseFolder = "/sdcard/socute-apk";
  
  @override
  void initState() {
    super.initState();
    _initApp();
  }

  // --- INITIALIZATION ---
  Future<void> _initApp() async {
    await [Permission.storage, Permission.manageExternalStorage].request();
    await _detectArchAndSetUrl();
    await _refreshFiles();
  }

  Future<void> _detectArchAndSetUrl() async {
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
  }

  // --- FILE SYSTEM LOGIC ---
  Future<void> _refreshFiles() async {
    final dir = Directory("$_baseFolder/scripts");
    if (!await dir.exists()) {
      await dir.create(recursive: true);
      _log("Created folder: $_baseFolder/scripts");
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
  }

  // --- DOWNLOAD LOGIC ---
  Future<void> _downloadBinary() async {
    try {
      _log("[*] Downloading binary...");
      if (!mounted) return;
      var dir = await getApplicationSupportDirectory();
      String tempPath = "${dir.path}/temp.xz";
      
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
      _runningProcess?.kill();
      await Process.run('su', ['-c', 'pkill -f frida-inject']);
      await Process.run('su', ['-c', 'am force-stop $_targetPackage']);
      
      _log("[*] Target '$_targetPackage' killed.");
      _log("[*] Frida process terminated.");
    } catch (e) {
      _log("[!] Error stopping: $e");
    }

    setState(() {
      _isRunning = false;
      _runningProcess = null;
    });
  }

  // --- LAUNCH LOGIC ---
  Future<void> _launchAndInject() async {
    if (_targetPackage.isEmpty) {
      _log("[!] Please select target app first!");
      return;
    }

    File binaryExternal = File("$_baseFolder/frida-inject");
    if (!binaryExternal.existsSync()) {
      _log("[!] Binary not found. Please download first.");
      return;
    }

    setState(() => _isRunning = true);

    try {
      _log("--- STARTING INJECTION ---");
      
      final internalDir = await getApplicationSupportDirectory();
      final internalBinary = File("${internalDir.path}/frida-bin");
      await internalBinary.writeAsBytes(await binaryExternal.readAsBytes());
      await Process.run('chmod', ['755', internalBinary.path]);

      final payloadFile = File("$_baseFolder/payload.js");
      var sink = payloadFile.openWrite();

      if (_useProxy) {
        sink.writeln('// --- PROXY HOOK ---');
        sink.writeln(_generateProxyScript(_ipCtrl.text, _portCtrl.text));
      }

      _selectedScripts.forEach((path, isSelected) {
        if (isSelected) {
          sink.writeln('\n// --- FILE: ${path.split('/').last} ---');
          sink.writeln(File(path).readAsStringSync());
        }
      });
      
      await sink.close();
      _log("[*] Payload prepared.");

      _log("[*] Spawning Target: $_targetPackage");
      
      String cmd = "${internalBinary.path} -f $_targetPackage -s ${payloadFile.path}";
      
      _runningProcess = await Process.start('su', ['-c', cmd]);
      
      _runningProcess!.stdout.transform(utf8.decoder).listen((data) {
        _log(data.trim()); 
      });
      
      _runningProcess!.stderr.transform(utf8.decoder).listen((data) {
        _log("[ERR] ${data.trim()}");
      });

      _runningProcess!.exitCode.then((code) {
        if (mounted && _isRunning) {
           _log("[*] Process exited with code: $code");
           setState(() => _isRunning = false);
        }
      });

    } catch (e) {
      _log("[!] Error: $e");
      setState(() => _isRunning = false);
    }
  }

  String _generateProxyScript(String ip, String port) {
    return """
    Java.perform(function() {
      console.log("[+] Force Proxy (frida-script): $ip:$port");
      var System = Java.use("java.lang.System");
      System.setProperty("http.proxyHost", "$ip");
      System.setProperty("http.proxyPort", "$port");
      System.setProperty("https.proxyHost", "$ip");
      System.setProperty("https.proxyPort", "$port");
    });
    """;
  }

  void _log(String text) {
    if (!mounted) return;
    setState(() => _logs += "$text\n");
  }

  Future<void> _pickApp() async {
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
            // --- PERBAIKAN DI SINI (WithIcon -> ApplicationWithIcon) ---
            leading: apps[i] is ApplicationWithIcon 
                ? Image.memory((apps[i] as ApplicationWithIcon).icon, width: 32) 
                : null,
            // -----------------------------------------------------------
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

  @override
  Widget build(BuildContext context) {
    bool binaryExists = File("$_baseFolder/frida-inject").existsSync();

    return Scaffold(
      backgroundColor: Colors.grey[900], 
      appBar: AppBar(
        title: const Text("SoCute.apk (Frida GUI)"), 
        backgroundColor: Colors.black,
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline), 
            onPressed: () => setState(() => _logs = ""),
            tooltip: "Clear Logs",
          )
        ],
      ),
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
                onTap: _isRunning ? null : _pickApp,
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

            // 3. INJECT OPTIONS
            ExpansionTile(
              title: const Text("Inject Options", style: TextStyle(color: Colors.white)),
              initiallyExpanded: true,
              children: [
                CheckboxListTile(
                  title: const Text("Enable Proxy (by frida-script)", style: TextStyle(color: Colors.white)),
                  subtitle: const Text("Injects HTTP proxy config via Java System Property", style: TextStyle(color: Colors.grey, fontSize: 10)),
                  value: _useProxy,
                  onChanged: _isRunning ? null : (v) => setState(() => _useProxy = v!),
                ),
                if (_useProxy) Row(
                  children: [
                    Expanded(child: TextField(controller: _ipCtrl, enabled: !_isRunning, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "IP", labelStyle: TextStyle(color: Colors.grey)))),
                    const SizedBox(width: 10),
                    Expanded(child: TextField(controller: _portCtrl, enabled: !_isRunning, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Port", labelStyle: TextStyle(color: Colors.grey)))),
                  ],
                ),
                const Divider(color: Colors.grey),
                
                Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                  const Text("  Scripts (/socute-apk/scripts)", style: TextStyle(color: Colors.grey)),
                  IconButton(icon: const Icon(Icons.refresh, color: Colors.white), onPressed: _refreshFiles)
                ]),
                ..._scriptFiles.map((f) => CheckboxListTile(
                  title: Text(f.path.split('/').last, style: const TextStyle(color: Colors.white)),
                  value: _selectedScripts[f.path],
                  onChanged: _isRunning ? null : (v) => setState(() => _selectedScripts[f.path] = v!),
                  dense: true,
                )).toList(),
              ],
            ),

            const SizedBox(height: 10),
            
            // 4. ACTION BUTTON
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: _isRunning ? Colors.redAccent : Colors.greenAccent, 
                padding: const EdgeInsets.symmetric(vertical: 15)
              ),
              onPressed: _isRunning ? _stopAndKill : _launchAndInject,
              child: Text(
                _isRunning ? "STOP & KILL APP" : "LAUNCH & INJECT", 
                style: const TextStyle(color: Colors.black, fontWeight: FontWeight.bold, fontSize: 18)
              ),
            ),

            const SizedBox(height: 10),

            // 5. TERMINAL LOG
            Container(
              height: 200,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(color: Colors.black, border: Border.all(color: _isRunning ? Colors.red : Colors.green)),
              child: SingleChildScrollView(
                reverse: true, 
                child: Text(_logs, style: const TextStyle(color: Colors.green, fontFamily: 'monospace')),
              ),
            )
          ],
        ),
      ),
    );
  }
}