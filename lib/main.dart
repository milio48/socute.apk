import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:dio/dio.dart';
import 'package:http/http.dart' as http;
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:device_apps/device_apps.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:file_picker/file_picker.dart';
import 'package:pty/pty.dart'; // [CORE] Wajib ada untuk Runtime Inject

// --- MAIN ENTRY POINT ---
void main() {
  runApp(const MaterialApp(
    title: "SoCute Injector",
    debugShowCheckedModeBanner: false,
    home: LauncherPage(),
  ));
}

// --- DATA MODELS ---
class ScriptItem {
  File? file;
  String virtualType; 
  bool isVirtual;
  bool isChecked;
  String name;
  String description;

  ScriptItem({
    this.file, 
    this.virtualType = "",
    this.isVirtual = false, 
    this.isChecked = true, 
    required this.name,
    this.description = ""
  });
}

// --- ENGINE BUILDER (v2.6.2) ---
class SocuteEngineBuilder {
  static const String FIAU_FILENAME = "fiau_template.js";
  static const String FMU_FILENAME = "fmu_template.js";
  static const String FIAU_URL = "https://raw.githubusercontent.com/milio48/socute.apk/refs/heads/main/fiau-by-httptoolkit.js";
  static const String FMU_URL = "https://raw.githubusercontent.com/milio48/socute.apk/refs/heads/main/fmu-by-akabe1.js"; 

  static Future<bool> isFiauAvailable() async {
    final dir = await getApplicationDocumentsDirectory();
    return File("${dir.path}/$FIAU_FILENAME").exists();
  }

  static Future<bool> isFmuAvailable() async {
    final dir = await getApplicationDocumentsDirectory();
    return File("${dir.path}/$FMU_FILENAME").exists();
  }

  static Future<void> downloadScript(String url, String filename) async {
    final response = await http.get(Uri.parse(url));
    if (response.statusCode == 200) {
      final dir = await getApplicationDocumentsDirectory();
      await File("${dir.path}/$filename").writeAsString(response.body);
    } else {
      throw Exception("HTTP ${response.statusCode}");
    }
  }

  static Future<String> generateFiauScript() async {
    final prefs = await SharedPreferences.getInstance();
    final dir = await getApplicationDocumentsDirectory();
    final templateFile = File("${dir.path}/$FIAU_FILENAME");
    if (!await templateFile.exists()) return "// [ERROR] FIAU Template missing."; 

    String content = await templateFile.readAsString();
    // Configs
    String cert = prefs.getString('cfg_cert') ?? "";
    String ip = prefs.getString('cfg_ip') ?? "127.0.0.1";
    String port = prefs.getString('cfg_port') ?? "8080";
    bool debug = prefs.getBool('cfg_debug') ?? false;
    bool blockHttp3 = prefs.getBool('cfg_http3') ?? true;
    String ignoredPortsRaw = prefs.getString('cfg_ignored') ?? "";
    bool socks5 = prefs.getBool('cfg_socks5') ?? false;
    String ignoredPortsJson = ignoredPortsRaw.trim().isEmpty ? "[]" : "[${ignoredPortsRaw}]";

    final replacements = {
      '{{SOCUTE_CERT_PEM}}': cert,
      '{{SOCUTE_PROXY_HOST}}': ip,
      '{{SOCUTE_PROXY_PORT}}': port,
      '{{SOCUTE_DEBUG_MODE}}': debug.toString(),
      '{{SOCUTE_BLOCK_HTTP3}}': blockHttp3.toString(),
      '{{SOCUTE_IGNORED_PORTS}}': ignoredPortsJson,
      '{{SOCUTE_SOCKS5_SUPPORT}}': socks5.toString(),
    };
    replacements.forEach((key, val) => content = content.replaceAll(key, val));
    return content;
  }

  static Future<String> generateFmuScript() async {
    final dir = await getApplicationDocumentsDirectory();
    final templateFile = File("${dir.path}/$FMU_FILENAME");
    if (!await templateFile.exists()) return "// [ERROR] FMU Template missing.";
    return await templateFile.readAsString();
  }
}

// ==========================================
// PAGE 1: LAUNCHER
// ==========================================
class LauncherPage extends StatefulWidget {
  const LauncherPage({super.key});
  @override
  State<LauncherPage> createState() => _LauncherPageState();
}

class _LauncherPageState extends State<LauncherPage> with SingleTickerProviderStateMixin, WidgetsBindingObserver {
  // Logs & Process
  String _logs = "Initializing SoCute v2.6.2 (PTY Edition)...\n";
  String _runtimeLogs = "";
  bool _isRunning = false;
  bool _isRuntimeRunning = false;
  
  // [CORE] Menggunakan PseudoTerminal bukan Process biasa
  PseudoTerminal? _mainPty;
  
  // History Files
  File? _historyExecFile;
  File? _historyRuntimeFile;

  // Target
  String _targetPackage = "";
  String _targetName = "Select Target App";

  // Configs
  bool _selinuxPermissive = false; 
  bool _sslBypassMode = false; 
  late TabController _tabController;
  
  // Downloader
  final TextEditingController _fridaVersionCtrl = TextEditingController(text: "17.5.2");
  String _selectedArch = "arm64";
  String _hostCpu = "Unknown";
  final List<String> _archOptions = ["arm64", "arm", "x86", "x86_64"];

  // Script Data
  List<ScriptItem> _scriptItems = [];
  List<File> _availableAssets = []; 
  File? _selectedRuntimeScript;
  String? _storageDir;  
  String? _internalDir; 
  
  bool _fiauReady = false;
  bool _fmuReady = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _tabController = TabController(length: 2, vsync: this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _initSystem());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _checkSELinux();
  }

  Future<void> _initSystem() async {
    try {
      final extDir = await getExternalStorageDirectory();
      final intDir = await getApplicationSupportDirectory();
      _storageDir = extDir!.path;
      _internalDir = intDir.path;
      await Directory("$_storageDir/scripts").create(recursive: true);
      
      _historyExecFile = File("$_internalDir/history_exec.log");
      _historyRuntimeFile = File("$_internalDir/history_runtime.log");
      if (!_historyExecFile!.existsSync()) _historyExecFile!.createSync();
      if (!_historyRuntimeFile!.existsSync()) _historyRuntimeFile!.createSync();

      // Detect Host CPU
      var androidInfo = await DeviceInfoPlugin().androidInfo;
      var abi = androidInfo.supportedAbis[0].toLowerCase();
      _hostCpu = abi;
      if (abi.contains("x86_64")) _selectedArch = "x86_64";
      else if (abi.contains("x86")) _selectedArch = "x86";
      else if (abi.contains("arm") && !abi.contains("64")) _selectedArch = "arm";
      setState(() {});

      await _checkSELinux();
      await _checkEngineStatus();
      await _refreshScripts();
    } catch (e) { _logMain("[!] Init Error: $e"); }
  }

  Future<void> _checkSELinux() async {
    try {
      var res = await Process.run('su', ['-c', 'getenforce']);
      setState(() => _selinuxPermissive = (res.stdout.toString().trim().toLowerCase() == "permissive"));
    } catch (e) { _logMain("[!] SELinux Check Failed: $e"); }
  }

  Future<void> _toggleSELinux() async {
    String cmd = _selinuxPermissive ? 'setenforce 1' : 'setenforce 0';
    await Process.run('su', ['-c', cmd]);
    await _checkSELinux();
  }

  Future<void> _checkEngineStatus() async {
    bool fiau = await SocuteEngineBuilder.isFiauAvailable();
    bool fmu = await SocuteEngineBuilder.isFmuAvailable();
    setState(() { _fiauReady = fiau; _fmuReady = fmu; });
  }

  Future<void> _refreshScripts() async {
    if (_storageDir == null) return;
    try {
      final scriptDir = Directory("$_storageDir/scripts");
      List<FileSystemEntity> files = scriptDir.listSync();
      var jsFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
      jsFiles.sort((a, b) => a.path.compareTo(b.path));
      
      setState(() => _availableAssets = jsFiles);
      Set<String> checkedNames = _scriptItems.where((i) => i.isChecked).map((i) => i.name).toSet();
      List<ScriptItem> newList = [];

      if (_sslBypassMode) {
        newList.add(ScriptItem(name: "⚡ FIAU Script", virtualType: "fiau", isVirtual: true, description: "Auto-Config Bypass", isChecked: _fiauReady && (checkedNames.contains("⚡ FIAU Script") || _scriptItems.isEmpty)));
        newList.add(ScriptItem(name: "🛡️ FMU Script", virtualType: "fmu", isVirtual: true, description: "Manual Mode", isChecked: _fmuReady && checkedNames.contains("🛡️ FMU Script")));
      }
      for (var f in jsFiles) {
        String name = f.path.split('/').last;
        newList.add(ScriptItem(file: f, name: name, description: "Local File", isChecked: checkedNames.contains(name)));
      }
      setState(() => _scriptItems = newList);
    } catch (e) { _logMain("[!] Load Scripts Error: $e"); }
  }

  void _logMain(String text) {
    if (!mounted) return;
    String line = text.endsWith('\n') ? text : "$text\n";
    setState(() => _logs += line);
    _historyExecFile?.writeAsStringSync(line, mode: FileMode.append);
  }

  void _logRuntime(String text) {
    if (!mounted) return;
    String line = text.endsWith('\n') ? text : "$text\n";
    setState(() => _runtimeLogs += line);
    _historyRuntimeFile?.writeAsStringSync(line, mode: FileMode.append);
  }

  Future<void> _downloadBinary(BuildContext ctx) async {
    Navigator.pop(ctx);
    if (_storageDir == null) return;
    try {
      _logMain("[*] Downloading Frida...");
      String ver = _fridaVersionCtrl.text;
      String url = "https://github.com/frida/frida/releases/download/$ver/frida-inject-$ver-android-$_selectedArch.xz";
      String tempPath = "$_storageDir/temp.xz";
      await Dio().download(url, tempPath);
      List<int> xzBytes = File(tempPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      File("$_storageDir/frida-inject")..createSync()..writeAsBytesSync(tarBytes);
      File(tempPath).deleteSync();
      _logMain("[OK] Binary $_selectedArch ($ver) Installed!");
    } catch (e) { _logMain("[!] Download Failed: $e"); }
  }

  // --- LAUNCH LOGIC (v2.6.2 - TRUE PTY IMPLEMENTATION) ---
  Future<void> _launchSequence() async {
    if (_targetPackage.isEmpty) { _logMain("[!] Select target app first!"); return; }
    File binary = File("$_storageDir/frida-inject");
    if (!binary.existsSync()) { _logMain("[!] Binary missing. Download first."); return; }

    try {
       var res = await Process.run('su', ['-c', 'pidof $_targetPackage']);
       if (res.stdout.toString().trim().isNotEmpty) {
         _logMain("[!] WARNING: $_targetPackage is already running.");
         _logMain("[*] Recommended: Force Stop app first.");
       }
    } catch(e) {}

    if (!_selinuxPermissive) {
      _logMain("[!] WARNING: SELinux is ENFORCING.");
      _logMain("[*] Please turn OFF SELinux for best stability.");
    }

    setState(() { _isRunning = true; _logs = ""; });
    _historyExecFile?.writeAsStringSync("\n=== NEW SESSION ===\n", mode: FileMode.append);
    _logMain("=== STARTING INJECTION v2.6.2 (PTY NATIVE) ===");

    try {
      File executable = File("$_internalDir/frida-bin");
      if (await executable.exists()) await executable.delete();
      await executable.writeAsBytes(await binary.readAsBytes());
      await Process.run('chmod', ['755', executable.path]);

      File payload = File("$_internalDir/payload.js");
      var sink = payload.openWrite();
      int count = 0;

      for (var item in _scriptItems) {
        if (!item.isChecked) continue;
        if (item.isVirtual) {
          if (item.virtualType == "fiau") {
             if (!_fiauReady) { _logMain("[!] Skipped FIAU: Missing."); continue; }
             sink.writeln("\n// --- MODULE: FIAU ---");
             sink.writeln(await SocuteEngineBuilder.generateFiauScript());
          } else if (item.virtualType == "fmu") {
             if (!_fmuReady) { _logMain("[!] Skipped FMU: Missing."); continue; }
             sink.writeln("\n// --- MODULE: FMU ---");
             sink.writeln(await SocuteEngineBuilder.generateFmuScript());
          }
          count++;
        } else {
          sink.writeln('\n// --- FILE: ${item.name} ---');
          sink.writeln(item.file!.readAsStringSync());
          count++;
        }
      }
      await sink.close();
      _logMain("[*] Merged $count modules.");

      _logMain("[*] Allocating Pseudo-Terminal (PTY)...");
      
      // [CORE] PTY START
      // Kita jalankan 'su' di dalam terminal palsu.
      // Frida akan melihat ini sebagai Terminal Asli, jadi flag -i akan bekerja.
      _mainPty = PseudoTerminal.start(
        'su', 
        [], 
        blocking: false
      );

      // Listen Output dari PTY (Stream<Uint8List>)
      _mainPty!.out
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
             if (line.trim().isEmpty) return;
             if (line.contains("[RT]")) {
                // Runtime Log
                String clean = line.replaceAll("[RT]", "").trim();
                _logRuntime(clean);
             } else {
                // System Log
                _logMain(line);
             }
      });

      // [CORE] Jalankan Frida di dalam shell 'su' yang sudah terbuka di PTY
      String cmd = "${executable.path} -f $_targetPackage -s ${payload.path} -i";
      _logMain("[*] Sending command to PTY: $cmd");
      
      // Tulis perintah + Enter (\n)
      _mainPty!.write(cmd + "\n");

    } catch (e) {
      _logMain("[!!!] LAUNCH FAILED: $e");
      setState(() => _isRunning = false);
    }
  }

  // [CORE] RUNTIME INJECT VIA PTY WRITE
  Future<void> _injectRuntime() async {
    if (!_isRunning || _mainPty == null) { 
        _logMain("[!] Error: Session not active."); return; 
    }
    if (_selectedRuntimeScript == null) { 
        _logRuntime("[!] Select script first."); return; 
    }

    setState(() => _isRuntimeRunning = true);
    _logRuntime("\n>>> INJECTING: ${_selectedRuntimeScript!.path.split('/').last}");

    try {
      String rawCode = await _selectedRuntimeScript!.readAsString();
      String b64Code = base64Encode(utf8.encode(rawCode));

      // WRAPPER dengan ADVANCED LOGGER SHIM
      String wrapper = '''
(function() {
    try {
        if (!globalThis.hasShim) {
            var _l = console.log;
            var _e = console.error;
            function fmt(args) {
                var items = [];
                for(var i=0; i<args.length; i++) {
                    var a = args[i];
                    if (typeof a === 'object' && a !== null) {
                        try { items.push(JSON.stringify(a)); } catch(e){ items.push(a.toString()); }
                    } else { items.push(a); }
                }
                return items.join(" ");
            }
            console.log = function() { _l("[RT] " + fmt(arguments)); };
            console.error = function() { _e("[RT] [ERR] " + fmt(arguments)); };
            globalThis.hasShim = true;
        }

        var b64 = "$b64Code";
        var dec = "";
        if (typeof atob === 'function') { dec = atob(b64); } 
        else {
            var B = Java.use("android.util.Base64");
            var b = B.decode(b64, 0);
            var S = Java.use("java.lang.String");
            dec = S.\$new(b).toString();
        }
        
        console.log("Executing " + dec.length + " bytes...");
        (1, eval)(dec);
        
    } catch(e) { console.error("PTY FAIL: " + e); }
})();
''';
      // Flatten
      String oneLiner = wrapper.replaceAll('\n', ' ');
      
      // [CORE] WRITE TO PTY (Seperti mengetik manual di terminal)
      _mainPty!.write(oneLiner + "\n");
      
    } catch (e) {
      _logRuntime("[!] Injection Failed: $e");
    } finally {
      setState(() => _isRuntimeRunning = false);
    }
  }

  void _stopSequence() async {
    // Kill PTY Object
    _mainPty?.kill();
    // Force kill binary just in case
    await Process.run('su', ['-c', 'pkill -f frida-inject']);
    
    if (mounted) setState(() { _isRunning = false; _isRuntimeRunning = false; _mainPty = null; });
    _logMain("[*] Session Ended.");
  }

  void _viewPayload() async {
    File p = File("$_internalDir/payload.js");
    if (p.existsSync()) {
        String content = await p.readAsString();
        if(mounted) showDialog(context: context, builder: (_) => PayloadViewerDialog(code: content));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("SoCute v2.6.2", style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.grey[900],
        actions: [
          IconButton(icon: const Icon(Icons.info_outline), onPressed: _showAbout),
          IconButton(icon: const Icon(Icons.settings_ethernet), onPressed: () => showModalBottomSheet(context: context, builder: (c) => _buildDownloader(c))),
          IconButton(icon: const Icon(Icons.folder_open), onPressed: () {
            Navigator.push(context, MaterialPageRoute(builder: (c) => ScriptManagerPage(storageDir: _storageDir!)))
              .then((_) => _refreshScripts());
          }),
        ],
      ),
      body: SingleChildScrollView( 
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // 1. SELINUX STATUS & RECOMMENDATION
              Card(
                color: _selinuxPermissive ? Colors.red[900]!.withOpacity(0.5) : Colors.green[900]!.withOpacity(0.5),
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Row(
                    children: [
                      Icon(Icons.security, color: _selinuxPermissive ? Colors.redAccent : Colors.greenAccent),
                      const SizedBox(width: 15),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text("SELinux Status", style: TextStyle(color: Colors.white, fontSize: 12)),
                          Text(_selinuxPermissive ? "PERMISSIVE (OFF)" : "ENFORCING (ON)", style: TextStyle(color: _selinuxPermissive ? Colors.redAccent : Colors.greenAccent, fontWeight: FontWeight.bold)),
                          if (!_selinuxPermissive)
                             Text("Please turn OFF for best stability", style: TextStyle(color: Colors.orange, fontSize: 10, fontStyle: FontStyle.italic))
                        ],
                      ),
                      const Spacer(),
                      Switch(
                        value: _selinuxPermissive, 
                        activeColor: Colors.red,
                        activeTrackColor: Colors.red[900],
                        inactiveThumbColor: Colors.green,
                        inactiveTrackColor: Colors.green[900],
                        onChanged: (v) => _toggleSELinux()
                      )
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),

              // 2. TARGET CARD
              Card(
                color: Colors.grey[900],
                child: ListTile(
                  title: Text(_targetName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  subtitle: Text(_targetPackage.isEmpty ? "Tap to select target" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                  trailing: const Icon(Icons.touch_app, color: Colors.blueAccent),
                  onTap: _isRunning ? null : _pickApp,
                ),
              ),

              // 3. SSL BYPASS TOGGLE
              SwitchListTile(
                title: const Text("Enable SSL Bypass Mode", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                subtitle: const Text("Activate advanced interceptors (FIAU/FMU)", style: TextStyle(color: Colors.grey, fontSize: 11)),
                value: _sslBypassMode,
                activeColor: Colors.orange,
                onChanged: _isRunning ? null : (v) => setState(() { _sslBypassMode = v; _refreshScripts(); }),
              ),

              // 4. TABS AREA
              AnimatedCrossFade(
                firstChild: Container(),
                secondChild: _buildTabsArea(),
                crossFadeState: _sslBypassMode ? CrossFadeState.showSecond : CrossFadeState.showFirst,
                duration: const Duration(milliseconds: 300),
              ),

              // 5. PAYLOAD COMPOSER
              const SizedBox(height: 15),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: const [
                  Text("Payload Composer", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  Text("Drag to reorder", style: TextStyle(color: Colors.grey, fontSize: 11)),
                ]),
              ),
              Container(
                height: 200,
                decoration: BoxDecoration(color: Colors.grey[900], borderRadius: BorderRadius.circular(5), border: Border.all(color: Colors.white10)),
                child: Scrollbar(
                  thumbVisibility: true,
                  child: ReorderableListView(
                    padding: const EdgeInsets.all(5),
                    onReorder: (oldIndex, newIndex) {
                      setState(() {
                        if (newIndex > oldIndex) newIndex -= 1;
                        final item = _scriptItems.removeAt(oldIndex);
                        _scriptItems.insert(newIndex, item);
                      });
                    },
                    children: [
                      for (int i = 0; i < _scriptItems.length; i++)
                        ListTile(
                          key: ValueKey("item_${_scriptItems[i].name}_$i"),
                          dense: true,
                          tileColor: _scriptItems[i].isVirtual 
                            ? (_scriptItems[i].virtualType == 'fiau' ? Colors.orange.withOpacity(0.1) : Colors.cyan.withOpacity(0.1))
                            : Colors.black12,
                          leading: Icon(Icons.drag_handle, color: Colors.grey),
                          title: Text(_scriptItems[i].name, style: TextStyle(color: _scriptItems[i].isVirtual ? (_scriptItems[i].virtualType == 'fiau' ? Colors.orangeAccent : Colors.cyanAccent) : Colors.white, fontWeight: _scriptItems[i].isVirtual ? FontWeight.bold : FontWeight.normal)),
                          subtitle: Text(_scriptItems[i].description, style: const TextStyle(fontSize: 10, color: Colors.grey)),
                          trailing: Checkbox(value: _scriptItems[i].isChecked, activeColor: Colors.green, onChanged: _isRunning ? null : (v) => setState(() => _scriptItems[i].isChecked = v!)),
                        )
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 10),

              // 6. LAUNCH BUTTON
              ElevatedButton(
                style: ElevatedButton.styleFrom(backgroundColor: _isRunning ? Colors.red[900] : Colors.greenAccent[700], padding: const EdgeInsets.symmetric(vertical: 15)),
                onPressed: _isRunning ? _stopSequence : _launchSequence,
                child: Text(_isRunning ? "STOP SESSION" : "LAUNCH (PTY)", style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
              ),

              // 7. SYSTEM LOGS
              const SizedBox(height: 20),
              _buildLogToolbar("System Logs", _logs, onClear: () => setState(() => _logs = ""), onViewPayload: _viewPayload, historyFile: _historyExecFile),
              Container(
                height: 200,
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.green.withOpacity(0.3))),
                child: SingleChildScrollView(
                  reverse: true,
                  child: SelectableText(_logs, style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 11)),
                ),
              ),

              const Divider(color: Colors.white24, height: 40),

              // 8. RUNTIME INJECTOR
              const Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text("Runtime Injector", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                  Text("PTY Native Injection (Base64 Safe Mode)", style: TextStyle(color: Colors.grey, fontSize: 11)),
              ]),
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    child: DropdownButtonFormField<File>(
                      decoration: const InputDecoration(filled: true, fillColor: Colors.white10, contentPadding: EdgeInsets.symmetric(horizontal: 10, vertical: 0)),
                      dropdownColor: Colors.grey[900],
                      value: _selectedRuntimeScript,
                      hint: const Text("Select Script", style: TextStyle(color: Colors.grey)),
                      items: _availableAssets.map((f) => DropdownMenuItem(value: f, child: Text(f.path.split('/').last, style: const TextStyle(color: Colors.white, fontSize: 12)))).toList(),
                      onChanged: (v) => setState(() => _selectedRuntimeScript = v),
                    ),
                  ),
                  const SizedBox(width: 10),
                  ElevatedButton(
                    onPressed: _isRunning && !_isRuntimeRunning ? _injectRuntime : null,
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.blueAccent),
                    child: _isRuntimeRunning 
                      ? const SizedBox(width: 15, height: 15, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2)) 
                      : const Text("INJECT"),
                  )
                ],
              ),
              const SizedBox(height: 10),
              _buildLogToolbar("Runtime Output", _runtimeLogs, onClear: () => setState(() => _runtimeLogs = ""), historyFile: _historyRuntimeFile, isRuntime: true),
              Container(
                height: 150,
                width: double.infinity,
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.cyan.withOpacity(0.3))), 
                child: SingleChildScrollView(
                  reverse: true,
                  child: SelectableText(_runtimeLogs, style: const TextStyle(color: Colors.cyanAccent, fontFamily: 'monospace', fontSize: 11)),
                ),
              ),
              SizedBox(height: MediaQuery.of(context).size.height * 0.4),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTabsArea() {
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(border: Border.all(color: Colors.white10), borderRadius: BorderRadius.circular(5)),
      child: Column(
        children: [
          Container(color: Colors.grey[900], child: Column(children: [TabBar(controller: _tabController, indicatorColor: Colors.orange, labelColor: Colors.orange, unselectedLabelColor: Colors.grey, tabs: const [Tab(text: "⚡ FIAU"), Tab(text: "🛡️ FMU")])])),
          SizedBox(height: 180, child: TabBarView(controller: _tabController, children: [
            Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const Text("Auto-Config Injection", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)), const Spacer(), Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [Text(_fiauReady ? "Script: Ready" : "Script: Missing", style: TextStyle(color: _fiauReady ? Colors.green : Colors.red, fontSize: 12)), ElevatedButton.icon(icon: const Icon(Icons.settings, size: 16), label: const Text("Configure"), style: ElevatedButton.styleFrom(backgroundColor: Colors.orange.withOpacity(0.2), foregroundColor: Colors.orange), onPressed: () async { await showDialog(context: context, builder: (ctx) => const ConfigDialog()); _checkEngineStatus(); })])])),
            Padding(padding: const EdgeInsets.all(12), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const Text("System-Relied Unpinning", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)), const Spacer(), Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [Text(_fmuReady ? "Script: Ready" : "Script: Missing", style: TextStyle(color: _fmuReady ? Colors.green : Colors.red, fontSize: 12)), ElevatedButton.icon(icon: const Icon(Icons.download, size: 16), label: const Text("Update FMU"), style: ElevatedButton.styleFrom(backgroundColor: Colors.cyan.withOpacity(0.2), foregroundColor: Colors.cyan), onPressed: () async { try { await SocuteEngineBuilder.downloadScript(SocuteEngineBuilder.FMU_URL, SocuteEngineBuilder.FMU_FILENAME); setState(() => _fmuReady = true); ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("FMU Script Updated!"))); } catch (e) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Error: $e"), backgroundColor: Colors.red)); } })])])),
          ]))
        ],
      ),
    );
  }

  Widget _buildLogToolbar(String title, String content, {required VoidCallback onClear, VoidCallback? onViewPayload, File? historyFile, bool isRuntime = false}) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(title, style: const TextStyle(color: Colors.white, fontSize: 12)),
        Row(
          children: [
            if (onViewPayload != null) IconButton(icon: const Icon(Icons.description, color: Colors.yellow, size: 18), onPressed: (_isRunning) ? onViewPayload : null, tooltip: "View Payload"),
            if (historyFile != null) IconButton(icon: const Icon(Icons.save, color: Colors.purpleAccent, size: 18), onPressed: () => showDialog(context: context, builder: (_) => LogHistoryViewer(file: historyFile, title: title)), tooltip: "Save/View"),
            IconButton(icon: const Icon(Icons.copy, color: Colors.blue, size: 18), onPressed: () => Clipboard.setData(ClipboardData(text: content))),
            IconButton(icon: const Icon(Icons.delete_sweep, color: Colors.red, size: 18), onPressed: onClear),
            IconButton(icon: const Icon(Icons.fullscreen, color: Colors.white, size: 18), onPressed: () => showDialog(context: context, builder: (c) => Dialog(backgroundColor: Colors.black, child: Stack(children: [
              Container(
                  width: double.infinity, height: double.infinity,
                  padding: const EdgeInsets.all(15),
                  decoration: BoxDecoration(border: Border.all(color: isRuntime ? Colors.cyan : Colors.green)),
                  child: SelectableText(content, style: TextStyle(color: isRuntime ? Colors.cyanAccent : Colors.greenAccent, fontFamily: 'monospace'))
              ),
              Positioned(right: 0, top: 0, child: IconButton(icon: const Icon(Icons.close, color: Colors.white), onPressed: () => Navigator.pop(c)))
            ])))),
          ],
        )
      ],
    );
  }

  void _showAbout() {
    showDialog(context: context, builder: (ctx) => AlertDialog(backgroundColor: Colors.grey[900], title: const Text("SoCute v2.6.2", style: TextStyle(color: Colors.white)), content: const Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
       Text("Credits:", style: TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)),
       Text("• Frida: frida.re", style: TextStyle(color: Colors.grey)),
       Text("• FIAU: github.com/httptoolkit", style: TextStyle(color: Colors.grey)),
       Text("• FMU: codeshare.frida.re/@akabe1", style: TextStyle(color: Colors.grey)),
       Text("• SoCute: Milio48", style: TextStyle(color: Colors.grey)),
       SizedBox(height: 10),
       Text("License: AGPL-3.0", style: TextStyle(color: Colors.orangeAccent)),
       Text("Build: 2024-PTY-NATIVE", style: TextStyle(color: Colors.grey, fontSize: 10)),
    ]), actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("CLOSE"))]));
  }

  Widget _buildDownloader(BuildContext ctx) {
    bool isBinaryReady = File("$_storageDir/frida-inject").existsSync();
    return Padding(padding: const EdgeInsets.all(20), child: Column(mainAxisSize: MainAxisSize.min, children: [
       const Text("Binary Downloader", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
       Text("Host CPU: $_hostCpu", style: TextStyle(color: Colors.grey, fontSize: 12)),
       Text("Status: ${isBinaryReady ? "READY" : "MISSING"}", style: TextStyle(color: isBinaryReady ? Colors.green : Colors.red, fontWeight: FontWeight.bold)),
       const SizedBox(height: 10),
       DropdownButtonFormField(value: _selectedArch, items: _archOptions.map((a) => DropdownMenuItem(value: a, child: Text(a))).toList(), onChanged: (v) => setState(() => _selectedArch = v.toString())),
       TextField(controller: _fridaVersionCtrl, decoration: const InputDecoration(labelText: "Frida Version", hintText: "e.g. 17.5.2")),
       const SizedBox(height: 20),
       ElevatedButton(onPressed: () => _downloadBinary(ctx), child: const Text("DOWNLOAD")),
       const SizedBox(height: 20),
    ]));
  }

  void _pickApp() async {
    List<Application> apps = await DeviceApps.getInstalledApplications(includeAppIcons: true);
    showDialog(context: context, builder: (ctx) => AlertDialog(title: const Text("Select Target"), content: SizedBox(width: double.maxFinite, height: 400, child: ListView.builder(itemCount: apps.length, itemBuilder: (c, i) => ListTile(leading: apps[i] is ApplicationWithIcon ? Image.memory((apps[i] as ApplicationWithIcon).icon, width: 32) : null, title: Text(apps[i].appName), subtitle: Text(apps[i].packageName, style: const TextStyle(fontSize: 10)), onTap: () { setState(() { _targetName = apps[i].appName; _targetPackage = apps[i].packageName; }); Navigator.pop(ctx); })))));
  }
}

// ==========================================
// DIALOGS & MANAGERS
// ==========================================
class ConfigDialog extends StatefulWidget { const ConfigDialog({super.key}); @override State<ConfigDialog> createState() => _ConfigDialogState(); }
class _ConfigDialogState extends State<ConfigDialog> {
  final _certCtrl = TextEditingController(); final _ipCtrl = TextEditingController(); final _portCtrl = TextEditingController(); final _ignoredCtrl = TextEditingController();
  bool _debug = false; bool _blockHttp3 = true; bool _socks5 = false;
  @override void initState() { super.initState(); _loadPrefs(); }
  void _loadPrefs() async { final prefs = await SharedPreferences.getInstance(); setState(() { _certCtrl.text = prefs.getString('cfg_cert') ?? ""; _ipCtrl.text = prefs.getString('cfg_ip') ?? ""; _portCtrl.text = prefs.getString('cfg_port') ?? ""; _ignoredCtrl.text = prefs.getString('cfg_ignored') ?? ""; _debug = prefs.getBool('cfg_debug') ?? false; _blockHttp3 = prefs.getBool('cfg_http3') ?? true; _socks5 = prefs.getBool('cfg_socks5') ?? false; }); }
  void _save() async { final prefs = await SharedPreferences.getInstance(); await prefs.setString('cfg_cert', _certCtrl.text); await prefs.setString('cfg_ip', _ipCtrl.text); await prefs.setString('cfg_port', _portCtrl.text); await prefs.setString('cfg_ignored', _ignoredCtrl.text); await prefs.setBool('cfg_debug', _debug); await prefs.setBool('cfg_http3', _blockHttp3); await prefs.setBool('cfg_socks5', _socks5); if(mounted) Navigator.pop(context); }
  void _pickCert() async { FilePickerResult? r = await FilePicker.platform.pickFiles(); if (r!=null) { File f = File(r.files.single.path!); _certCtrl.text = await f.readAsString(); } }
  
  // FIAU DOWNLOADER ACTION
  void _downloadFiau() async {
      try {
          await SocuteEngineBuilder.downloadScript(SocuteEngineBuilder.FIAU_URL, SocuteEngineBuilder.FIAU_FILENAME);
          ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("FIAU Script Downloaded!")));
      } catch (e) {
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Err: $e"), backgroundColor: Colors.red));
      }
  }

  @override Widget build(BuildContext context) { return AlertDialog(backgroundColor: Colors.grey[900], title: const Text("FIAU Config", style: TextStyle(color: Colors.white)), content: SingleChildScrollView(child: Column(children: [
      // [FIX] Button Download restored
      SizedBox(width: double.infinity, child: ElevatedButton.icon(icon: const Icon(Icons.download), label: const Text("Download Latest FIAU Script"), onPressed: _downloadFiau, style: ElevatedButton.styleFrom(backgroundColor: Colors.orange[900]))),
      const SizedBox(height: 10), 
      // [FIX] Hint Text Updated
      TextField(controller: _certCtrl, maxLines: 3, style: const TextStyle(color: Colors.white, fontSize: 10), decoration: InputDecoration(filled: true, fillColor: Colors.black, hintText: "-----BEGIN CERTIFICATE-----\n....\n-----END CERTIFICATE-----", suffixIcon: IconButton(icon: const Icon(Icons.folder), onPressed: _pickCert))), 
      const SizedBox(height: 5), 
      Row(children: [Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Proxy IP", hintText: "192.168.1.x"))), const SizedBox(width: 5), Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Port", hintText: "8080")))]), TextField(controller: _ignoredCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Ignored Ports", hintText: "e.g. 22, 53")), SwitchListTile(title: const Text("Block HTTP/3", style: TextStyle(color: Colors.white)), value: _blockHttp3, onChanged: (v) => setState(() => _blockHttp3 = v)), SwitchListTile(title: const Text("SOCKS5", style: TextStyle(color: Colors.white)), value: _socks5, onChanged: (v) => setState(() => _socks5 = v)), SwitchListTile(title: const Text("Debug", style: TextStyle(color: Colors.white)), value: _debug, onChanged: (v) => setState(() => _debug = v))])), actions: [ElevatedButton(onPressed: _save, child: const Text("SAVE"))]); }
}

class ScriptManagerPage extends StatefulWidget { final String storageDir; const ScriptManagerPage({super.key, required this.storageDir}); @override State<ScriptManagerPage> createState() => _ScriptManagerPageState(); }
class _ScriptManagerPageState extends State<ScriptManagerPage> {
  List<File> _files = []; @override void initState() { super.initState(); _loadFiles(); }
  void _loadFiles() { try { final dir = Directory("${widget.storageDir}/scripts"); setState(() => _files = dir.listSync().whereType<File>().where((f) => f.path.endsWith('.js')).toList()); } catch (e) {} }
  void _deleteFile(File f) { try { f.deleteSync(); _loadFiles(); } catch(e) {} }
  void _goToEditor({File? file}) async { await Navigator.push(context, MaterialPageRoute(builder: (ctx) => ScriptEditorPage(storageDir: widget.storageDir, fileToEdit: file))); _loadFiles(); }
  @override Widget build(BuildContext context) { return Scaffold(backgroundColor: Colors.grey[900], appBar: AppBar(title: const Text("Script Manager"), backgroundColor: Colors.black), floatingActionButton: FloatingActionButton(backgroundColor: Colors.blue, onPressed: () => _goToEditor(), child: const Icon(Icons.add)), body: _files.isEmpty ? const Center(child: Text("No scripts yet.", style: TextStyle(color: Colors.grey))) : ListView.builder(itemCount: _files.length, itemBuilder: (ctx, i) => Card(color: Colors.grey[850], child: ListTile(title: Text(_files[i].path.split('/').last, style: const TextStyle(color: Colors.white)), onTap: () => _goToEditor(file: _files[i]), trailing: IconButton(icon: const Icon(Icons.delete, color: Colors.red), onPressed: () => _deleteFile(_files[i])))))); }
}

// ==========================================
// EDITOR: FIXED LINE NUMBERS (HORIZONTAL SCROLL)
// ==========================================
class ManualLineNumberEditor extends StatefulWidget { final TextEditingController controller; final bool readOnly; const ManualLineNumberEditor({super.key, required this.controller, this.readOnly = false}); @override State<ManualLineNumberEditor> createState() => _ManualLineNumberEditorState(); }
class _ManualLineNumberEditorState extends State<ManualLineNumberEditor> {
  String _lineNumbers = "1";
  @override void initState() { super.initState(); widget.controller.addListener(_updateLineNumbers); _updateLineNumbers(); }
  @override void dispose() { widget.controller.removeListener(_updateLineNumbers); super.dispose(); }
  void _updateLineNumbers() {
    int lines = widget.controller.text.split('\n').length;
    final buffer = StringBuffer(); for (int i = 1; i <= lines; i++) buffer.writeln(i);
    if (buffer.toString().trim() != _lineNumbers.trim()) setState(() => _lineNumbers = buffer.toString());
  }
  @override Widget build(BuildContext context) {
    // [FIX] Anti Word Wrap Logic: SingleChildScrollView(Horizontal) -> SizedBox(Large Width)
    const textStyle = TextStyle(fontFamily: 'monospace', fontSize: 13, height: 1.2);
    return Container(color: const Color(0xFF1E1E1E), child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 10), color: const Color(0xFF2D2D2D), child: Text(_lineNumbers, textAlign: TextAlign.right, style: textStyle.copyWith(color: Colors.grey))),
        Expanded(
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: SizedBox(
              width: 10000, // Very wide to prevent wrapping
              child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 0),
                  child: TextField(
                      controller: widget.controller,
                      maxLines: null,
                      readOnly: widget.readOnly,
                      style: textStyle.copyWith(color: Colors.greenAccent),
                      decoration: const InputDecoration(border: InputBorder.none, contentPadding: EdgeInsets.only(top: 10, bottom: 10))
                  )
              ),
            ),
          )
        )
    ]));
  }
}

class ScriptEditorPage extends StatefulWidget { final String storageDir; final File? fileToEdit; const ScriptEditorPage({super.key, required this.storageDir, this.fileToEdit}); @override State<ScriptEditorPage> createState() => _ScriptEditorPageState(); }
class _ScriptEditorPageState extends State<ScriptEditorPage> {
  final _nameCtrl = TextEditingController(); final _contentCtrl = TextEditingController();
  @override void initState() { super.initState(); _contentCtrl.text = "// Paste script here..."; if (widget.fileToEdit != null) { _nameCtrl.text = widget.fileToEdit!.path.split('/').last; _contentCtrl.text = widget.fileToEdit!.readAsStringSync(); } }
  void _save() { String name = _nameCtrl.text.trim(); if (!name.endsWith(".js")) name += ".js"; if (name.isEmpty || name == ".js") return; File f = File("${widget.storageDir}/scripts/$name"); f.writeAsStringSync(_contentCtrl.text); Navigator.pop(context); }
  @override Widget build(BuildContext context) { return Scaffold(backgroundColor: Colors.black, appBar: AppBar(title: Text(widget.fileToEdit == null ? "New Script" : "Edit Script"), backgroundColor: Colors.grey[900], actions: [IconButton(icon: const Icon(Icons.save), onPressed: _save)]), body: Column(children: [Padding(padding: const EdgeInsets.all(8.0), child: TextField(controller: _nameCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Filename", hintText: "myscript.js"))), Expanded(child: ManualLineNumberEditor(controller: _contentCtrl))])); }
}

class PayloadViewerDialog extends StatelessWidget { final String code; const PayloadViewerDialog({super.key, required this.code});
  @override Widget build(BuildContext context) { return Dialog(backgroundColor: Colors.black, insetPadding: const EdgeInsets.all(10), child: Column(children: [AppBar(backgroundColor: Colors.grey[900], title: const Text("Payload Viewer"), leading: IconButton(icon: const Icon(Icons.close), onPressed: () => Navigator.pop(context))), Expanded(child: ManualLineNumberEditor(controller: TextEditingController(text: code), readOnly: true))])); }
}

class LogHistoryViewer extends StatelessWidget { final File file; final String title; const LogHistoryViewer({super.key, required this.file, this.title = "Log History"});
  @override Widget build(BuildContext context) { 
    String content = file.readAsStringSync();
    return Dialog(backgroundColor: Colors.black, child: Column(children: [
        AppBar(backgroundColor: Colors.grey[900], title: Text(title), actions: [
            IconButton(icon: const Icon(Icons.copy), onPressed: () => Clipboard.setData(ClipboardData(text: content))),
            IconButton(icon: const Icon(Icons.delete), onPressed: () { file.writeAsStringSync(""); Navigator.pop(context); })
        ]), 
        Expanded(child: SingleChildScrollView(child: Padding(padding: const EdgeInsets.all(15), child: SelectableText(content, style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 11)))))
    ])); 
  }
}