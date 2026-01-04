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
  File? file; // Null if virtual (Cloud Script)
  bool isVirtual;
  bool isChecked;
  String name;

  ScriptItem({this.file, this.isVirtual = false, this.isChecked = true, required this.name});
}

// --- ENGINE BUILDER (Logic Core v2.4.1) ---
class SocuteEngineBuilder {
  static const String TEMPLATE_FILENAME = "fiau_template.js";
  static const String RAW_URL = "https://raw.githubusercontent.com/milio48/socute.apk/refs/heads/main/fiau-by-httptoolkit.js";

  static Future<bool> isTemplateAvailable() async {
    final dir = await getApplicationDocumentsDirectory();
    return File("${dir.path}/$TEMPLATE_FILENAME").exists();
  }

  static Future<void> downloadTemplate() async {
    final response = await http.get(Uri.parse(RAW_URL));
    if (response.statusCode == 200) {
      final dir = await getApplicationDocumentsDirectory();
      final file = File("${dir.path}/$TEMPLATE_FILENAME");
      await file.writeAsString(response.body);
    } else {
      throw Exception("Failed to download engine: HTTP ${response.statusCode}");
    }
  }

  static Future<String> generateScript() async {
    final prefs = await SharedPreferences.getInstance();
    final dir = await getApplicationDocumentsDirectory();
    final templateFile = File("${dir.path}/$TEMPLATE_FILENAME");
    
    if (!await templateFile.exists()) return ""; 

    String content = await templateFile.readAsString();
    
    // Get Config from storage
    String cert = prefs.getString('cfg_cert') ?? "";
    String ip = prefs.getString('cfg_ip') ?? "127.0.0.1";
    String port = prefs.getString('cfg_port') ?? "8080";
    bool debug = prefs.getBool('cfg_debug') ?? false;
    bool blockHttp3 = prefs.getBool('cfg_http3') ?? true;
    
    // Advanced Configs
    String ignoredPortsRaw = prefs.getString('cfg_ignored') ?? "";
    bool socks5 = prefs.getBool('cfg_socks5') ?? false;

    // Convert "22, 53" -> "[22, 53]"
    String ignoredPortsJson = ignoredPortsRaw.trim().isEmpty ? "[]" : "[${ignoredPortsRaw}]";

    // Replace Placeholders
    final replacements = {
      '{{SOCUTE_CERT_PEM}}': cert,
      '{{SOCUTE_PROXY_HOST}}': ip,
      '{{SOCUTE_PROXY_PORT}}': port,
      '{{SOCUTE_DEBUG_MODE}}': debug.toString(),
      '{{SOCUTE_BLOCK_HTTP3}}': blockHttp3.toString(),
      '{{SOCUTE_IGNORED_PORTS}}': ignoredPortsJson,
      '{{SOCUTE_SOCKS5_SUPPORT}}': socks5.toString(),
    };

    replacements.forEach((key, val) {
      content = content.replaceAll(key, val);
    });

    return content;
  }
}

// ==========================================
// PAGE 1: LAUNCHER (THE COCKPIT)
// ==========================================
class LauncherPage extends StatefulWidget {
  const LauncherPage({super.key});
  @override
  State<LauncherPage> createState() => _LauncherPageState();
}

class _LauncherPageState extends State<LauncherPage> {
  // Logs & Process
  String _logs = "Initializing SoCute v2.4 (Cloud Engine)...";
  bool _isRunning = false;
  Process? _runningProcess;

  // Target
  String _targetPackage = "";
  String _targetName = "Select Target App";

  // Launch Config
  bool _disableSELinux = false; 
  
  // Downloader Config
  final TextEditingController _fridaVersionCtrl = TextEditingController(text: "17.5.2");
  String _selectedArch = "arm64"; 
  final List<String> _archOptions = ["arm64", "arm", "x86", "x86_64"];

  // Script Data
  List<ScriptItem> _scriptItems = [];
  String? _storageDir;  
  String? _internalDir; 
  bool _isEngineReady = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initSystem());
  }

  Future<void> _initSystem() async {
    try {
      final extDir = await getExternalStorageDirectory();
      final intDir = await getApplicationSupportDirectory();
      _storageDir = extDir!.path;
      _internalDir = intDir.path;

      await Directory("$_storageDir/scripts").create(recursive: true);

      // Auto Detect Arch
      var androidInfo = await DeviceInfoPlugin().androidInfo;
      var abi = androidInfo.supportedAbis[0].toLowerCase();
      String detected = "arm64";
      if (abi.contains("arm") && !abi.contains("64")) detected = "arm";
      setState(() => _selectedArch = detected);

      await _checkEngineStatus();
      await _refreshScripts();
    } catch (e) {
      _log("[!] Init Error: $e");
    }
  }

  Future<void> _checkEngineStatus() async {
    bool ready = await SocuteEngineBuilder.isTemplateAvailable();
    setState(() => _isEngineReady = ready);
  }

  Future<void> _refreshScripts() async {
    if (_storageDir == null) return;
    try {
      final scriptDir = Directory("$_storageDir/scripts");
      List<FileSystemEntity> files = scriptDir.listSync();
      var jsFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
      jsFiles.sort((a, b) => a.path.compareTo(b.path));

      // Preserve check states
      Set<String> checkedNames = _scriptItems.where((i) => i.isChecked).map((i) => i.name).toSet();
      
      List<ScriptItem> newList = [];

      // 1. Add VIRTUAL ITEM (FIAU)
      newList.add(ScriptItem(
        name: "⚡ Universal Interceptor (Configured)",
        isVirtual: true,
        isChecked: _isEngineReady && (checkedNames.contains("⚡ Universal Interceptor (Configured)") || _scriptItems.isEmpty)
      ));

      // 2. Add FILE ITEMS
      for (var f in jsFiles) {
        String name = f.path.split('/').last;
        newList.add(ScriptItem(
          file: f,
          name: name,
          isChecked: checkedNames.contains(name)
        ));
      }

      setState(() => _scriptItems = newList);
    } catch (e) {
      _log("[!] Load Scripts Error: $e");
    }
  }

  Future<void> _downloadBinary(BuildContext ctx) async {
    if (_storageDir == null) return;
    Navigator.pop(ctx);
    try {
      _log("[*] Downloading Frida...");
      String ver = _fridaVersionCtrl.text;
      String url = "https://github.com/frida/frida/releases/download/$ver/frida-inject-$ver-android-$_selectedArch.xz";
      String tempPath = "$_storageDir/temp.xz";
      await Dio().download(url, tempPath);
      
      List<int> xzBytes = File(tempPath).readAsBytesSync();
      List<int> tarBytes = XZDecoder().decodeBytes(xzBytes);
      
      File("$_storageDir/frida-inject")
        ..createSync()
        ..writeAsBytesSync(tarBytes);
      
      File(tempPath).deleteSync();
      _log("[OK] Binary $_selectedArch ($ver) Installed!");
      setState(() {});
    } catch (e) {
      _log("[!] Download Failed: $e");
    }
  }

  Future<void> _launchSequence() async {
    if (_targetPackage.isEmpty) { _log("[!] Select target app first!"); return; }
    File binary = File("$_storageDir/frida-inject");
    if (!binary.existsSync()) { _log("[!] Binary missing. Download first."); return; }

    setState(() => _isRunning = true);
    _log("\n=== STARTING INJECTION ===");

    try {
      if (_disableSELinux) {
        await Process.run('su', ['-c', 'setenforce 0']);
        _log("[*] SELinux Disabled.");
      }

      File executable = File("$_internalDir/frida-bin");
      if (await executable.exists()) await executable.delete();
      await executable.writeAsBytes(await binary.readAsBytes());
      await Process.run('chmod', ['755', executable.path]);

      // --- MERGER LOGIC V2 ---
      File payload = File("$_internalDir/payload.js");
      var sink = payload.openWrite();

      int count = 0;
      for (var item in _scriptItems) {
        if (!item.isChecked) continue;

        if (item.isVirtual) {
          if (!_isEngineReady) {
            _log("[!] Skipping Interceptor: Engine not downloaded.");
            continue;
          }
          _log("[+] Generating Universal Interceptor Payload...");
          String fiauScript = await SocuteEngineBuilder.generateScript();
          sink.writeln("\n// --- MODULE: UNIVERSAL INTERCEPTOR ---");
          sink.writeln(fiauScript);
          count++;
        } else {
          sink.writeln('\n// --- FILE: ${item.name} ---');
          sink.writeln(item.file!.readAsStringSync());
          count++;
        }
      }
      await sink.close();
      _log("[*] Merged $count scripts/modules.");

      // EXECUTE
      _log("[*] Spawning $_targetPackage...");
      String cmd = "${executable.path} -f $_targetPackage -s ${payload.path}";
      _runningProcess = await Process.start('su', ['-c', cmd]);

      _runningProcess!.stdout.transform(utf8.decoder).listen((d) => _log(d.trim()));
      _runningProcess!.stderr.transform(utf8.decoder).listen((d) => _log("[ERR] ${d.trim()}"));

    } catch (e) {
      _log("[!!!] LAUNCH FAILED: $e");
      setState(() => _isRunning = false);
    }
  }

  void _log(String text) {
    if (!mounted) return;
    setState(() => _logs += "\n$text");
  }

  void _openConfigDialog() async {
    await showDialog(context: context, builder: (ctx) => const ConfigDialog());
    await _checkEngineStatus();
    _refreshScripts();
  }

  void _stopSequence() async {
    _runningProcess?.kill();
    await Process.run('su', ['-c', 'pkill -f frida-inject']);
    setState(() { _isRunning = false; _runningProcess = null; });
    _log("[*] Process Killed.");
  }

  // --- UI START ---
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("SoCute v2.4", style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.grey[900],
        actions: [
          // MENU ABOUT (Revised with Credits)
          IconButton(
            icon: const Icon(Icons.info_outline), 
            onPressed: () => showDialog(
              context: context, 
              builder: (ctx) => AlertDialog(
                backgroundColor: Colors.grey[900],
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10), side: const BorderSide(color: Colors.white10)),
                title: Row(children: [
                  const Icon(Icons.adb, color: Colors.green), 
                  const SizedBox(width: 10),
                  const Text("About SoCute", style: TextStyle(color: Colors.white))
                ]),
                content: SingleChildScrollView(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text("Version: v2.4 (Cloud Engine)", style: TextStyle(color: Colors.greenAccent, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 5),
                      const Text("Advanced Frida Injector GUI for Android security research.", style: TextStyle(color: Colors.grey, fontSize: 12)),
                      const SizedBox(height: 15),
                      const Text("License:", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                      const Text("AGPL-3.0-or-later", style: TextStyle(color: Colors.orangeAccent, fontFamily: 'monospace')),
                      const Divider(color: Colors.white24, height: 20),
                      const Text("Credits & Libraries:", style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 10),
                      _buildCreditItem(Icons.code, "Milio48 (SoCute)", "github.com/milio48/socute.apk"),
                      _buildCreditItem(Icons.memory, "Frida Core", "frida.re"),
                      _buildCreditItem(Icons.security, "FIAU Script", "github.com/httptoolkit"),
                    ],
                  ),
                ),
                actions: [
                  TextButton(onPressed: () => Navigator.pop(ctx), child: const Text("CLOSE", style: TextStyle(color: Colors.blue)))
                ],
              )
            )
          ),
          IconButton(icon: const Icon(Icons.settings_ethernet), onPressed: () => showModalBottomSheet(context: context, builder: (c) => _buildDownloader(c))),
          IconButton(icon: const Icon(Icons.folder_open), onPressed: () {
            Navigator.push(context, MaterialPageRoute(builder: (c) => ScriptManagerPage(storageDir: _storageDir!)))
              .then((_) => _refreshScripts());
          }),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // TARGET CARD
            Card(
              color: Colors.grey[900],
              child: ListTile(
                title: Text(_targetName, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                subtitle: Text(_targetPackage.isEmpty ? "Tap to select target" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                trailing: const Icon(Icons.touch_app, color: Colors.blueAccent),
                onTap: _isRunning ? null : _pickApp,
              ),
            ),

            // PAYLOAD HEADER
            const SizedBox(height: 10),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text("Payload Composer", style: TextStyle(color: Colors.grey, fontSize: 12)),
                TextButton.icon(
                  onPressed: _openConfigDialog, 
                  icon: const Icon(Icons.settings, size: 16),
                  label: const Text("Config Interceptor"),
                  style: TextButton.styleFrom(foregroundColor: Colors.orangeAccent),
                )
              ],
            ),

            // COMPOSER LIST
            Expanded( // Gunakan Expanded agar list ini mengisi ruang sisa
              child: Container(
                margin: const EdgeInsets.only(bottom: 10),
                decoration: BoxDecoration(color: Colors.grey[900], borderRadius: BorderRadius.circular(5), border: Border.all(color: Colors.white10)),
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
                        key: ValueKey("item_$i"),
                        dense: true,
                        tileColor: _scriptItems[i].isVirtual ? Colors.blue.withOpacity(0.1) : Colors.black12,
                        leading: Icon(Icons.drag_handle, color: _scriptItems[i].isVirtual ? Colors.orange : Colors.grey),
                        title: Text(
                          _scriptItems[i].name, 
                          style: TextStyle(
                            color: _scriptItems[i].isVirtual ? Colors.orangeAccent : Colors.white,
                            fontWeight: _scriptItems[i].isVirtual ? FontWeight.bold : FontWeight.normal
                          )
                        ),
                        trailing: Checkbox(
                          value: _scriptItems[i].isChecked,
                          activeColor: Colors.green,
                          onChanged: _isRunning || (_scriptItems[i].isVirtual && !_isEngineReady) 
                            ? null 
                            : (v) => setState(() => _scriptItems[i].isChecked = v!),
                        ),
                      )
                  ],
                ),
              ),
            ),

            // LAUNCH TOGGLE
            SwitchListTile(
              title: const Text("Disable SELinux (Anti-Crash)", style: TextStyle(color: Colors.orangeAccent)),
              subtitle: const Text("Prevents reboots on Android 13/14", style: TextStyle(color: Colors.grey, fontSize: 10)),
              value: _disableSELinux, activeColor: Colors.orange,
              contentPadding: EdgeInsets.zero,
              onChanged: _isRunning ? null : (v) => setState(() => _disableSELinux = v),
            ),

            const SizedBox(height: 10),

            // LAUNCH BUTTON
            ElevatedButton(
              style: ElevatedButton.styleFrom(backgroundColor: _isRunning ? Colors.red[900] : Colors.greenAccent[700], padding: const EdgeInsets.symmetric(vertical: 15)),
              onPressed: _isRunning ? _stopSequence : _launchSequence,
              child: Text(_isRunning ? "STOP INJECTION" : "LAUNCH", style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
            ),

            // LOGS VIEW
            const SizedBox(height: 10),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text("Execution Logs:", style: TextStyle(color: Colors.white, fontSize: 12)),
                Row(
                  children: [
                    IconButton(icon: const Icon(Icons.copy, color: Colors.blue, size: 20), onPressed: () => Clipboard.setData(ClipboardData(text: _logs))),
                    IconButton(icon: const Icon(Icons.delete_sweep, color: Colors.red, size: 20), onPressed: () => setState(() => _logs = "")),
                  ],
                )
              ],
            ),
            
            // [UX FIX] Box Log dibuat lebih tinggi
            Container(
              height: 160, 
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.white24)),
              child: SingleChildScrollView(
                reverse: true,
                child: SelectableText(_logs, style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 11)),
              ),
            ),
            
            // [UX FIX] MARGIN BOTTOM YANG LEGA (FOOTER)
            // Ini memastikan log paling bawah bisa naik ke atas
            const SizedBox(height: 50), 
          ],
        ),
      ),
    );
  }

  // Credit Item Helper
  Widget _buildCreditItem(IconData icon, String title, String subtitle) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8.0),
      child: Row(
        children: [
          Icon(icon, size: 16, color: Colors.grey),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(color: Colors.white, fontSize: 13)),
                Text(subtitle, style: const TextStyle(color: Colors.grey, fontSize: 11)),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildDownloader(BuildContext ctx) {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text("Binary Downloader", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
          DropdownButtonFormField(
            value: _selectedArch,
            items: _archOptions.map((a) => DropdownMenuItem(value: a, child: Text(a))).toList(),
            onChanged: (v) => setState(() => _selectedArch = v.toString()),
          ),
          TextField(
            controller: _fridaVersionCtrl, 
            decoration: const InputDecoration(labelText: "Frida Version", hintText: "e.g. 16.2.5 or 17.5.2")
          ),
          const SizedBox(height: 20),
          ElevatedButton(onPressed: () => _downloadBinary(ctx), child: const Text("DOWNLOAD")),
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  void _pickApp() async {
    List<Application> apps = await DeviceApps.getInstalledApplications(includeAppIcons: true);
    showDialog(context: context, builder: (ctx) => AlertDialog(
      title: const Text("Select Target"),
      content: SizedBox(width: double.maxFinite, height: 400, child: ListView.builder(
        itemCount: apps.length,
        itemBuilder: (c, i) => ListTile(
          leading: apps[i] is ApplicationWithIcon ? Image.memory((apps[i] as ApplicationWithIcon).icon, width: 32) : null,
          title: Text(apps[i].appName),
          subtitle: Text(apps[i].packageName, style: const TextStyle(fontSize: 10)),
          onTap: () { setState(() { _targetName = apps[i].appName; _targetPackage = apps[i].packageName; }); Navigator.pop(ctx); },
        ),
      )),
    ));
  }
}

// ==========================================
// CONFIG DIALOG (Complete with Hints, Ignored Ports, SOCKS5)
// ==========================================
class ConfigDialog extends StatefulWidget {
  const ConfigDialog({super.key});
  @override
  State<ConfigDialog> createState() => _ConfigDialogState();
}

class _ConfigDialogState extends State<ConfigDialog> {
  final _certCtrl = TextEditingController();
  final _ipCtrl = TextEditingController();
  final _portCtrl = TextEditingController();
  final _ignoredCtrl = TextEditingController();
  
  bool _debug = false;
  bool _blockHttp3 = true;
  bool _socks5 = false;
  
  bool _hasEngine = false;
  bool _downloading = false;

  @override
  void initState() {
    super.initState();
    _loadPrefs();
    _checkEngine();
  }

  void _loadPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _certCtrl.text = prefs.getString('cfg_cert') ?? "";
      _ipCtrl.text = prefs.getString('cfg_ip') ?? "";
      _portCtrl.text = prefs.getString('cfg_port') ?? "";
      _ignoredCtrl.text = prefs.getString('cfg_ignored') ?? "";
      
      _debug = prefs.getBool('cfg_debug') ?? false;
      _blockHttp3 = prefs.getBool('cfg_http3') ?? true;
      _socks5 = prefs.getBool('cfg_socks5') ?? false;
    });
  }

  void _checkEngine() async {
    bool has = await SocuteEngineBuilder.isTemplateAvailable();
    setState(() => _hasEngine = has);
  }

  void _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('cfg_cert', _certCtrl.text);
    await prefs.setString('cfg_ip', _ipCtrl.text);
    await prefs.setString('cfg_port', _portCtrl.text);
    await prefs.setString('cfg_ignored', _ignoredCtrl.text);
    
    await prefs.setBool('cfg_debug', _debug);
    await prefs.setBool('cfg_http3', _blockHttp3);
    await prefs.setBool('cfg_socks5', _socks5);
    
    if (mounted) Navigator.pop(context);
  }

  void _downloadEngine() async {
    setState(() => _downloading = true);
    try {
      await SocuteEngineBuilder.downloadTemplate();
      setState(() => _hasEngine = true);
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Engine Updated!")));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text("Error: $e"), backgroundColor: Colors.red));
    } finally {
      setState(() => _downloading = false);
    }
  }

  void _pickCert() async {
    FilePickerResult? result = await FilePicker.platform.pickFiles();
    if (result != null) {
      File file = File(result.files.single.path!);
      String content = await file.readAsString();
      setState(() => _certCtrl.text = content);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: Colors.grey[900],
      title: const Text("Interceptor Config", style: TextStyle(color: Colors.white)),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 1. ENGINE STATUS
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(5), border: Border.all(color: _hasEngine ? Colors.green : Colors.red)),
              child: Row(
                children: [
                  Icon(_hasEngine ? Icons.check_circle : Icons.error, color: _hasEngine ? Colors.green : Colors.red),
                  const SizedBox(width: 10),
                  Expanded(child: Text(_hasEngine ? "Engine Ready" : "Engine Missing", style: const TextStyle(color: Colors.white))),
                  if (_downloading) const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))
                  else IconButton(icon: const Icon(Icons.download, color: Colors.blue), onPressed: _downloadEngine, tooltip: "Update Engine")
                ],
              ),
            ),
            const SizedBox(height: 15),

            // 2. CERTIFICATE
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text("CA Certificate (PEM)", style: TextStyle(color: Colors.grey, fontSize: 12)),
                IconButton(icon: const Icon(Icons.folder_open, color: Colors.orange), onPressed: _pickCert, tooltip: "Import File")
              ],
            ),
            TextField(
              controller: _certCtrl,
              maxLines: 4, 
              minLines: 2,
              style: const TextStyle(color: Colors.white, fontSize: 10, fontFamily: 'monospace'),
              decoration: const InputDecoration(
                filled: true, fillColor: Colors.black,
                border: OutlineInputBorder(),
                hintText: "-----BEGIN CERTIFICATE-----\n...",
                hintStyle: TextStyle(color: Colors.grey)
              ),
            ),

            // 3. PROXY CONFIG
            const SizedBox(height: 10),
            Row(children: [
              Expanded(child: TextField(
                controller: _ipCtrl, 
                style: const TextStyle(color: Colors.white), 
                decoration: const InputDecoration(
                  labelText: "Proxy IP", 
                  hintText: "e.g. 192.168.1.15",
                  hintStyle: TextStyle(color: Colors.white24),
                  labelStyle: TextStyle(color: Colors.grey)
                )
              )),
              const SizedBox(width: 10),
              Expanded(child: TextField(
                controller: _portCtrl, 
                keyboardType: TextInputType.number,
                style: const TextStyle(color: Colors.white), 
                decoration: const InputDecoration(
                  labelText: "Port", 
                  hintText: "8080",
                  hintStyle: TextStyle(color: Colors.white24),
                  labelStyle: TextStyle(color: Colors.grey)
                )
              )),
            ]),
            
            // 4. IGNORED PORTS
            const SizedBox(height: 10),
            TextField(
              controller: _ignoredCtrl, 
              keyboardType: TextInputType.number,
              style: const TextStyle(color: Colors.white), 
              decoration: const InputDecoration(
                labelText: "Ignored Ports", 
                hintText: "e.g. 22, 53, 8883",
                hintStyle: TextStyle(color: Colors.white24),
                labelStyle: TextStyle(color: Colors.grey),
                prefixIcon: Icon(Icons.block, color: Colors.grey, size: 18)
              )
            ),

            // 5. TOGGLES
            const SizedBox(height: 5),
            SwitchListTile(
              title: const Text("Block HTTP/3 (QUIC)", style: TextStyle(color: Colors.white, fontSize: 14)),
              subtitle: const Text("Force downgrade to HTTP/1.1", style: TextStyle(color: Colors.grey, fontSize: 10)),
              value: _blockHttp3, onChanged: (v) => setState(() => _blockHttp3 = v),
              activeColor: Colors.blue, contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text("Use SOCKS5 Proxy", style: TextStyle(color: Colors.white, fontSize: 14)),
              subtitle: const Text("Enable if using SSH/SOCKS tunnel", style: TextStyle(color: Colors.grey, fontSize: 10)),
              value: _socks5, onChanged: (v) => setState(() => _socks5 = v),
              activeColor: Colors.purpleAccent, contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text("Debug Mode", style: TextStyle(color: Colors.white, fontSize: 14)),
              subtitle: const Text("Show verbose logs", style: TextStyle(color: Colors.grey, fontSize: 10)),
              value: _debug, onChanged: (v) => setState(() => _debug = v),
              activeColor: Colors.red, contentPadding: EdgeInsets.zero,
            ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text("CANCEL")),
        ElevatedButton(onPressed: _save, child: const Text("SAVE CONFIG")),
      ],
    );
  }
}

// ==========================================
// PAGE 2: SCRIPT MANAGER (CRUD)
// ==========================================
class ScriptManagerPage extends StatefulWidget {
  final String storageDir;
  const ScriptManagerPage({super.key, required this.storageDir});
  @override
  State<ScriptManagerPage> createState() => _ScriptManagerPageState();
}

class _ScriptManagerPageState extends State<ScriptManagerPage> {
  List<File> _files = [];
  @override
  void initState() { super.initState(); _loadFiles(); }
  void _loadFiles() {
    try {
      final dir = Directory("${widget.storageDir}/scripts");
      List<FileSystemEntity> raw = dir.listSync();
      setState(() => _files = raw.whereType<File>().where((f) => f.path.endsWith('.js')).toList());
    } catch (e) {/*ignore*/}
  }
  void _deleteFile(File f) { try { f.deleteSync(); _loadFiles(); } catch(e) {/*ignore*/} }
  void _goToEditor({File? file}) async {
    await Navigator.push(context, MaterialPageRoute(builder: (ctx) => ScriptEditorPage(storageDir: widget.storageDir, fileToEdit: file)));
    _loadFiles();
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[900],
      appBar: AppBar(title: const Text("Script Manager"), backgroundColor: Colors.black),
      floatingActionButton: FloatingActionButton(backgroundColor: Colors.blue, onPressed: () => _goToEditor(), child: const Icon(Icons.add)),
      body: _files.isEmpty 
        ? const Center(child: Text("No scripts yet.\nTap + to create one.", textAlign: TextAlign.center, style: TextStyle(color: Colors.grey)))
        : ListView.builder(
            itemCount: _files.length,
            itemBuilder: (ctx, i) => Card(color: Colors.grey[850], child: ListTile(
              leading: const Icon(Icons.javascript, color: Colors.orange),
              title: Text(_files[i].path.split('/').last, style: const TextStyle(color: Colors.white)),
              onTap: () => _goToEditor(file: _files[i]),
              trailing: IconButton(icon: const Icon(Icons.delete, color: Colors.red), onPressed: () => _deleteFile(_files[i])),
            )),
          ),
    );
  }
}

// ==========================================
// PAGE 3: SCRIPT EDITOR
// ==========================================
class ScriptEditorPage extends StatefulWidget {
  final String storageDir;
  final File? fileToEdit;
  const ScriptEditorPage({super.key, required this.storageDir, this.fileToEdit});
  @override
  State<ScriptEditorPage> createState() => _ScriptEditorPageState();
}

class _ScriptEditorPageState extends State<ScriptEditorPage> {
  final _nameCtrl = TextEditingController();
  final _contentCtrl = TextEditingController();
  @override
  void initState() {
    super.initState();
    if (widget.fileToEdit != null) {
      _nameCtrl.text = widget.fileToEdit!.path.split('/').last;
      _contentCtrl.text = widget.fileToEdit!.readAsStringSync();
    }
  }
  void _save() {
    String name = _nameCtrl.text.trim();
    if (!name.endsWith(".js")) name += ".js";
    if (name.isEmpty || name == ".js") return;
    File f = File("${widget.storageDir}/scripts/$name");
    f.writeAsStringSync(_contentCtrl.text);
    Navigator.pop(context);
  }
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(title: Text(widget.fileToEdit == null ? "New Script" : "Edit Script"), backgroundColor: Colors.grey[900], actions: [IconButton(icon: const Icon(Icons.save, color: Colors.blueAccent), onPressed: _save)]),
      body: Padding(padding: const EdgeInsets.all(10), child: Column(children: [
        TextField(controller: _nameCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Filename", hintText: "myscript.js", enabledBorder: UnderlineInputBorder(borderSide: BorderSide(color: Colors.grey)))),
        const SizedBox(height: 10),
        Expanded(child: Container(padding: const EdgeInsets.all(5), decoration: BoxDecoration(color: Colors.grey[900], borderRadius: BorderRadius.circular(5)), child: TextField(controller: _contentCtrl, maxLines: null, expands: true, style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 13), decoration: const InputDecoration(border: InputBorder.none, hintText: "// Paste your Frida script here...")))),
      ])),
    );
  }
}