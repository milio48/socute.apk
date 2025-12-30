import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:archive/archive_io.dart';
import 'package:path_provider/path_provider.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:device_apps/device_apps.dart';
import 'package:flutter/services.dart';

// --- MAIN ENTRY POINT ---
void main() {
  runApp(const MaterialApp(
    title: "SoCute Injector",
    debugShowCheckedModeBanner: false,
    home: LauncherPage(),
  ));
}

// --- HELPER CLASS FOR PAYLOAD COMPOSER ---
class ScriptItem {
  File file;
  bool isChecked;
  ScriptItem({required this.file, this.isChecked = true});
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
  String _logs = "Initializing SoCute v2.2...\n";
  bool _isRunning = false;
  Process? _runningProcess;

  // Target
  String _targetPackage = "";
  String _targetName = "Select Target App";

  // Configuration
  bool _disableSELinux = false; // Anti-Crash
  bool _useProxy = false;
  final TextEditingController _ipCtrl = TextEditingController(text: "192.168.1.10");
  final TextEditingController _portCtrl = TextEditingController(text: "8080");

  // Downloader Config
  final TextEditingController _fridaVersionCtrl = TextEditingController(text: "17.5.2");
  String _selectedArch = "arm64"; 
  final List<String> _archOptions = ["arm64", "arm", "x86", "x86_64"];

  // Script Data
  List<ScriptItem> _scriptItems = [];
  String? _storageDir;  // Public
  String? _internalDir; // Private Executable

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _initSystem());
  }

  // 1. SYSTEM INIT
  Future<void> _initSystem() async {
    try {
      // Paths
      final extDir = await getExternalStorageDirectory();
      final intDir = await getApplicationSupportDirectory();
      _storageDir = extDir!.path;
      _internalDir = intDir.path;

      // Create folder
      await Directory("$_storageDir/scripts").create(recursive: true);

      // Auto Detect Arch
      var androidInfo = await DeviceInfoPlugin().androidInfo;
      var abi = androidInfo.supportedAbis[0].toLowerCase();
      
      String detected = "arm64";
      if (abi.contains("arm") && !abi.contains("64")) detected = "arm";
      else if (abi.contains("x86_64")) detected = "x86_64";
      else if (abi.contains("x86")) detected = "x86";

      setState(() => _selectedArch = detected);
      _log("[*] System Ready. Arch: $detected");

      await _refreshScripts();

    } catch (e) {
      _log("[!] Init Error: $e");
    }
  }

  // 2. REFRESH SCRIPTS (Preserve Selection Logic)
  Future<void> _refreshScripts() async {
    if (_storageDir == null) return;
    try {
      final scriptDir = Directory("$_storageDir/scripts");
      List<FileSystemEntity> files = scriptDir.listSync();
      var jsFiles = files.whereType<File>().where((f) => f.path.endsWith('.js')).toList();

      // Sort alphabetically first
      jsFiles.sort((a, b) => a.path.compareTo(b.path));

      setState(() {
        // We create new items but try to preserve 'isChecked' state if file existed before
        Set<String> previouslyChecked = _scriptItems
            .where((i) => i.isChecked)
            .map((i) => i.file.path)
            .toSet();

        _scriptItems = jsFiles.map((f) {
          // If it was checked before (or list was empty meaning first load), keep it checked
          bool shouldCheck = previouslyChecked.contains(f.path) || _scriptItems.isEmpty;
          return ScriptItem(file: f, isChecked: shouldCheck);
        }).toList();
      });
    } catch (e) {
      _log("[!] Load Scripts Error: $e");
    }
  }

  // 3. DOWNLOADER LOGIC
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

  // 4. LAUNCH SEQUENCE (THE ENGINE)
  Future<void> _launchSequence() async {
    if (_targetPackage.isEmpty) { _log("[!] Select target app first!"); return; }
    File binary = File("$_storageDir/frida-inject");
    if (!binary.existsSync()) { _log("[!] Binary missing. Download first."); return; }

    setState(() => _isRunning = true);
    _log("\n=== STARTING INJECTION ===");

    try {
      // A. Anti-Crash (SELinux)
      if (_disableSELinux) {
        await Process.run('su', ['-c', 'setenforce 0']);
        _log("[*] SELinux Disabled (Permissive).");
      }

      // B. Prepare Executable
      File executable = File("$_internalDir/frida-bin");
      if (await executable.exists()) await executable.delete();
      await executable.writeAsBytes(await binary.readAsBytes());
      await Process.run('chmod', ['755', executable.path]);

      // C. MERGER LOGIC (Proxy First -> Selected Scripts)
      File payload = File("$_internalDir/payload.js");
      var sink = payload.openWrite();

      // 1. Proxy
      if (_useProxy) {
        String ip = _ipCtrl.text;
        String port = _portCtrl.text;
        sink.writeln("Java.perform(function() { var S = Java.use('java.lang.System'); S.setProperty('http.proxyHost','$ip'); S.setProperty('http.proxyPort','$port'); S.setProperty('https.proxyHost','$ip'); S.setProperty('https.proxyPort','$port'); console.log('[+] Proxy injected: $ip:$port'); });");
        _log("[+] Proxy Config injected.");
      }

      // 2. User Scripts
      int count = 0;
      for (var item in _scriptItems) {
        if (item.isChecked) {
          sink.writeln('\n// --- FILE: ${item.file.path.split('/').last} ---');
          sink.writeln(item.file.readAsStringSync());
          count++;
        }
      }
      await sink.close();
      _log("[*] Merged $count scripts into payload.");

      // D. EXECUTE
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

  Future<void> _stopSequence() async {
    _runningProcess?.kill();
    await Process.run('su', ['-c', 'pkill -f frida-inject']);
    setState(() { _isRunning = false; _runningProcess = null; });
    _log("[*] Process Killed.");
  }

  void _log(String text) {
    if (!mounted) return;
    setState(() => _logs += "$text\n");
  }

  // --- UI COMPONENTS ---

  void _showDownloader() {
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.grey[900], builder: (ctx) {
      return Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text("Binary Downloader", style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 15),
            DropdownButtonFormField(
              value: _selectedArch,
              dropdownColor: Colors.grey[800],
              style: const TextStyle(color: Colors.white),
              decoration: const InputDecoration(labelText: "Architecture", labelStyle: TextStyle(color: Colors.grey)),
              items: _archOptions.map((a) => DropdownMenuItem(value: a, child: Text(a.toUpperCase()))).toList(),
              onChanged: (v) => setState(() => _selectedArch = v.toString()),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _fridaVersionCtrl,
              style: const TextStyle(color: Colors.white),
              decoration: const InputDecoration(labelText: "Frida Version", labelStyle: TextStyle(color: Colors.grey)),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () => _downloadBinary(ctx),
              style: ElevatedButton.styleFrom(backgroundColor: Colors.blue, minimumSize: const Size.fromHeight(50)),
              child: const Text("DOWNLOAD"),
            ),
            const SizedBox(height: 200), // Spacing for keyboard
          ],
        ),
      );
    });
  }

  void _openScriptManager() async {
    // Navigate to Manager Page
    await Navigator.push(
      context, 
      MaterialPageRoute(builder: (context) => ScriptManagerPage(storageDir: _storageDir!))
    );
    // Refresh list when coming back
    _refreshScripts();
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
          onTap: () {
            setState(() { _targetName = apps[i].appName; _targetPackage = apps[i].packageName; });
            Navigator.pop(ctx);
          },
        ),
      )),
    ));
  }

  @override
  Widget build(BuildContext context) {
    bool binaryReady = _storageDir != null && File("$_storageDir/frida-inject").existsSync();

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text("SoCute v2.2", style: TextStyle(fontWeight: FontWeight.bold)),
        backgroundColor: Colors.grey[900],
        actions: [
          IconButton(icon: const Icon(Icons.settings_ethernet), tooltip: "Downloader", onPressed: _showDownloader),
          IconButton(icon: const Icon(Icons.folder_open), tooltip: "Script Manager", onPressed: _openScriptManager),
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
                subtitle: Text(_targetPackage.isEmpty ? "Tap to select target" : _targetPackage, style: const TextStyle(color: Colors.greenAccent)),
                trailing: const Icon(Icons.touch_app, color: Colors.blueAccent),
                onTap: _isRunning ? null : _pickApp,
              ),
            ),

            // 2. PAYLOAD COMPOSER (The Reorderable List)
            const SizedBox(height: 10),
            const Text("Payload Composer (Drag to Reorder)", style: TextStyle(color: Colors.grey, fontSize: 12)),
            Container(
              height: 250, // FIXED HEIGHT SCROLLABLE WINDOW
              decoration: BoxDecoration(color: Colors.grey[900], borderRadius: BorderRadius.circular(5), border: Border.all(color: Colors.white10)),
              child: _scriptItems.isEmpty 
                ? const Center(child: Text("No scripts found.\nGo to Manager to create/import.", textAlign: TextAlign.center, style: TextStyle(color: Colors.grey)))
                : ReorderableListView(
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
                          key: ValueKey(_scriptItems[i].file.path),
                          dense: true,
                          tileColor: Colors.black12,
                          leading: const Icon(Icons.drag_handle, color: Colors.grey),
                          title: Text(_scriptItems[i].file.path.split('/').last, style: const TextStyle(color: Colors.white)),
                          trailing: Checkbox(
                            value: _scriptItems[i].isChecked,
                            activeColor: Colors.green,
                            onChanged: _isRunning ? null : (v) => setState(() => _scriptItems[i].isChecked = v!),
                          ),
                        )
                    ],
                  ),
            ),

            // 3. LAUNCH TOGGLES
            ExpansionTile(
              title: const Text("Launch Config", style: TextStyle(color: Colors.white, fontSize: 14)),
              collapsedBackgroundColor: Colors.transparent,
              children: [
                SwitchListTile(
                  title: const Text("Disable SELinux (Anti-Crash)", style: TextStyle(color: Colors.orangeAccent)),
                  subtitle: const Text("Use if app reboots. Reduces Security.", style: TextStyle(color: Colors.grey, fontSize: 10)),
                  value: _disableSELinux, activeColor: Colors.orange,
                  onChanged: _isRunning ? null : (v) => setState(() => _disableSELinux = v),
                ),
                SwitchListTile(
                  title: const Text("Inject Proxy", style: TextStyle(color: Colors.white)),
                  subtitle: const Text("Overrides proxy via Frida Script", style: TextStyle(color: Colors.grey, fontSize: 10)),
                  value: _useProxy, activeColor: Colors.blue,
                  onChanged: _isRunning ? null : (v) => setState(() => _useProxy = v),
                ),
                if (_useProxy) Row(children: [
                  Expanded(child: TextField(controller: _ipCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "IP", labelStyle: TextStyle(color: Colors.grey)))),
                  const SizedBox(width: 10),
                  Expanded(child: TextField(controller: _portCtrl, style: const TextStyle(color: Colors.white), decoration: const InputDecoration(labelText: "Port", labelStyle: TextStyle(color: Colors.grey)))),
                ])
              ],
            ),

            const Spacer(),

            // 4. ACTION BUTTONS
            Row(children: [
              binaryReady ? const Icon(Icons.check_circle, color: Colors.green) : const Icon(Icons.error, color: Colors.red),
              const SizedBox(width: 10),
              Expanded(
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(backgroundColor: _isRunning ? Colors.red[900] : Colors.greenAccent[700], padding: const EdgeInsets.symmetric(vertical: 15)),
                  onPressed: _isRunning ? _stopSequence : _launchSequence,
                  child: Text(_isRunning ? "STOP INJECTION" : "LAUNCH", style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                ),
              )
            ]),

            // 5. LOGS
            const SizedBox(height: 10),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text("Execution Logs:", style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.bold)),
                Row(
                  children: [
                    // Tombol Copy
                    IconButton(
                      icon: const Icon(Icons.copy, color: Colors.blue, size: 20),
                      tooltip: "Copy Logs",
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: _logs));
                        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Logs copied to clipboard!", style: TextStyle(color: Colors.white)), backgroundColor: Colors.blue));
                      },
                    ),
                    // Tombol Clear
                    IconButton(
                      icon: const Icon(Icons.delete_sweep, color: Colors.red, size: 20),
                      tooltip: "Clear Logs",
                      onPressed: () => setState(() => _logs = ""),
                    ),
                  ],
                )
              ],
            ),
            Container(
              height: 150,
              width: double.infinity,
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(color: Colors.black, border: Border.all(color: Colors.white24), borderRadius: BorderRadius.circular(5)),
              child: SingleChildScrollView(
                reverse: true,
                child: SelectableText( 
                  _logs, 
                  style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 11)
                ),
              ),
            )
          ],
        ),
      ),
    );
  }
}

// ==========================================
// PAGE 2: SCRIPT MANAGER (ASSETS)
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
  void initState() {
    super.initState();
    _loadFiles();
  }

  void _loadFiles() {
    try {
      final dir = Directory("${widget.storageDir}/scripts");
      List<FileSystemEntity> raw = dir.listSync();
      setState(() {
        _files = raw.whereType<File>().where((f) => f.path.endsWith('.js')).toList();
      });
    } catch (e) {
      debugPrint("Error: $e");
    }
  }

  void _deleteFile(File f) {
    try { f.deleteSync(); _loadFiles(); } catch(e) {/* ignore */}
  }

  void _goToEditor({File? file}) async {
    await Navigator.push(context, MaterialPageRoute(builder: (ctx) => ScriptEditorPage(storageDir: widget.storageDir, fileToEdit: file)));
    _loadFiles();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey[900],
      appBar: AppBar(title: const Text("Script Manager"), backgroundColor: Colors.black),
      floatingActionButton: FloatingActionButton(
        backgroundColor: Colors.blue,
        onPressed: () => _goToEditor(),
        child: const Icon(Icons.add),
      ),
      body: _files.isEmpty 
        ? const Center(child: Text("No scripts yet.\nTap + to create one.", textAlign: TextAlign.center, style: TextStyle(color: Colors.grey)))
        : ListView.builder(
            itemCount: _files.length,
            itemBuilder: (ctx, i) {
              return Card(
                color: Colors.grey[850],
                margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                child: ListTile(
                  leading: const Icon(Icons.javascript, color: Colors.orange),
                  title: Text(_files[i].path.split('/').last, style: const TextStyle(color: Colors.white)),
                  onTap: () => _goToEditor(file: _files[i]),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete, color: Colors.red),
                    onPressed: () => _deleteFile(_files[i]),
                  ),
                ),
              );
            },
          ),
    );
  }
}

// ==========================================
// PAGE 3: SCRIPT EDITOR (CRUD)
// ==========================================
class ScriptEditorPage extends StatefulWidget {
  final String storageDir;
  final File? fileToEdit;
  const ScriptEditorPage({super.key, required this.storageDir, this.fileToEdit});

  @override
  State<ScriptEditorPage> createState() => _ScriptEditorPageState();
}

class _ScriptEditorPageState extends State<ScriptEditorPage> {
  final TextEditingController _nameCtrl = TextEditingController();
  final TextEditingController _contentCtrl = TextEditingController();

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
    
    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Saved!")));
    Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(widget.fileToEdit == null ? "New Script" : "Edit Script"),
        backgroundColor: Colors.grey[900],
        actions: [
          IconButton(icon: const Icon(Icons.save, color: Colors.blueAccent), onPressed: _save)
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(10),
        child: Column(
          children: [
            TextField(
              controller: _nameCtrl,
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
              decoration: const InputDecoration(
                labelText: "Filename (e.g. bypass.js)",
                labelStyle: TextStyle(color: Colors.grey),
                enabledBorder: UnderlineInputBorder(borderSide: BorderSide(color: Colors.grey)),
              ),
            ),
            const SizedBox(height: 10),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(5),
                decoration: BoxDecoration(color: Colors.grey[900], borderRadius: BorderRadius.circular(5)),
                child: TextField(
                  controller: _contentCtrl,
                  maxLines: null,
                  expands: true,
                  style: const TextStyle(color: Colors.greenAccent, fontFamily: 'monospace', fontSize: 13),
                  decoration: const InputDecoration(
                    border: InputBorder.none,
                    hintText: "// Paste your Frida script here...",
                    hintStyle: TextStyle(color: Colors.white24),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}