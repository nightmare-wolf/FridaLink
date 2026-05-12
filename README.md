# FridaLink

**FridaLink** is a Burp Suite extension that brings [Frida](https://frida.re) dynamic instrumentation directly into the Burp workspace for authorized Android mobile penetration testing. Instead of juggling Frida terminals, Python scripts, and Burp simultaneously, FridaLink gives you a single unified panel: live runtime events, an interactive REPL, intercept + modify flows, match-and-replace rules, static APK analysis, MASVS checklist tracking, and PDF report generation — all inside Burp. Please note that some features may not be fully functional yet — this project is actively being developed, and updates are a work in progress. Expect improvements to stability, aesthetics, and overall smoothness over time.

> **Authorization required.** FridaLink is a professional penetration testing tool. Use it only against applications you are authorized to test.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Starting the Sidecar](#starting-the-sidecar)
5. [Connecting from Burp](#connecting-from-burp)
6. [Core Workflow](#core-workflow)
7. [Tabs Reference](#tabs-reference)
8. [Writing Frida Scripts for FridaLink](#writing-frida-scripts-for-fridalink)
9. [Script Library Layout](#script-library-layout)
10. [WebSocket Protocol](#websocket-protocol)
11. [Common Penetration Testing Workflows](#common-penetration-testing-workflows)
12. [Demo Mode](#demo-mode)
13. [Troubleshooting](#troubleshooting)
14. [Architecture](#architecture)

---

## How It Works

FridaLink bridges four layers:

```
Burp Suite (Kotlin extension)
        │  WebSocket  ws://127.0.0.1:7766/ws
        ▼
Python Sidecar  (fridalink_sidecar)
        │  Frida Python API  (USB / ADB)
        ▼
Frida Agent  (GumJS — injected into target)
        │  ptrace / process injection
        ▼
Target Android Application
```

The Burp extension never talks to Frida directly. It sends JSON commands to the Python sidecar over a local WebSocket. The sidecar manages the Frida session and streams structured events back to Burp in real time. This separation lets the extension stay lightweight and keeps Frida-specific error handling isolated in Python.

---

## Requirements

| Component | Minimum version | Notes |
|---|---|---|
| Burp Suite Professional | 2024.1+ | Community edition does not support extensions |
| Java (JDK) | 17+ | Must match the JVM Burp runs under |
| Gradle | 8+ | Only needed to build the JAR |
| Python | 3.11+ | For the sidecar |
| `frida` Python package | 17.0+ | Must match the frida-server binary on device |
| `frida-tools` | same as frida | Optional — needed for the Frida Trace tab |
| ADB | any recent | Must be on `PATH` |
| Android device or emulator | Android 9+ | Must be rooted with frida-server running |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourorg/FridaLink.git
cd FridaLink
```

### 2. Build the Burp extension JAR

**Linux / macOS:**
```bash
./gradlew jar
```

**Windows:**
```powershell
.\gradlew.bat jar
```

Output: `build/libs/FridaLink-1.0.0.jar`

### 3. Set up the Python sidecar

```bash
cd python
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.\.venv\Scripts\Activate.ps1

pip install -e .
pip install frida frida-tools
```

### 4. Load the extension in Burp

1. Open **Burp Suite Professional**
2. Go to **Extensions → Installed → Add**
3. Extension type: **Java**
4. Extension file: `build/libs/FridaLink-1.0.0.jar`
5. Click **Next** — check the Output and Errors tabs are clean
6. The **FridaLink** tab appears in the Burp navigation bar

---

## Starting the Sidecar

The sidecar is a Python WebSocket server that bridges Burp to Frida. Start it before connecting from Burp.

```bash
# From the python/ directory, with the venv active
python -m fridalink_sidecar
```

Expected output:

```
[fridalink][2026-05-11T14:00:00+00:00] sidecar listening on ws://127.0.0.1:7766/ws
[fridalink][2026-05-11T14:00:00+00:00] script library path: /home/user/Burp/Scripts
```

### Sidecar options

```
--host        Bind address (default: 127.0.0.1)
--port        Port (default: 7766)
--demo        Run with synthetic data — no device needed
--scripts-dir Path to your Frida script library directory
```

**Script library auto-detection** (no `--scripts-dir` needed):

| OS | Default path |
|---|---|
| Windows | `C:\Users\<you>\Burp\Scripts` |
| Linux / macOS | `~/Burp/Scripts` |

Falls back to `<repo>/scripts/` if neither location exists.

```bash
# Override the script directory explicitly
python -m fridalink_sidecar --scripts-dir /opt/mobile-pentest/scripts
```

### Starting frida-server on the device

```bash
# Push frida-server to the device (match version to your pip install)
adb push frida-server-17.9.1-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start it (as root)
adb shell su -c "/data/local/tmp/frida-server &"

# Verify
frida-ps -U | head -5
```

---

## Connecting from Burp

1. Open the **FridaLink** tab
2. Set **Host** to `127.0.0.1` and **Port** to `7766`
3. Click **Connect**

The status bar changes from `Disconnected` to a summary like:

```
Connected — Frida ok — device=Pixel 7 — 312 processes — session=none
```

Click **Refresh Processes** in the Live Feed toolbar to populate the process table.

---

## Core Workflow

This is the standard sequence for every engagement:

```
1. Start frida-server on the rooted Android device
2. Start the Python sidecar on your laptop
3. Connect from Burp → FridaLink tab
4. Refresh the process list
5. Select the target app process
6. Click Attach  (or use Spawn + Inject for early instrumentation)
7. Load one or more Frida scripts from the Script Library tab
8. Trigger app behavior — events stream into the Live Feed in real time
9. Use the REPL for interactive exploration
10. Document findings in the MASVS tab
11. Generate a PDF report
```

---

## Tabs Reference

### Toolbar (persistent across all tabs)

```
Host [127.0.0.1]  Port [7766]  [Connect]  [Disconnect]
Python [python]   Root [~/Burp/Scripts]
Spawn [com.package.name]  [Spawn+Inject]  [Resume]
─────────────────────────────────────────────────────
Status: Connected · Selected: com.example.app (PID 2341) · Session: Attached
```

| Control | Purpose |
|---|---|
| Host / Port | Address of the Python sidecar |
| Connect / Disconnect | Open or close the WebSocket session |
| Python | Path to the Python interpreter for sidecar auto-launch |
| Root | Base path for script resolution |
| Spawn | Package identifier for cold-start instrumentation |
| Spawn + Inject | Spawn the app via Frida, inject enabled library scripts while paused, then wait for Resume |
| Resume | Resume a paused spawned process after hooks are installed |

---

### Live Feed

The real-time event table. Every `send()` call from any loaded Frida script appears here.

```
[Refresh] [Attach] [Detach]   Filter: [_______]  Category: [All ▼]
Process: [All ▼]  Module: [_______]  [✓] Errors only  [⏸ Scroll Lock]
────────────────────────────────────────────────────────────────────
Time      │ Process     │ Category │ Module          │ Summary
──────────┼─────────────┼──────────┼─────────────────┼───────────────
14:01:22  │ com.example │ network  │ libssl.so       │ SSL_read 842b
14:01:22  │ com.example │ call     │ libil2cpp.so    │ GetUserInfo()
14:01:23  │ com.example │ java     │ OkHttp3         │ POST /api/buy
────────────────────────────────────────────────────────────────────
Event Details (selected row):
  args:    {"method":"GetUserInfo","callArgs":[],"result":"uid=9912"}
  retval:  uid=9912
  thread:  14   severity: info   script: lua_il2cpp_inspector.js
```

**Event categories:** `call`, `network`, `tls`, `jni`, `java`, `message`, `script`, `attach`, `detach`, `intercept`, `rpc_result`, `error`

**Scroll Lock (`⏸`):** Freezes the table at the current position so you can inspect events without the view jumping. Toggle off to resume live-tail.

**Export to file:** Streams all arriving events to a `.jsonl` file on disk in real time — safe to `tail -f` from a terminal while capture runs.

---

### Match & Replace

Rewrite rules applied by the sidecar to Frida-intercepted message buffers before they are forwarded.

```
┌──────────┬─────────────┬────────────────┬────────────────┬────────────┐
│ Enabled  │ URL Pattern │ Match          │ Replace        │ Comment    │
├──────────┼─────────────┼────────────────┼────────────────┼────────────┤
│ [✓]      │ /api/mall   │ "boughtNum":1  │ "boughtNum":99 │ qty tamper │
│ [ ]      │ (any)       │ "result":false │ "result":true  │ bool flip  │
└──────────┴─────────────┴────────────────┴────────────────┴────────────┘
[+ Add Rule]  [Remove Selected]  [Push to Session]
```

Double-click any cell to edit inline. **Push to Session** sends all enabled rules to the sidecar immediately — no reattach required.

---

### Intercept

Messages that a Frida script has flagged for manual review and decision.

```
Time      │ Process     │ Direction   │ Channel  │ Summary
──────────┼─────────────┼─────────────┼──────────┼──────────────────────
14:05:01  │ com.example │ ▶ outbound  │ tcp/443  │ POST /api/mall/buy
14:05:01  │ com.example │ ◀ inbound   │ tcp/443  │ 200 OK

Payload (editable):
{"action":"buy","itemId":"sword_001","boughtNum":1,"jade":500}

[Forward]  [Drop]
```

Edit the payload text area, then click **Forward** to pass the (modified) message through or **Drop** to discard it.

---

### Sidecar Logs

All operational messages from the Python sidecar and Frida session.

```
[14:00:00] sidecar listening on ws://127.0.0.1:7766/ws
[14:00:01] client connected, clients=1
[14:00:03] Frida device resolved: Pixel 7
[14:00:05] attached to pid=2341 name=com.example.app
[14:00:06] REPL helper loaded
[14:00:07] script library loaded: 18 script(s) from /home/user/Burp/Scripts
```

Use this tab to diagnose attach failures, script load errors, and device visibility issues before checking anything else.

---

### Script Library

Manages your on-disk Frida script collection.

```
Library Path: [/home/user/Burp/Scripts]  [Scan]

Name                    │ Category │ Description
────────────────────────┼──────────┼───────────────────────────────────
ssl_unpin_bypass        │ tls      │ Disable certificate pinning
openssl_observer        │ tls      │ SSL_read/write native hook
lua_il2cpp_inspector    │ native   │ IL2CPP + Lua + RPC inspector
jni_observer            │ native   │ JNI call tracing
okhttp_observer         │ http     │ OkHttp3 request/response logging
kcp_observer            │ native   │ KCP UDP packet logging (game traffic)

[Load Script]  [Load All Enabled]
```

**Scan** walks the library directory recursively and reads `@metadata` headers from each `.js` file. **Load All Enabled** is used after **Spawn + Inject** to batch-load scripts into the paused process before it starts.

---

### Custom Scripts

Write, edit, and run ad-hoc Frida scripts without saving them to disk.

```javascript
// Script Name: quick-hook
// Language:    javascript

Interceptor.attach(
    Module.findExportByName("libssl.so", "SSL_read"), {
        onEnter(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave(retval) {
            const bytes = retval.toInt32();
            if (bytes > 0) {
                send({
                    type: "fridalink_event",
                    category: "tls", module: "libssl.so", target: "SSL_read",
                    summary: `SSL_read ${bytes} bytes`,
                    timestamp: new Date().toISOString(),
                    thread_id: String(Process.getCurrentThreadId()),
                    script_source: "quick-hook",
                    severity: "info",
                    payload_ascii_preview: this.buf.readUtf8String(Math.min(bytes, 200)),
                });
            }
        }
    }
);
```

Click **Run Script** to inject the editor content into the current session immediately.

---

### RPC Console

Call named exports on scripts that expose `rpc.exports`.

```
Method: [list_modules]   Args: []
[Call RPC]

[14:10:22] list_modules() →
  libil2cpp.so  @ 0x70b5600000  size=28MB
  libgame.so    @ 0x70f1234000  size=4MB
  libssl.so     @ 0x70a1234000  size=800KB

[14:10:45] list_exports("libgame.so") →
  GameState_GetCurrentUserId
  MallManager_Buy
  RewardManager_GetItems
```

Results appear as `rpc_result` events in the Live Feed and in the RPC Console output area.

---

### Frida REPL

An interactive JavaScript terminal connected to the live Frida session.

```javascript
// Type JS — press Enter to evaluate

> Process.arch
"arm64"

> Process.enumerateModules().length
87

> Module.findExportByName(null, "SSL_read")
"0x7f1a2b3c4d50"

> hexdump(ptr("0x7f1a2b3c4d50"), { length: 32 })
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
7f1a2b3c4d50  ff 83 02 d1 fd 7b 04 a9 fc 6f 05 a9 fa 67 06 a9  .....{...o...g..

> Memory.scanSync(ptr("0x70b5600000"), 0x100000, "55 73 65 72 49 64")
[{ address: "0x70b5601f40", size: 6 }]
```

Up/Down arrow keys navigate command history. The cheat sheet panel on the right provides quick reference for Process, Module, Memory, Interceptor, and NativeFunction APIs.

---

### Frida Trace

Runs `frida-trace` as a subprocess and streams output into FridaLink.

```
Target:   [com.example.app]
Include:  [SSL_*,ikcp_*,MallManager_*]
Exclude:  [malloc,free,pthread_*]
Work Dir: [/home/user/frida-handlers]
[Start Trace]  [Stop]

Tracing...
   843 ms  SSL_read()
   843 ms  ikcp_recv()
   845 ms  MallManager_Buy()
   846 ms  SSL_write()
```

Frida Trace generates editable `.js` handler files in the work directory. Edit them live — the trace hot-reloads automatically.

---

### MASVS

OWASP MASVS v2 compliance checklist with evidence tracking.

```
MASVS-NETWORK-1   │ L1 │ Certificate validation         │ FAIL
MASVS-NETWORK-2   │ L1 │ Network security config        │ PASS
MASVS-STORAGE-1   │ L1 │ Sensitive data at rest         │ NOT_TESTED
MASVS-RESILIENCE-1│ R  │ Root / emulator detection      │ FAIL
```

Double-click **Status** to cycle: `NOT_TESTED → PASS → FAIL → NOT_APPLICABLE`. The **Evidence** field accepts free text — paste event details, ADB output, or screenshots.

---

### Static Analysis

APK inspection without installing the app.

```bash
# Provide the APK path and click Analyze APK
/home/user/targets/com.example.app.apk
```

Subtabs:
- **Certificate** — subject, issuer, algorithm, key size, expiry, debug-cert warning
- **Libraries** — SDK packages detected in DEX and `.so` files with risk ratings
- **URL References** — all hardcoded URLs extracted from DEX, assets, and `strings.xml`
- **Behavior** — permissions, `android:debuggable`, backup flag, network security config, exported components
- **Findings** — all detected issues with severity, CWE, CVSS, and MASVS reference

---

### Geo Map

Maps all server IPs from HTTP history to physical locations.

```
[Geolocate All]  [Analyze Foreign Traffic]

IP              │ CC │ Country       │ Org           │ Threat
────────────────┼────┼───────────────┼───────────────┼────────────────────
103.4.x.x       │ JP │ Japan         │ Sony Music    │
34.x.x.x        │ US │ United States │ Google Cloud  │
1.x.x.x         │ CN │ China         │ Alibaba       │ Data Broker (CN) ⚠

Foreign Traffic Summary:
  3 servers outside US — 1 CN flagged as Data Broker
```

---

### Report

Generates a PDF penetration testing report from all collected evidence.

```
Target:    [com.example.app (Example App)]
Assessor:  [Your Name]   Engagement: [ENG-001]
Output:    [/home/user/reports/example_app.pdf]
[Generate Report]
```

The report pulls from: MASVS checklist, Static Analysis findings, Traffic endpoints, and Geo Map server data.

---

## Writing Frida Scripts for FridaLink

### File header (required for the Script Library to display metadata)

```javascript
// @name My Hook Script
// @category native
// @description One sentence describing what this script observes.
// @version 1.0
```

### The `emit()` helper (copy into every script)

```javascript
'use strict';

const TAG = 'my_hook';

function emit(event) {
    send({
        type:          'fridalink_event',
        timestamp:     new Date().toISOString(),
        thread_id:     String(Process.getCurrentThreadId()),
        script_source: TAG,
        severity:      'info',
        ...event,           // caller fields override defaults above
    });
}
```

### Native hook — SSL_read traffic capture

```javascript
// @name SSL Read Observer
// @category tls
// @description Captures decrypted TLS plaintext from SSL_read.
// @version 1.0

'use strict';

const TAG = 'ssl_observer';

function emit(event) {
    send({
        type: 'fridalink_event', timestamp: new Date().toISOString(),
        thread_id: String(Process.getCurrentThreadId()),
        script_source: TAG, severity: 'info', ...event,
    });
}

const sslReadPtr = Module.findExportByName('libssl.so', 'SSL_read');

if (sslReadPtr) {
    Interceptor.attach(sslReadPtr, {
        onEnter(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave(retval) {
            const n = retval.toInt32();
            if (n <= 0) return;
            let preview = '';
            try { preview = this.buf.readUtf8String(Math.min(n, 512)); } catch (_) {}
            emit({
                category: 'tls', module: 'libssl.so', target: 'SSL_read',
                summary:  `SSL_read ${n} bytes`,
                payload_ascii_preview: preview,
            });
        },
    });
    emit({ category: 'script', module: TAG, target: 'load', summary: 'SSL_read observer loaded' });
} else {
    emit({ category: 'error', module: TAG, target: 'load',
           summary: 'libssl.so SSL_read not found', severity: 'warn' });
}
```

### Java hook — OkHttp3 request logging

```javascript
// @name OkHttp3 Observer
// @category http
// @description Logs OkHttp3 requests and responses including headers and body.
// @version 1.0

'use strict';

const TAG = 'okhttp3';

function emit(event) {
    send({
        type: 'fridalink_event', timestamp: new Date().toISOString(),
        thread_id: String(Process.getCurrentThreadId()),
        script_source: TAG, severity: 'info', ...event,
    });
}

// Java.use() requires the Android Runtime — poll until it is ready.
(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);
        return;
    }
    Java.perform(function () {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const Request      = Java.use('okhttp3.Request');

        OkHttpClient.newCall.implementation = function (request) {
            const url    = request.url().toString();
            const method = request.method();
            emit({
                category: 'http', module: 'OkHttp3', target: url,
                summary:  `${method} ${url}`,
                args:     JSON.stringify({ method, url }),
            });
            return this.newCall(request);
        };

        emit({ category: 'script', module: TAG, target: 'load', summary: 'OkHttp3 observer loaded' });
    });
})();
```

### Intercept + forward script

Scripts can hold a message and emit it to the Intercept tab instead of logging it:

```javascript
// @name Mall Buy Interceptor
// @category native
// @description Intercepts the buy protocol message for manual modification.
// @version 1.0

'use strict';

const TAG = 'mall_interceptor';

const lua_rawget = Module.findExportByName(null, 'lua_rawget');
let   interceptPending = false;

if (lua_rawget) {
    Interceptor.attach(lua_rawget, {
        onEnter(args) {
            // Capture the key from the Lua table lookup
            try {
                const key = args[2].readCString();
                if (key === 'boughtNum' && !interceptPending) {
                    interceptPending = true;
                    // Emit an intercept candidate — appears in the Intercept tab
                    send({
                        kind:      'intercept',
                        id:        `buy-${Date.now()}`,
                        timestamp: new Date().toISOString(),
                        direction: 'outbound',
                        channel:   'lua/game',
                        summary:   'c2s_mall_buy — boughtNum write',
                        editable:  true,
                        payload:   JSON.stringify({ boughtNum: 1 }),
                    });
                }
            } catch (_) {}
        },
    });
}
```

### RPC exports (for the RPC Console tab)

```javascript
// @name IL2CPP Inspector
// @category native
// @description Exposes module enumeration and export listing via RPC.
// @version 1.0

'use strict';

rpc.exports = {
    listModules: function () {
        return Process.enumerateModules().map(m => ({
            name: m.name, base: m.base.toString(), size: m.size,
        }));
    },
    listExports: function (libName) {
        const mod = Process.findModuleByName(libName);
        if (!mod) return [];
        return mod.enumerateExports().map(e => e.name);
    },
    evaluate: function (code) {
        try {
            const val = (0, eval)(code);
            return { ok: true, result: (val === undefined) ? 'undefined' : JSON.stringify(val) };
        } catch (e) {
            return { ok: false, error: e.message || String(e) };
        }
    },
};
```

### Receiving Match & Replace rules from Burp

```javascript
// Re-arm after every push so future rule updates are received
let activeRules = [];

function listenForRules() {
    recv('update_rules', function (message) {
        activeRules = (message.rules || []).filter(r => r.enabled !== false);
        listenForRules();
    });
}
listenForRules();
```

### Safe backtrace capture

```javascript
// Inside onEnter only — never inside dlopen hooks (deadlock risk)
onEnter(args) {
    try {
        this.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join('\n    ');
    } catch (_) { this.bt = ''; }
},
onLeave(retval) {
    emit({ category: 'native', module: 'libc', target: 'connect',
           summary: 'connect()', backtrace: this.bt });
},
```

---

## Script Library Layout

Place scripts anywhere under your library directory. Subdirectory names become the default category.

```
~/Burp/Scripts/              (Windows: C:\Users\<you>\Burp\Scripts)
├── tls/
│   ├── ssl_unpin_bypass.js      → category "tls"
│   └── openssl_observer.js      → category "tls"
├── native/
│   ├── jni_observer.js          → category "native"
│   ├── dns_observer.js          → category "native"
│   ├── kcp_observer.js          → category "native"
│   └── socket_observer.js       → category "native"
├── java/
│   ├── okhttp_observer.js       → category "java"
│   └── webview_observer.js      → category "java"
├── http/
│   └── unity_curl_hook.js       → category "http"
└── helper/
    └── backtrace_helper.js      → category "helper"
```

Every `.js` file is automatically discovered on **Scan**. The `@name`, `@category`, `@description`, and `@version` header tags control what appears in the library table.

---

## WebSocket Protocol

All messages are UTF-8 JSON over `ws://host:port/ws`.

### Burp → Sidecar

```json
// Handshake
{ "type": "hello", "client": "fridalink-burp", "version": "1.0.0" }

// Refresh process list
{ "type": "process_refresh" }

// Attach to a running process
{ "type": "attach", "pid": 2341 }

// Detach current session
{ "type": "detach" }

// Spawn app by package name and pre-load scripts
{
  "type": "spawn",
  "identifier": "com.example.app",
  "scripts": [
    { "name": "ssl_unpin_bypass", "content": "..." },
    { "name": "okhttp_observer",  "content": "..." }
  ]
}

// Resume a spawned (paused) process
{ "type": "resume" }

// Load a script into the current session
{
  "type": "script_run",
  "script": {
    "id": "my-hook", "name": "My Hook", "language": "javascript",
    "description": "Example", "content": "send({...})"
  }
}

// Act on an intercepted message
{ "type": "intercept_action", "id": "buy-1234", "action": "forward", "payload": "{...modified...}" }

// Push match-and-replace rules
{
  "type": "update_rules",
  "rules": [
    { "id": "r1", "enabled": true, "urlPattern": "/api/mall", "matchText": "\"boughtNum\":1", "replaceText": "\"boughtNum\":99" }
  ]
}

// Call an RPC export on loaded scripts
{ "type": "rpc_call", "method": "listModules", "args": [] }

// Evaluate JS in the REPL helper context
{ "type": "repl_eval", "code": "Process.arch" }
```

### Sidecar → Burp

```json
// Status line
{ "type": "status", "message": "Attached to pid 2341" }

// Structured session state
{
  "type": "session_summary",
  "summary": {
    "host_frida_available": true,
    "android_device_visible": true,
    "device_label": "Pixel 7",
    "android_process_count": 312,
    "session_active": true,
    "loaded_script_count": 3,
    "attached_pid": 2341,
    "attached_name": "com.example.app",
    "error": null
  }
}

// Process inventory
{
  "type": "process_list",
  "processes": [
    { "pid": 2341, "name": "com.example.app", "platform": "android", "state": "running", "attached": true }
  ]
}

// Single runtime event
{
  "type": "event",
  "timestamp": "2026-05-11T14:01:22Z",
  "process": "com.example.app",
  "category": "tls",
  "module": "libssl.so",
  "target": "SSL_read",
  "summary": "SSL_read 842 bytes",
  "severity": "info",
  "thread_id": "14",
  "script_source": "ssl_observer",
  "args": "",
  "retval": "842",
  "payload_ascii_preview": "HTTP/1.1 200 OK\r\nContent-Type: application/json..."
}

// Intercept candidate (appears in Intercept tab)
{
  "type": "intercept",
  "id": "buy-1715436082000",
  "timestamp": "2026-05-11T14:01:22Z",
  "process": "com.example.app",
  "direction": "outbound",
  "channel": "tcp/443",
  "summary": "POST /api/mall/buy",
  "payload": "{\"action\":\"buy\",\"itemId\":\"sword_001\",\"boughtNum\":1,\"jade\":500}",
  "editable": true
}

// Script catalog
{
  "type": "scripts",
  "scripts": [
    { "id": "lib:tls/ssl_unpin_bypass.js", "name": "SSL Unpin Bypass",
      "category": "tls", "description": "...", "language": "javascript", "content": "..." }
  ]
}

// REPL response
{ "type": "repl_result", "code": "Process.arch", "result": "arm64", "error": null }
```

---

## Common Penetration Testing Workflows

### A — SSL Unpinning and traffic capture

```
Goal: Read HTTPS traffic the app would normally block via certificate pinning.

1.  Attach to process (or use Spawn + Inject)
2.  Script Library → load tls/ssl_unpin_bypass.js
3.  Script Library → load tls/openssl_observer.js
4.  Trigger any HTTPS activity in the app
5.  Live Feed → filter category=tls
6.  Click an event → details panel shows decrypted ASCII payload
7.  Cross-reference with Burp HTTP history in the Traffic tab
```

### B — OkHttp / network library interception

```
Goal: Log all HTTP requests and responses at the library level,
      including endpoints that bypass the system proxy.

1.  Attach to process
2.  Script Library → load java/okhttp_observer.js
3.  Trigger app activity
4.  Live Feed → filter category=http
5.  Click a request event → args field contains method, URL, headers
6.  Click the matching response event → retval contains status + body
```

### C — Intercept and modify a purchase request

```
Goal: Tamper with an in-app purchase before it leaves the device.

1.  Attach to process
2.  Script Library → load the intercept script for your target flow
3.  Trigger the purchase flow in the app
4.  Switch to the Intercept tab — the message appears
5.  Edit "boughtNum":1 → "boughtNum":99  (or modify price, item ID, etc.)
6.  Click Forward
7.  Live Feed → watch for the server response event
8.  Verify the server accepted or rejected the modified value
```

### D — Match & Replace for response body rewriting

```
Goal: Modify server responses at the Frida layer to test
      client-side trust of server data.

1.  Identify the JSON field to modify in Live Feed
    (e.g. "gems":100 in a game currency response)
2.  Match & Replace tab → Add Rule
    URL Pattern: /api/user/inventory
    Match:       "gems":100
    Replace:     "gems":99999
3.  Enable the rule and click Push to Session
4.  Trigger the relevant app action
5.  Observe whether the client accepts and renders the modified value
```

### E — JWT and auth token capture and replay

```
Goal: Capture a valid auth token for API replay testing.

1.  Attach to process
2.  Load okhttp_observer.js or openssl_observer.js
3.  Trigger any authenticated request in the app
4.  Live Feed → click the outbound network event
5.  Details panel → args contains request headers including Authorization / X-AccessToken
6.  Copy the token value
7.  Use Burp Repeater or a test script to replay the request with the captured token
8.  Test: change the userId in the path to another account (IDOR)
9.  Test: remove the token entirely (missing auth check)
10. Test: use an expired token (token expiry enforcement)
```

### F — IL2CPP / game engine method discovery

```
Goal: Enumerate native methods in a Unity IL2CPP game and find attack surface.

1.  Attach to process
2.  Script Library → load lua_il2cpp_inspector.js
3.  RPC Console → Method: listModules → Call RPC
    Result: libil2cpp.so @ 0x70b5600000 (28 MB)
4.  RPC Console → Method: listExports, Args: "libil2cpp.so" → Call RPC
    Result: GameState_GetCurrentUserId, MallManager_Buy, RewardManager_GetItems, ...
5.  REPL → hook a method by address:
```

```javascript
// In the Frida REPL tab:

// Find the target method address
const addr = Module.findExportByName("libil2cpp.so", "MallManager_Buy");
console.log("MallManager_Buy @", addr);

// Attach a hook to log arguments
Interceptor.attach(addr, {
    onEnter(args) {
        send({
            type: "fridalink_event", category: "call",
            module: "libil2cpp.so", target: "MallManager_Buy",
            summary: "MallManager_Buy() called",
            args: JSON.stringify({
                arg0: args[0].toString(),
                arg1: args[1].toString(),
            }),
            timestamp: new Date().toISOString(),
            thread_id: String(Process.getCurrentThreadId()),
            script_source: "repl",
            severity: "info",
        });
    }
});
```

### G — Root detection bypass

```
Goal: Verify and bypass root detection so the app runs normally
      on the rooted test device.

1.  Attach to process
2.  Custom Scripts tab → write and run:
```

```javascript
// @name Root Detection Bypass
// @category java
// @description Returns false for all common root detection methods.

'use strict';

(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);
        return;
    }
    Java.perform(function () {
        // RootBeer
        try {
            const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            RootBeer.isRooted.implementation         = function () { return false; };
            RootBeer.isRootedWithoutBusyBox.implementation = function () { return false; };
        } catch (_) {}

        // Common file-existence checks
        const File = Java.use('java.io.File');
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            if (path.includes('su') || path.includes('magisk') || path.includes('superuser')) {
                return false;
            }
            return this.exists();
        };

        send({
            type: 'fridalink_event', category: 'script', module: 'root_bypass',
            target: 'load', summary: 'Root detection bypass active',
            timestamp: new Date().toISOString(),
            thread_id: String(Process.getCurrentThreadId()),
            script_source: 'root_bypass', severity: 'info',
        });
    });
})();
```

### H — Certificate pinning bypass (native / OkHttp)

```javascript
// @name Certificate Pinning Bypass
// @category tls
// @description Disables SSL pinning for OkHttp3 and the system TrustManager.
// @version 1.0

'use strict';

(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);
        return;
    }
    Java.perform(function () {
        // OkHttp3 CertificatePinner — return empty pin set
        try {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation =
                function (hostname, peerCertificates) {
                    send({
                        type: 'fridalink_event', category: 'tls',
                        module: 'CertificatePinner', target: hostname,
                        summary: `CertificatePinner.check() bypassed for ${hostname}`,
                        timestamp: new Date().toISOString(),
                        thread_id: String(Process.getCurrentThreadId()),
                        script_source: 'ssl_bypass', severity: 'warn',
                    });
                    // Do nothing — bypass the pin check
                };
        } catch (_) {}

        // Generic X509TrustManager — accept all certs
        try {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext       = Java.use('javax.net.ssl.SSLContext');
            const TrustAll = Java.registerClass({
                name: 'com.fridalink.TrustAll',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {},
                    getAcceptedIssuers: function () { return []; },
                },
            });
            const ctx = SSLContext.getInstance('TLS');
            ctx.init(null, [TrustAll.$new()], null);
            SSLContext.setDefault(ctx);
        } catch (_) {}
    });
})();
```

---

## Demo Mode

No Android device? Run the sidecar in demo mode to explore the UI with synthetic events:

```bash
python -m fridalink_sidecar --demo
```

In Burp → FridaLink, change **Host** to `demo` and click **Connect**. Synthetic events appear every two seconds in the Live Feed, and the Intercept tab receives demo intercept candidates every six seconds. All controls work the same way — click Forward, modify payloads, push rules — without a real device.

Switch back to a real session by changing Host back to `127.0.0.1` and clicking **Connect** again.

---

## Troubleshooting

### "No Android device visible" in the status bar

```bash
# Check that ADB sees the device
adb devices

# Check frida-server is running
adb shell ps | grep frida

# Check version match between client and server
frida --version
adb shell /data/local/tmp/frida-server --version
```

### Script loads but no events appear in Live Feed

Every event must come from a `send()` call with `type: 'fridalink_event'`. Check:
- The script actually loaded — Sidecar Logs tab should show `script loaded: <name>`
- The hooked function is actually being called — try the REPL to probe the symbol address
- `send()` is being called — add a test `send()` at script load time

```javascript
// Add this at the bottom of any script to confirm it loaded
send({
    type: 'fridalink_event', category: 'script', module: 'test',
    target: 'load', summary: 'Script loaded OK',
    timestamp: new Date().toISOString(),
    thread_id: String(Process.getCurrentThreadId()),
    script_source: 'test', severity: 'info',
});
```

### "Frida is not installed" in sidecar logs

```bash
# Make sure you are in the venv and frida is installed
which python
pip show frida
```

### Script fails on spawn but works on attach

Scripts with `Java.use()` must use the `waitForJava` polling pattern (see [Writing Frida Scripts](#writing-frida-scripts-for-fridalink)). Using `setImmediate` for `Java.perform()` fails during spawn because ART is not ready yet.

### `TypeError: not a function` on `Module.findExportByName('lib.so', 'sym')`

Use the instance method form instead:

```javascript
// Wrong (deprecated in Frida 16+)
Module.findExportByName('libssl.so', 'SSL_read');

// Correct
Process.findModuleByName('libssl.so').findExportByName('SSL_read');
// or
Module.getExportByName('libssl.so', 'SSL_read');
```

---

## Architecture

```
FridaLink/
├── src/main/kotlin/fridalink/
│   ├── FridaLinkExtension.kt         Burp extension entry point
│   ├── model/
│   │   └── Models.kt                 All state data classes (immutable)
│   ├── service/
│   │   ├── TelemetrySource.kt        Interface + TelemetryListener
│   │   ├── FridaLinkController.kt    State owner, routes commands, 200ms render loop
│   │   ├── SidecarTelemetrySource.kt WebSocket client to Python sidecar
│   │   └── DemoTelemetrySource.kt    In-memory demo mode (no sidecar needed)
│   └── ui/
│       └── FridaLinkTab.kt           All Swing UI — tabs, tables, REPL terminal
├── python/src/fridalink_sidecar/
│   └── app.py                        WebSocket server, Frida bridge, event normalizer
├── scripts/                          Frida JS scripts organized by category
│   ├── tls/
│   ├── native/
│   ├── java/
│   ├── http/
│   └── helper/
├── docs/
│   ├── architecture.md
│   ├── protocol.md
│   └── script-authoring-guide.md
├── GUIDE.md                          Full tab-by-tab user guide
└── RUNBOOK.md                        Engagement operational runbook
```

**State model:** All UI state lives in a single immutable `FridaLinkState` snapshot. `FridaLinkController` is the only writer. A 200 ms Swing timer calls `render()` on the EDT — the UI is purely a projection of the current state snapshot, never mutated by user actions directly.

**Thread safety:** All Frida callbacks arrive on background threads via `emit_event_threadsafe()` / `emit_intercept_threadsafe()`, which schedule coroutines back onto the asyncio loop. Swing mutations are always dispatched with `SwingUtilities.invokeLater`.

---

## License

FridaLink is intended for authorized security testing only. See `LICENSE` for terms.
