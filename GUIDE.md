# FridaLink — Comprehensive User Guide

A complete reference for installing, navigating, and using FridaLink during mobile penetration testing engagements.

---

## TABLE OF CONTENTS

1. [What Is FridaLink?](#1-what-is-fridalink)
2. [Architecture Overview](#2-architecture-overview)
3. [Installation and First Launch](#3-installation-and-first-launch)
4. [The FridaLink Interface — Tab-by-Tab](#4-the-fridalink-interface--tab-by-tab)
   - [4.1 Toolbar and Status Bar](#41-toolbar-and-status-bar)
   - [4.2 Live Feed](#42-live-feed)
   - [4.3 Match & Replace](#43-match--replace)
   - [4.4 Intercept](#44-intercept)
   - [4.5 Sidecar Logs](#45-sidecar-logs)
   - [4.6 Script Library](#46-script-library)
   - [4.7 Custom Scripts](#47-custom-scripts)
   - [4.8 RPC Console](#48-rpc-console)
   - [4.9 Frida REPL](#49-frida-repl)
   - [4.10 Traffic](#410-traffic)
   - [4.11 Frida Trace](#411-frida-trace)
   - [4.12 MASVS](#412-masvs)
   - [4.13 Static Analysis](#413-static-analysis)
   - [4.14 Geo Map](#414-geo-map)
   - [4.15 Report](#415-report)
5. [How to Use FridaLink — First Time](#5-how-to-use-fridalink--first-time)
6. [Escalating Your Use in an Engagement](#6-escalating-your-use-in-an-engagement)
7. [Script Reference](#7-script-reference)
8. [Message Protocol Reference](#8-message-protocol-reference)
9. [Common Workflows](#9-common-workflows)

---

## 1. WHAT IS FRIDALINK?

FridaLink is a Burp Suite extension that brings **Frida dynamic instrumentation** directly into the Burp workspace. Instead of switching between terminal windows and Burp, you can:

- Watch Frida events in a live table alongside your HTTP traffic
- Intercept and modify native protocol messages
- Run Frida scripts and RPC calls without leaving Burp
- Build an OWASP MASVS checklist, analyze APKs, map server locations, and generate PDF reports — all in one tool

FridaLink is designed for **authorized mobile penetration testing** of Android applications.

---

## 2. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────┐
│                    Burp Suite Professional                  │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   FridaLink Tab                       │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │  │
│  │  │Live Feed │ │ Intercept│ │   REPL   │ │ Report  │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────────┘  │  │
│  │       Kotlin UI (Swing) — renders FridaLinkState      │  │
│  └───────────────────────────────────────────────────────┘  │
│            │   FridaLinkController                          │
└────────────┼────────────────────────────────────────────────┘
             │ WebSocket client
             │ ws://127.0.0.1:7766/ws
             │ JSON messages
             ▼
┌────────────────────────────────────────┐
│         Python Sidecar                 │
│   (fridalink_sidecar / app.py)         │
│                                        │
│  asyncio WebSocket server              │
│  Frida Python API bridge               │
│  Event normalizer                      │
└───────────────────┬────────────────────┘
                    │ frida Python package
                    │ USB / TCP / local
                    ▼
┌────────────────────────────────────────┐
│         Frida Agent (GumJS)            │
│   Injected into target process         │
│                                        │
│  Interceptor.attach() hooks            │
│  rpc.exports                           │
│  send() event emission                 │
└───────────────────┬────────────────────┘
                    │ ptrace / process injection
                    ▼
┌────────────────────────────────────────┐
│         Target Application             │
│   (e.g. com.crunchyroll.bleachsoulres) │
│                                        │
│   libil2cpp.so, libgame.so, libssl.so  │
│   JNI, Lua C API, KCP, OkHttp         │
└────────────────────────────────────────┘
```

### Data Flow — Events

```
Native hook fires in target process
        │
        ▼
send({ type:"event", category:"network", ... })   ← Frida script
        │
        ▼
Python sidecar receives Frida message
        │
        ▼
Sidecar emits WebSocket JSON: {"type":"event", ...}
        │
        ▼
Kotlin controller receives message in onMessage()
        │
        ▼
FridaLinkState updated: events list grows
        │
        ▼
Swing timer fires every 200ms → render() called
        │
        ▼
Live Feed table updated on EDT
```

### Demo Mode vs. Real Mode

FridaLink has two telemetry sources:

```
  ┌─────────────────────────────────────────┐
  │           TelemetrySource (interface)   │
  └──────────────┬──────────────────────────┘
                 │
       ┌─────────┴──────────────┐
       ▼                        ▼
DemoTelemetrySource     SidecarTelemetrySource
  (no sidecar needed)     (real connection)
  synthetic events        live Frida data
  great for UI testing    used in real engagements
```

In Demo mode: connect with host `demo` — synthetic events flow immediately. Useful for testing UI without a device.

---

## 3. INSTALLATION AND FIRST LAUNCH

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Burp Suite Professional | ≥2024.1 | Community edition will not load extensions |
| Java (JDK/JRE) | ≥17 | Must match Burp's JVM |
| Python | ≥3.11 | For the sidecar |
| Frida CLI tools | ≥17.0 | `pip install frida-tools` |
| frida Python package | same as server | Must match server binary |
| ADB | any recent | Android platform tools |
| Rooted Android device | Android 12–16 | Or a rooted emulator |

### Step 1: Build the Extension

```bash
cd FridaLink
./gradlew jar
# Output: build/libs/fridalink-1.0.0.jar (or similar)
```

On Windows use `gradlew.bat jar`.

### Step 2: Install Python Dependencies

```bash
cd FridaLink/python
pip install -e .
```

### Step 3: Load in Burp

1. Open Burp Suite
2. Go to **Extensions** tab → **Add**
3. Extension type: **Java**
4. Extension file: select `build/libs/fridalink-*.jar`
5. Click **Next** — you should see no errors in the Output/Errors tabs
6. The **FridaLink** tab appears in the Burp top navigation bar

### Step 4: Start the Sidecar

```bash
cd FridaLink/python
python -m fridalink_sidecar
```

You should see:
```
FridaLink sidecar running on ws://127.0.0.1:7766
Waiting for Burp connection...
```

### Step 5: Connect

In Burp → FridaLink:
- Host: `127.0.0.1`
- Port: `7766`
- Click **Connect**

Status bar changes from `Disconnected` to `Connected to sidecar`.

---

## 4. THE FRIDALINK INTERFACE — TAB-BY-TAB

### 4.1 Toolbar and Status Bar

The toolbar runs across the top of all tabs:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Host [127.0.0.1] Port [7766] [Connect] [Disconnect]                │
│  Python [python] Root [/path/to/scripts]                            │
│  Spawn [com.package.name] [Spawn+Inject] [Resume]                   │
├─────────────────────────────────────────────────────────────────────┤
│  Status: Connected to sidecar     Selected: BleachSoulRes (1010)    │
│  Session: Attached to pid 1010                                      │
└─────────────────────────────────────────────────────────────────────┘
```

| Field | Purpose |
|---|---|
| Host / Port | Address of the Python sidecar WebSocket server |
| Connect | Opens WebSocket connection to sidecar |
| Disconnect | Cleanly closes the session |
| Python | Path to python executable (used for sidecar auto-launch) |
| Root | Base directory for script paths |
| Spawn | Package identifier for spawn mode |
| Spawn + Inject | Starts app via Frida spawn, injects enabled library scripts |
| Resume | Resumes a spawned process after instrumentation is set up |

**Status Bar (bottom of toolbar):**
- Left: connection and activity status messages
- Middle: currently selected process name and PID
- Right: session attachment state

### 4.2 Live Feed

The main event stream. Every `send()` call from your Frida scripts appears here in real time.

```
┌─────────────────────────────────────────────────────────────────────┐
│  [Refresh]  [Attach]  [Detach]   Filter: [________] Cat:[All ▼]    │
│  Process:[All ▼]  Module:[______]  Target:[________] [✓] Errors     │
│  [⏸ Scroll Lock]  [✓] Export to file  Dir:[___________] File:[___] │
├──────────┬───────────┬──────────┬────────────────┬──────────────────┤
│ Time     │ Process   │ Category │ Module         │ Summary          │
├──────────┼───────────┼──────────┼────────────────┼──────────────────┤
│ 18:34:01 │ BleachRes │ network  │ libssl.so      │ SSL_read 412b    │
│ 18:34:01 │ BleachRes │ call     │ libil2cpp.so   │ GetUserInfo()    │
│ 18:34:02 │ BleachRes │ jni      │ libart.so      │ JNI_GetEnv       │
└──────────┴───────────┴──────────┴────────────────┴──────────────────┘
  ┌───────────────────────────────────────────────────────────────────┐
  │ Event Details (selected row)                                      │
  │ args: {"method":"GetUserInfo","callArgs":[],"result":"..."}       │
  │ severity: info  threadId: 12  scriptSource: lua_il2cpp_inspector  │
  └───────────────────────────────────────────────────────────────────┘
```

**Columns:**
- `Time` — UTC timestamp
- `Process` — process name that generated the event
- `Category` — event type: `call`, `network`, `jni`, `message`, `attach`, `detach`, `script`, `intercept`, `rpc_result`
- `Module` — source library or script name
- `Summary` — human-readable one-liner

**Filter Bar:**
- Text box: free-text search across all columns
- Category dropdown: filter to one category
- Process dropdown: filter to one process
- Module field: exact module name filter
- Target field: exact target name filter
- Errors only: show only `severity=error` events
- Bookmarked: show only events you've starred (right-click → Bookmark)

**Scroll Lock:** When enabled (`⏸`), the table stops auto-scrolling to new events. Current position is held. Toggle off to resume live tail.

**Export:** Enables writing all events to a `.jsonl` file as they arrive. Set the export directory and filename, then check **Export to file**. Events are appended in real time — safe to read while capture runs.

**Event Details Panel:** Click any row to see full event metadata including `args`, `retval`, `backtrace`, `threadId`, `correlationId`, `raw`.

**Right-click context menu on event rows:**
- Bookmark — flag an event for later review
- Copy row — copy the summary line
- Send to Repeater — if the event contains an HTTP request body

### 4.3 Match & Replace

Rules that rewrite message content in-flight, applied by the sidecar to Frida-intercepted messages before forwarding.

```
┌──────────┬────────────┬───────────────┬──────────────┬────────────┐
│ Enabled  │ URL Pattern│ Match         │ Replace      │ Comment    │
├──────────┼────────────┼───────────────┼──────────────┼────────────┤
│ [✓]      │ /api/mall  │ "boughtNum":1 │ "boughtNum":99│ Qty tamper│
│ [ ]      │ (all)      │ "result":false│ "result":true │ Bool flip │
└──────────┴────────────┴───────────────┴──────────────┴────────────┘
  [+ Add Rule]  [Remove Selected]  [Push to Session]
```

Double-click any cell to edit inline. Rules with **Enabled** checked are active.

**URL Pattern:** Leave blank to apply to all URLs. Supports literal string matching or regex (check **Regex** column).

**Push to Session:** Sends all current rules to the sidecar via `update_rules` WebSocket message. Rules become active immediately without reattaching.

### 4.4 Intercept

Messages flagged by Frida scripts for manual review and action.

```
┌──────────┬────────────┬───────────────┬────────────┬──────────────┐
│ Time     │ Process    │ Direction     │ Channel    │ Summary      │
├──────────┼────────────┼───────────────┼────────────┼──────────────┤
│ 18:41:03 │ BleachRes  │ outbound ▶    │ tcp/443    │ POST /mall   │
│ 18:41:04 │ BleachRes  │ inbound  ◀    │ tcp/443    │ 200 OK       │
└──────────┴────────────┴───────────────┴────────────┴──────────────┘
  ┌──────────────────────────────────────────────────────────────────┐
  │ Payload (editable):                                              │
  │ {"action":"buy","itemId":"sword_001","boughtNum":1,"jade":500}   │
  └──────────────────────────────────────────────────────────────────┘
  [Forward]  [Drop]
```

**Workflow:**
1. A Frida script calls the sidecar's intercept channel instead of letting the message through
2. The message appears in the table
3. Select it — the payload is editable
4. Modify anything in the payload text area
5. Click **Forward** to send the (modified) message, or **Drop** to discard it

Color coding in the Direction column:
- Green `◀ inbound` — server to client
- Orange `▶ outbound` — client to server (modification target)

### 4.5 Sidecar Logs

All status messages emitted by the sidecar and Frida session appear here in order.

```
[18:34:00] FridaLink sidecar running on ws://127.0.0.1:7766
[18:34:01] Client connected: fridalink-burp v0.1.0
[18:34:05] Frida attached to pid 1010 (BleachSoulRes)
[18:34:06] Script loaded: lua_il2cpp_inspector.js
[18:34:06] REPL helper loaded
```

Use this tab to:
- Confirm successful attach/spawn
- Diagnose script load failures
- See raw error messages from Frida runtime
- Monitor rule push confirmations

Click **Clear** to reset the log display.

### 4.6 Script Library

Manages the built-in script collection on disk.

```
Library Path: [/path/to/FridaLink/scripts/           ] [Scan]

┌─────────────────────┬──────────┬──────────────────────────────────┐
│ Name                │ Category │ Description                      │
├─────────────────────┼──────────┼──────────────────────────────────┤
│ ssl_unpin_bypass    │ tls      │ Disable SSL certificate pinning  │
│ openssl_observer    │ tls      │ SSL_read/write native hook       │
│ lua_il2cpp_inspector│ native   │ IL2CPP + Lua + RPC inspector     │
│ jni_observer        │ native   │ JNI call tracing                 │
│ kcp_observer        │ native   │ KCP (game UDP) packet logging    │
└─────────────────────┴──────────┴──────────────────────────────────┘

  Script Details:
  Name: openssl_observer.js
  Version: 1.2 | Category: tls
  Description: Hooks SSL_read and SSL_write natively using
               Module.findExportByName. No Java.use().
  
  [Script Content shown below]
  
  [Load Script]  [Load All Enabled]
```

**Scan:** Reads the `scripts/` directory recursively, parses `@metadata` blocks in each script header, and populates the table.

**Load Script:** Sends a `script_run` message to the sidecar with the selected script's content. The script is injected into the current Frida session.

**Load All Enabled:** Loads all scripts with the **Enabled** checkbox checked — used after Spawn to load a batch at once.

### 4.7 Custom Scripts

Write, edit, and run ad-hoc Frida scripts without saving them to disk.

```
  Script Name:     [my-hook                      ]
  Language:        [javascript ▼]
  Description:     [Test hook for login function  ]
  
  ┌──────────────────────────────────────────────────────────────────┐
  │  Interceptor.attach(                                             │
  │    Module.findExportByName("libssl.so", "SSL_read"), {           │
  │      onEnter: function(args) {                                   │
  │        send({ type:"event", category:"network", ... });          │
  │      }                                                           │
  │  });                                                             │
  └──────────────────────────────────────────────────────────────────┘
  
  [Save]  [Run Script]  [Delete]
```

Saved custom scripts persist in the Burp extension state between sessions.

**Run Script** injects the current editor content directly — no save required.

### 4.8 RPC Console

Call named methods on scripts that expose `rpc.exports`.

```
  Method: [list_modules    ]  Args: [                        ]
  [Call RPC]                         Status: RPC dispatched
  
  ┌──────────────────────────────────────────────────────────────────┐
  │ [18:41:10] status() →                                            │
  │   { "attached": true, "pid": 1010, "scripts": 3 }               │
  │                                                                  │
  │ [18:41:22] list_modules() →                                      │
  │   libgame.so @ 0x70f1234000                                      │
  │   libil2cpp.so @ 0x70b5600000                                    │
  │   libssl.so @ 0x70a1234000                                       │
  └──────────────────────────────────────────────────────────────────┘
```

**Method:** Name of the `rpc.exports` function to call.

**Args:** Comma-separated or JSON array of arguments. Example: `"libil2cpp.so"` or `["libil2cpp.so", true]`.

Results arrive as `rpc_result` events in the Live Feed and are also displayed in the RPC Console output area.

Requires `lua_il2cpp_inspector.js` (or any script with `rpc.exports`) to be loaded.

### 4.9 Frida REPL

An interactive JavaScript terminal connected to the live Frida session.

```
┌─────────────────────────────────┬──────────────────────────────────┐
│  REPL Terminal (dark terminal)  │  Cheat Sheet                     │
│                                 │  ─────────────────────────────── │
│  [18:41:00] > Process.arch      │  PROCESS                         │
│  "arm64"                        │  Process.arch                    │
│                                 │  Process.id                      │
│  [18:41:05] > Module.           │  Process.enumerateModules()      │
│    findExportByName(null,        │  Process.findModuleByName("x")  │
│    "SSL_read")                  │  Process.enumerateThreads()      │
│  "0x7f1a2b3c4d"                │                                  │
│                                 │  MEMORY                          │
│  [18:41:12] > hexdump(ptr(      │  ptr("0x...").readCString()      │
│    "0x7f1a2b3c4d"), {           │  hexdump(ptr("0x..."))           │
│    length: 32 })                │  Memory.scan(base, size, pat)    │
│  0x7f1a2b3c4d  48 81 ec ...     │                                  │
│                                 │  HOOKS                           │
│  ┌──────────────────────────┐   │  Interceptor.attach(addr, {...}) │
│  │ > _                      │   │  Interceptor.replace(addr, fn)   │
│  └──────────────────────────┘   │  NativeFunction(addr, ret, args) │
└─────────────────────────────────┴──────────────────────────────────┘
```

**Enter** submits the current line.  
**Up / Down arrows** navigate command history (within the session).

**How it works:**
1. You type JS code in the input field
2. FridaLink sends `{"type":"repl_eval","code":"..."}` to the sidecar
3. Sidecar calls `script.exports.evaluate(code)` on the REPL helper script
4. REPL helper runs `(0, eval)(code)` in the Frida JS context
5. Result is serialized and sent back as `{"type":"repl_result","result":"..."}`
6. Output appears in the terminal pane, color-coded:
   - Grey — timestamp
   - Light-green `>` prompt + code
   - Light-grey — return value
   - Red — error message

The **cheat sheet** panel on the right covers:
- Process / Module / Memory / Pointer APIs
- Native hooks (`Interceptor.attach`, `NativeFunction`)
- Backtrace capture
- Java bridge (when applicable)
- RPC exports pattern
- Lua C API offsets
- SSL / network hooks
- Useful one-liners

### 4.10 Traffic

Burp HTTP proxy traffic imported and analyzed inside FridaLink.

```
  [Import from Burp History]  Filter: [_______________]
  
┌──────┬───────┬──────────────────────┬──────┬─────────┬────────────┐
│ #    │ Method│ Host                 │ Path │ Status  │ Mime       │
├──────┼───────┼──────────────────────┼──────┼─────────┼────────────┤
│ 0001 │ POST  │ api.example.com      │ /buy │ 200     │ JSON       │
│ 0002 │ GET   │ cdn.example.com      │ /img │ 200     │ image/png  │
└──────┴───────┴──────────────────────┴──────┴─────────┴────────────┘

  Request Headers:      Response Body:
  POST /buy HTTP/1.1    {"code":0,"result":"success"}
  Host: api.example.com
  X-AccessToken: Gmwz...
```

Use to:
- Review all endpoints the app contacts
- Export a host list for the Geo Map tab
- Identify signing patterns in request headers
- Find hardcoded tokens or API keys in responses

### 4.11 Frida Trace

Integrates `frida-trace` as a subprocess, streaming output into FridaLink.

```
  Target: [com.crunchyroll.bleachsoulres         ]
  Include: [SSL_*,ikcp_*,GameStart,GameEnd        ]
  Exclude: [malloc,free                           ]
  Work Dir: [/path/to/frida/handlers              ]
  [Start Trace]  [Stop]
  
  ┌──────────────────────────────────────────────────────────────────┐
  │ Tracing...                                                       │
  │  1234 ms  SSL_read()                                             │
  │  1235 ms  ikcp_recv()                                            │
  │  1235 ms  SSL_read()                                             │
  └──────────────────────────────────────────────────────────────────┘
```

Frida Trace generates handler `.js` files in the work directory automatically — you can edit them live and the trace hot-reloads.

### 4.12 MASVS

OWASP MASVS v2 compliance checklist with evidence tracking.

```
  [Load Checklist]  [Export]

┌──────────────────┬──────────┬────────────────────────┬──────────┐
│ Control ID       │ Level    │ Title                  │ Status   │
├──────────────────┼──────────┼────────────────────────┼──────────┤
│ MASVS-NETWORK-1  │ L1       │ Certificate validation │ FAIL  ✗  │
│ MASVS-NETWORK-2  │ L1       │ Network security config│ PASS  ✓  │
│ MASVS-STORAGE-1  │ L1       │ Sensitive data at rest │ NOT_TESTED│
│ MASVS-RESILIENCE-1│ R       │ Root detection         │ FAIL  ✗  │
└──────────────────┴──────────┴────────────────────────┴──────────┘

  Details panel (selected row):
  MASVS-NETWORK-1 — TLS Certificate Validation (MASTG-TEST-0021)
  Status: [FAIL ▼]
  Evidence: [SSL cert replaced with Burp CA — no error thrown, traffic
             proxied successfully via Burp on 2026-04-24              ]
  Notes: [App uses OkHttp with custom TrustManager, no system store   ]
```

Double-click the **Status** cell to cycle: NOT_TESTED → PASS → FAIL → NOT_APPLICABLE.

The evidence text area accepts free text, paste from Live Feed event details, ADB output, or screenshots.

### 4.13 Static Analysis

APK inspection without installing the app.

```
┌─── Subtabs ────────────────────────────────────────────────────────┐
│  Certificate │ Libraries │ URL References │ Behavior │ Findings    │
└────────────────────────────────────────────────────────────────────┘

  APK Path: [/path/to/bleach.apk        ] [Analyze APK]
  Decomp Src: [/path/to/jadx-output/    ] [Scan Source]
```

**Certificate subtab:** Subject, issuer, algorithm, key size, expiry, SHA-256 fingerprint. Debug cert warning shown in red.

**Libraries subtab:** SDK packages detected in dex + .so file names.

```
┌──────────────────────┬────────────┬──────────────────────────────┐
│ Package              │ Risk       │ Display Name                 │
├──────────────────────┼────────────┼──────────────────────────────┤
│ com.bytedance        │ HIGH  ■    │ ByteDance SDK                │
│ com.unity3d          │ none       │ Unity 3D Engine              │
│ com.appsflyer        │ medium  ■  │ AppsFlyer Attribution        │
└──────────────────────┴────────────┴──────────────────────────────┘
```

Click a library row to see verbose details: what it does, privacy implications, known incidents.

**URL References subtab:** All hardcoded URLs extracted from dex, assets, and strings.

**Behavior Profile:** Permissions, backup config, debuggable flag, network security config, exported components.

**Findings subtab:** All APK analysis findings with severity, CWE/CVSS, and MASVS reference.

### 4.14 Geo Map

Maps server IP addresses to physical locations on a world map.

```
  [Geolocate All]  [Analyze Foreign Traffic]

  ┌────────────────────────────────────────────────────────────────┐
  │  (ASCII world map — servers marked as dots by country)         │
  │                                                                │
  │    .US  .JP  .SG  .CN  .DE                                     │
  └────────────────────────────────────────────────────────────────┘

┌──────────────┬─────┬─────────┬────────────┬────────────────────┐
│ IP           │ CC  │ Country │ Org        │ Threat             │
├──────────────┼─────┼─────────┼────────────┼────────────────────┤
│ 103.4.x.x    │ JP  │ Japan   │ Sony Music │                    │
│ 34.x.x.x     │ US  │ United States│ Google│                   │
│ 1.x.x.x      │ CN  │ China   │ Alibaba   │ Data Broker (CN) ⚠ │
└──────────────┴─────┴─────────┴────────────┴────────────────────┘

  Foreign Traffic Summary:
  3 servers outside US — 1 CN flagged as Data Broker
```

**Geolocate All:** Sends all unique IPs from Traffic tab through a geolocation API and populates the table and map.

**Analyze Foreign Traffic:** Summarizes servers by country, flags tracking/data-broker domains, outputs a plain-text summary useful for the report.

### 4.15 Report

Generates a PDF penetration testing report.

```
  Target: [Bleach: Soul Resonance (com.crunchyroll.bleachsoulres)  ]
  Assessor: [Luis Del Rio          ]  Engagement: [ISI-O-0196]
  Output: [/home/user/FridaLink_Report.pdf                          ]
  
  [Generate Report]
  
  ┌──────────────────────────────────────────────────────────────────┐
  │ [18:50:00] Collecting findings...                                │
  │ [18:50:01] MASVS matrix: 23 items (8 FAIL, 12 PASS, 3 N/A)      │
  │ [18:50:02] PDF written: /home/user/FridaLink_Report.pdf          │
  └──────────────────────────────────────────────────────────────────┘
```

The report is populated from:
- **MASVS** tab — compliance matrix
- **Static Analysis → Findings** tab — all `ApkFinding` items
- **Traffic** tab — endpoint summary
- **Geo Map** — server country distribution

---

## 5. HOW TO USE FRIDALINK — FIRST TIME

Follow this sequence for your first engagement. Each step builds on the previous.

### Step 1 — Verify Connectivity (5 minutes)

1. Start sidecar, connect from Burp (see Section 3)
2. To verify without a device, connect with host `demo`:
   - Change Host field to `demo`
   - Click Connect
   - Live Feed should show synthetic events within 2 seconds
   - This confirms the extension loaded correctly

### Step 2 — Connect to Real Device (10 minutes)

1. Start Frida server on the device (see RUNBOOK Phase 0.1)
2. Change host back to `127.0.0.1`, port `7766`
3. Click Connect
4. In Live Feed toolbar: click **Refresh Processes**
5. Your target app's process should appear in the process table

If it doesn't appear:
- Ensure the app is running on the device
- Check `adb devices` — device must be visible
- Check Sidecar Logs tab for error messages

### Step 3 — Attach and Load Your First Script (5 minutes)

1. Select the target process in the Live Feed table
2. Click **Attach** — status bar shows `Attached to pid XXXX`
3. Go to **Script Library** tab
4. Set path to `FridaLink/scripts/` and click **Scan**
5. Select `tls/ssl_unpin_bypass.js`
6. Click **Load Script**
7. Trigger a network request in the app
8. Switch back to **Live Feed** — you should see events with `module = libssl.so`

### Step 4 — Read the Events (5 minutes)

Events have a consistent structure:

```
timestamp | process | category | module | summary
args / retval / backtrace (in details panel)
```

For network traffic:
- `category = network` — HTTP/HTTPS/UDP traffic
- `module = libssl.so` — decrypted TLS bytes
- `summary` — first ~80 chars of the payload or a description

Click any row to see full details below the table.

### Step 5 — Use the REPL for Quick Exploration

1. Go to **Frida REPL** tab
2. Type `Process.arch` and press Enter — should return `"arm64"`
3. Type `Process.enumerateModules().length` — count of loaded modules
4. Type `Module.findExportByName(null, "SSL_read")` — address of SSL_read

This is your interactive Frida console. Anything you can type into `frida -U -e "..."` you can type here.

---

## 6. ESCALATING YOUR USE IN AN ENGAGEMENT

This section describes how to progress from basic connectivity to advanced protocol manipulation.

### Stage 1 — Passive Observation

**Goal:** Understand what the app does at runtime without modifying anything.

Scripts to load:
- `tls/ssl_unpin_bypass.js` — get past certificate pinning
- `native/openssl_observer.js` — capture decrypted traffic buffers
- `native/jni_observer.js` — see which native Java calls are made

What to look for in Live Feed:
- API endpoints being called (filter `category=network`)
- Authentication headers (`X-AccessToken`, `Authorization`, `X-Signature`)
- Game state updates in response bodies
- JNI calls indicating security checks

**Deliverable:** A list of all API endpoints and their request/response patterns.

### Stage 2 — Static Correlation

**Goal:** Correlate live behavior with static APK analysis.

1. Run **Static Analysis** with the APK path
2. Compare hardcoded URLs found statically with live traffic in Traffic tab
3. Map detected SDKs to observed network traffic destinations in Geo Map
4. Mark MASVS items based on static evidence

**Deliverable:** Populated MASVS checklist with ~30% items resolved from static analysis alone.

### Stage 3 — Active Probing

**Goal:** Test specific security controls by probing with modified requests.

1. Capture a valid `X-AccessToken` from Live Feed or Burp history
2. Use `scripts/apj-api-test.py` to replay API calls:
   ```bash
   python apj-api-test.py payment   # tests product list endpoint
   python apj-api-test.py forge     # tests forged request
   ```
3. Modify request parameters and observe responses
4. Test IDOR by substituting other users' IDs into `userId` parameters
5. Test for missing authorization by removing the token entirely

**Deliverable:** Confirmed auth bypass or IDOR findings with evidence (request/response pairs).

### Stage 4 — Protocol Manipulation

**Goal:** Modify in-flight game protocol messages.

1. Load `native/openssl_observer.js` — observe raw protocol payloads
2. Use **Match & Replace** to rewrite known fields in responses
3. Load intercept scripts (e.g. `scripts/23-intercept-mall-buy-v3.js`)
4. Trigger the target flow in the app (e.g. purchase from the shop)
5. When an intercept appears, modify the payload and click **Forward**

**Escalation path for purchase flow:**
```
Stage 3: Identify product IDs from API response
   ↓
Stage 4a: Use Match & Replace to zero out prices in responses
   ↓
Stage 4b: Load intercept script to hook lua_rawget and modify boughtNum
   ↓
Stage 4c: If both fail, use RPC Console to call game functions directly
```

**Deliverable:** Confirmed business logic bypass (quantity, price, or item manipulation).

### Stage 5 — Deep Runtime Analysis

**Goal:** Understand the game engine internals, find additional attack surface.

1. Load `lua_il2cpp_inspector.js` (the main inspector script with full RPC)
2. Use **RPC Console** to call `list_modules` — note all `.so` files
3. Call `list_exports "libgame.so"` — see all exported functions
4. Use **Frida REPL** to explore:
   ```javascript
   // Find interesting game functions
   Process.enumerateModules()
     .filter(m => m.name.includes("game"))
     .map(m => m.path)
   
   // Scan for the string "boughtNum" in memory
   Memory.scanSync(ptr("0x70f1234000"), 0x1000000, "62 6f 75 67 68 74 4e 75 6d")
   ```
5. Use **Frida Trace** with IL2CPP method patterns to find undocumented game functions

**Deliverable:** Map of game engine internals, potential RPC endpoints, additional intercept targets.

### Stage 6 — Report Generation

**Goal:** Produce a deliverable from all collected evidence.

1. Ensure all MASVS items are marked with status + evidence
2. Ensure all findings are entered in **Static Analysis → Findings** with CVSS scores
3. Fill in **Report** tab fields
4. Click **Generate Report**
5. Review the PDF — add any missing narrative context manually

---

## 7. SCRIPT REFERENCE

### Built-in Script Library (`scripts/tls/`)

| Script | What It Does |
|---|---|
| `ssl_unpin_bypass.js` | Hooks TrustManager and HostnameVerifier to accept all certs |
| `anti_tamper_bypass.js` | Hooks common anti-tamper check functions to return safe values |
| `openssl_observer.js` | Hooks SSL_read/SSL_write natively — dumps decrypted buffers |
| `caller_net_observer.js` | Logs which code called each network function (call stack) |
| `unity_curl_hook.js` | Hooks Unity's libcurl to capture HTTP requests |
| `kcp_observer.js` | Logs KCP UDP packet contents (game battle traffic) |

### Built-in Script Library (`scripts/native/`)

| Script | What It Does |
|---|---|
| `il2cpp_observer.js` | Traces IL2CPP method calls by scanning method table |
| `jni_observer.js` | Logs JNI function calls and their Java method names |
| `dns_observer.js` | Logs all DNS lookups and resolutions |
| `hades_observer.js` | Traces Hades game framework calls (if present) |
| `jni_observer.js` | JNI call logging |
| `lua_inspector.js` | Hooks Lua C API functions (lua_call, lua_pcall) |
| `nw_message_reader.js` | Reads network message buffers |
| `nw_protocol_spy.js` | Decodes protocol framing |
| `proto_buffer_dump.js` | Dumps protobuf-encoded messages |
| `recv_injector.js` | Injects custom bytes into recv() buffer |
| `reward_tamper.js` | Example: modifies reward payload values |
| `socket_observer.js` | Logs TCP socket send/recv operations |
| `udp_endpoint_observer.js` | Logs all UDP endpoints the app contacts |
| `unity_bridge_observer.js` | Logs Unity ↔ native bridge calls |
| `combat_probe.js` | Probes combat state variables |

### Assessment Scripts (`scripts/21-24`)

| Script | Purpose | Status |
|---|---|---|
| `21-intercept-mall-buy.js` | Hooks lua_setfield to intercept buy message | Superseded |
| `22-intercept-mall-buy-v2.js` | Hooks lua_tointegerx | Superseded |
| `23-intercept-mall-buy-v3.js` | Hooks lua_rawget, TTL-gated replacement | Active |
| `24-capture-product-ids-v2.js` | SSL_read scan for product ID patterns | Active |

### Main Inspector (`lua_il2cpp_inspector.js`)

The primary RPC-capable script. Exposes via `rpc.exports`:

| RPC Method | Args | Returns |
|---|---|---|
| `status` | — | `{ attached, pid, scripts }` |
| `list_modules` | — | array of `{ name, base, size }` |
| `list_exports` | `libname` | array of export names |
| `trace_method` | `ClassName::Method` | void, begins tracing |
| `get_events` | — | buffered events array |
| `evaluate` | `code` | `{ ok, result }` or `{ ok:false, error }` |

---

## 8. MESSAGE PROTOCOL REFERENCE

Full WebSocket message type reference. All messages are JSON.

### From Burp to Sidecar

```json
{ "type": "hello", "client": "fridalink-burp", "version": "0.1.0" }
{ "type": "process_refresh" }
{ "type": "attach", "pid": 1010 }
{ "type": "detach" }
{ "type": "spawn", "identifier": "com.example.app", "scripts": [{"name":"...", "content":"..."}] }
{ "type": "resume" }
{ "type": "script_run", "script": {"id":"...", "name":"...", "language":"javascript", "description":"...", "content":"..."} }
{ "type": "intercept_action", "id": "abc123", "action": "forward", "payload": "{...modified...}" }
{ "type": "update_rules", "rules": [{"id":"r1", "enabled":true, "matchText":"x", "replaceText":"y", ...}] }
{ "type": "rpc_call", "method": "status", "args": [] }
{ "type": "repl_eval", "code": "Process.arch" }
```

### From Sidecar to Burp

```json
{ "type": "process_list", "processes": [{"pid":1010, "name":"BleachSoulRes", "platform":"android", "state":"foreground", "selected":true, "attached":false}] }
{ "type": "session_summary", "summary": {"pid":1010, "name":"BleachSoulRes"} }
{ "type": "event", "timestamp":"...", "process":"BleachSoulRes", "category":"network", "module":"libssl.so", "target":"SSL_read", "summary":"...", "args":"...", "severity":"info" }
{ "type": "event_batch", "events": [...] }
{ "type": "intercept", "id":"abc123", "timestamp":"...", "process":"...", "direction":"outbound", "channel":"tcp/443", "summary":"...", "payload":"{...}" }
{ "type": "intercept_batch", "items": [...] }
{ "type": "scripts", "scripts": [{"id":"...", "name":"...", "language":"javascript", "description":"...", "content":"..."}] }
{ "type": "status", "message": "Attached to pid 1010" }
{ "type": "repl_result", "code": "Process.arch", "result": "arm64", "error": null }
```

---

## 9. COMMON WORKFLOWS

### Workflow A: SSL Traffic Capture

```
1. Attach to process
2. Load: tls/ssl_unpin_bypass.js
3. Load: native/openssl_observer.js
4. Trigger HTTPS activity in app
5. Live Feed → filter category=network
6. Click event → details show decrypted buffer
```

### Workflow B: Intercept and Modify a Purchase Request

```
1. Attach to process
2. Load: scripts/23-intercept-mall-buy-v3.js
3. Trigger purchase in app
4. Switch to Intercept tab — message appears
5. Edit "boughtNum":1 → "boughtNum":99
6. Click Forward
7. Observe server response in Live Feed
```

### Workflow C: API Replay with Modified Parameters

```
1. Capture X-AccessToken from Live Feed or Burp HTTP history
2. Edit scripts/apj-api-test.py:
   ACCESS_TOKEN = "captured-token-here"
   PRODUCT_ID   = "item-id-from-store"
3. Run: python apj-api-test.py payment
4. If code=0: auth works — proceed to forge
5. If code=10001: token expired — capture fresh from Burp
```

### Workflow D: IL2CPP Method Discovery

```
1. Attach to process
2. Load: lua_il2cpp_inspector.js
3. RPC Console → Method: list_modules → Call RPC
4. Find "libil2cpp.so" in results
5. Method: list_exports, Args: "libil2cpp.so" → Call RPC
6. Search results for method names related to your target (e.g. "GetUser", "Buy")
7. Frida REPL: Interceptor.attach(Module.findExportByName("libil2cpp.so","TargetMethod"), {...})
```

### Workflow E: Match & Replace Rule for Response Rewriting

```
1. Identify the JSON field to modify in Live Feed (e.g. "gems":100)
2. Match & Replace tab → click "+ Add Rule"
3. URL Pattern: leave blank or set specific path
4. Match: "gems":100
5. Replace: "gems":9999
6. Ensure Enabled checkbox is checked
7. Click "Push to Session"
8. Trigger the relevant action in app — observe modified response
```
