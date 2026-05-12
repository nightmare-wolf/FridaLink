# FridaLink Engagement Runbook

Operational procedures for using FridaLink during an authorized mobile penetration testing engagement.

Assessment: ISI-O-0196 — BLEACH: Soul Resonance  
Target: `com.crunchyroll.bleachsoulres`  
Platform: Android 16, Frida Server 17.9.1  
Tool: FridaLink (Burp Suite Extension + Python Sidecar)

---

## PRE-ENGAGEMENT CHECKLIST

Before any testing session begins:

- [ ] Scope confirmed in writing — package name, server hostnames, test window
- [ ] Rooted test device or Android emulator with Frida server installed
- [ ] Frida server version matches `frida` Python package version (`frida --version`)
- [ ] Burp Suite Professional running with FridaLink jar loaded
- [ ] Python sidecar dependencies installed (`pip install -e python/`)
- [ ] ADB connected and device visible (`adb devices`)
- [ ] Target app installed and can be launched
- [ ] Burp proxy certificate installed on device / system trust store
- [ ] Event log export directory created and path noted

---

## PHASE 0 — ENVIRONMENT SETUP

### 0.1 Start Frida Server on Device

```bash
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

Verify:
```bash
frida-ls-devices
frida-ps -U | grep -i bleach
```

### 0.2 Start the FridaLink Sidecar

```bash
cd FridaLink/python
python -m fridalink_sidecar
```

Expected output:
```
FridaLink sidecar running on ws://127.0.0.1:7766
```

Keep this terminal open for the entire session.

### 0.3 Load FridaLink in Burp

1. Extensions → Add → Java → select `build/libs/fridalink-*.jar`
2. Navigate to the **FridaLink** tab that appears in the Burp top bar
3. In the toolbar: Host = `127.0.0.1`, Port = `7766`
4. Click **Connect**
5. Status bar should show: **Connected to sidecar**

---

## PHASE 1 — RECONNAISSANCE (Days 1–2)

### 1.1 Static Analysis

**FridaLink tab: Static Analysis**

1. Set APK path field to the target `.apk` file
2. Set Decompiled source path to the jadx output directory (if available)
3. Click **Analyze APK**

Review results across subtabs:
- **Certificate** — debug cert? expiry? algorithm?
- **Libraries** — third-party SDKs, known-risky ones highlighted in red
- **URL References** — hardcoded endpoints, non-HTTPS URLs, CDN domains
- **Behavior Profile** — permissions, network_security_config, backup flags

Actionable outputs:
- List of API endpoints → feed into Traffic tab and apj-api-test.py
- Risky SDKs → flag for MASVS-PRIVACY findings
- Missing network_security_config → MASVS-NETWORK-2 finding

### 1.2 ADB Device Checks

**FridaLink tab: Static Analysis → ADB subtab** (or via RPC Console)

1. Set Package field to `com.crunchyroll.bleachsoulres`
2. Click **Run ADB Checks**

Checks performed automatically:
- Root detection bypass status
- Certificate pinning status
- Debuggable flag
- Backup enabled flag
- Installed Frida server process
- Network proxy routing

### 1.3 Traffic Capture (Burp Proxy)

1. Route device traffic through Burp proxy (Wi-Fi proxy or VPN profile)
2. Launch the app, walk through all features: login, store, in-app purchase flow, settings
3. Switch to **FridaLink → Traffic** tab, click **Import from Burp History**
4. Use filter field to narrow by host or path
5. Note all API hosts — these are inputs to Phase 3

---

## PHASE 2 — DYNAMIC INSTRUMENTATION SETUP (Day 2)

### 2.1 Process Attachment

**FridaLink toolbar:**

- Option A — Attach to running process:
  1. Click **Refresh Processes** in the Live Feed toolbar
  2. Select `com.crunchyroll.bleachsoulres` (or `BleachSoulRes`) in the process table
  3. Click **Attach**

- Option B — Spawn with scripts pre-loaded:
  1. Set Spawn field to `com.crunchyroll.bleachsoulres`
  2. In Script Library, enable desired scripts
  3. Click **Spawn + Inject**
  4. Frida spawns the app with scripts already loaded; click **Resume** once instrumentation is ready

### 2.2 Load Core Scripts

**FridaLink → Script Library**

Set library path to `FridaLink/scripts/` and click **Scan Library**.

Required baseline scripts to enable:

| Script | Purpose |
|---|---|
| `tls/ssl_unpin_bypass.js` | Disable SSL pinning |
| `native/openssl_observer.js` | Capture raw SSL_read/SSL_write buffers |
| `lua_il2cpp_inspector.js` | IL2CPP method tracing + RPC exports |
| `native/jni_observer.js` | JNI call tracing |

To load a script:
1. Select it in the library list
2. Click **Load Script** — status changes to **loaded** in the list

### 2.3 Verify Instrumentation

**FridaLink → Live Feed**

- Events should appear within seconds of app activity
- Filter by `category = network` to confirm SSL decryption is working
- Filter by `module = libil2cpp.so` to confirm IL2CPP hooks are active

---

## PHASE 3 — PROTOCOL ANALYSIS (Days 2–3)

### 3.1 Network Protocol Mapping

**FridaLink → Live Feed + Traffic**

1. In Traffic tab: sort by Host — identify all API servers
2. Use **Geo Map** tab → click **Geolocate All** to map server countries
3. In Live Feed: filter `category=network` — observe real-time packet contents
4. Note: game uses KCP (UDP) for battle traffic — visible in `native/kcp_observer.js` events

Key protocol categories observed in this engagement:
- `c2s_mall_buy` — in-app purchase flow (Lua/proto binary message)
- `/api/sonyuser/v3/*` — APJ SDK authentication endpoints
- `/api/sonypayment/v3/*` — payment and product listing endpoints
- WebSocket over WSS for realtime battle state

### 3.2 APJ API Authentication

The game uses APJ SDK with HMAC-SHA256 request signing.

Signature construction (from `apj-api-test.py`):
```
sig_str = METHOD + "&" + "accept" + "&" + sorted_X_headers_kv + "&" + endpoint + "&&" + base64(body)
sig = HMAC-SHA256(sig_str, CHANNEL_SECRET).hexdigest()
```

**Critical:** `X-AccessToken` is NOT included in the signature. It is sent as a plain header.

Capture a valid token:
1. FridaLink → Live Feed, filter `module=openssl_observer` or `target=SSL_read`
2. Look for events with `summary` containing `X-AccessToken`
3. Alternatively: Burp Proxy → HTTP history → filter by `/api/sonyuser/` → copy `X-AccessToken` header value

Test token validity:
```bash
cd scripts
python apj-api-test.py payment   # tests /api/sonypayment/v3/get_product_list
```

Expected success: `{"code":0, "products":[...]}` — `code:0` means auth passed.
Expected failure: `{"code":10001,"msg":"auth failed"}` — token expired or wrong channel.

### 3.3 In-App Purchase Flow

Target: `c2s_mall_buy` protocol message with `boughtNum` field

**Scripts to use (in order of escalation):**

1. `scripts/23-intercept-mall-buy-v3.js` — hooks `lua_rawget` to intercept when the
   proto-serializer reads `boughtNum` from the Lua table, then replaces the
   `lua_rawget` return value with 99 before `lua_tointegerx` reads it.

   Load via REPL or Script Library, then trigger a purchase in the app.
   Watch Live Feed for `category=intercept, target=boughtNum`.

2. If v3 fails, use `scripts/24-capture-product-ids-v2.js` — captures product IDs
   from SSL traffic natively, no Java.use(). Identifies product ID format for
   direct API replay.

### 3.4 RPC Console Queries

**FridaLink → RPC Console**

With `lua_il2cpp_inspector.js` loaded, available RPC methods:

| Method | Args | Returns |
|---|---|---|
| `status` | — | current session status |
| `list_modules` | — | all loaded .so modules |
| `list_exports` | `"libname.so"` | exports from named library |
| `trace_method` | `"ClassName::MethodName"` | begin tracing that IL2CPP method |
| `get_events` | — | buffered events since last call |

Example: call `list_modules` → copy a module name → call `list_exports "libil2cpp.so"`.

---

## PHASE 4 — VULNERABILITY TESTING (Days 3–5)

### 4.1 MASVS Checklist

**FridaLink → MASVS**

Click **Load Checklist** to populate the OWASP MASVS v2 items.

For each item:
- Double-click to set status: **PASS / FAIL / NOT_APPLICABLE**
- Add evidence text (copy from Live Feed event, Traffic response, or ADB output)

Priority controls for this engagement:
- `MASVS-NETWORK-1` — certificate validation (test with invalid cert via Burp)
- `MASVS-NETWORK-2` — network security config present and restrictive
- `MASVS-RESILIENCE-1` — root detection bypass needed
- `MASVS-RESILIENCE-2` — Frida detection — does the app detect and kill the session?
- `MASVS-STORAGE-1` — sensitive data in local files (check via ADB)
- `MASVS-AUTH-1` — session token entropy and expiry

### 4.2 Match & Replace Rules

**FridaLink → Match & Replace**

Use to rewrite response bodies in-flight (applied by the sidecar to Frida-intercepted messages).

Example rules for this engagement:

| URL Pattern | Match | Replace | Purpose |
|---|---|---|---|
| `/api/mall` | `"boughtNum":1` | `"boughtNum":99` | Purchase quantity tamper |
| `/api/sonypayment` | `"price":"999"` | `"price":"0"` | Price zero-out test |
| *(all)* | `"result":false` | `"result":true` | Generic boolean flip |

Rules are pushed live to the sidecar session — no reload needed.

### 4.3 Intercept Queue

**FridaLink → Intercept**

The intercept queue holds messages flagged by Frida scripts for manual review.

For each intercepted message:
1. Select the row — payload appears in the editor below
2. Modify payload text directly
3. Click **Forward** (send modified) or **Drop** (discard the message)

Color coding:
- Green = inbound (server → client)
- Orange = outbound (client → server) — these are the mutation targets

---

## PHASE 5 — FRIDA REPL (Live Exploration)

**FridaLink → Frida REPL**

The REPL evaluates arbitrary JavaScript in the context of the active Frida session.

### REPL Workflow

1. Attach to the process first (Phase 2.1)
2. Load `lua_il2cpp_inspector.js` — this injects the `rpc.exports.evaluate()` helper
3. Switch to **Frida REPL** tab
4. Type any Frida JS expression and press Enter

**Up/Down arrows** navigate command history.

### Useful REPL Commands for This Engagement

```javascript
// See all loaded modules
Process.enumerateModules().map(m => m.name + " @ " + m.base).join("\n")

// Find libgame.so base
Process.findModuleByName("libgame.so").base

// Read 16 bytes at a native pointer
hexdump(ptr("0x7f1234abcd"), { length: 16 })

// Find SSL_read address
Module.findExportByName(null, "SSL_read")

// Check if anti-tamper is active
Module.findExportByName("libmsaoaidsec.so", "antiTamperCheck")

// Enumerate all threads
Process.enumerateThreads().map(t => t.id + " " + t.state).join("\n")

// Find lua_rawget
Module.findExportByName("libgame.so", "lua_rawget")
```

The cheat sheet panel on the right side of the REPL tab contains the full reference.

---

## PHASE 6 — REPORTING

**FridaLink → Report**

1. Set Target, Assessor, Engagement ID, and Output path fields
2. Ensure MASVS items have statuses and evidence filled in
3. Ensure Findings tab has all ApkFinding items created
4. Click **Generate Report** — produces a PDF at the output path

Report sections generated automatically:
- Executive Summary
- Scope and Methodology
- MASVS Compliance Matrix
- Findings (sorted by severity)
- Static Analysis Summary
- Network Traffic Observations
- Appendix: Raw Evidence

---

## SESSION TEARDOWN

At the end of each testing session:

1. **FridaLink → toolbar** → click **Disconnect**
2. Stop the sidecar: `Ctrl+C` in the sidecar terminal
3. Stop Frida server: `adb shell pkill frida-server`
4. Export event log: **Live Feed → Export** → set path and click **Enable Export**, then **Save Now**
5. Save the MASVS checklist state via **MASVS → Export**
6. Commit any new scripts or notes to the assessment repository

---

## TROUBLESHOOTING

### Sidecar won't connect

- Confirm sidecar is running: `netstat -an | grep 7766`
- Check host/port fields in toolbar match sidecar bind address
- Check Burp extension log: Extensions → FridaLink → Output tab

### Frida fails to attach: "Unable to find copied methods in java/lang/Thread"

- Frida 17.x / Android 16 bug — `Java.use()` is broken
- Solution: use native-only scripts — `Interceptor.attach()` with `Module.findExportByName()`
- Scripts in `scripts/native/` and `scripts/tls/` are already native-only

### Token expired (10001 auth failed)

- Capture a fresh token from Burp HTTP history — filter by `/api/sonyuser/` path
- Copy `X-AccessToken` header value from the most recent successful request
- Update `ACCESS_TOKEN` in `scripts/apj-api-test.py`
- Tokens observed in this engagement last approximately 1–2 hours

### REPL returns "Session not attached"

- Ensure a process is attached (Live Feed shows attached PID in status bar)
- Ensure `lua_il2cpp_inspector.js` is loaded (it injects the `rpc.exports.evaluate` helper)
- Try reloading the script via Script Library → select → Load Script

### Events not appearing in Live Feed

- Check that a script is actually loaded and producing `send()` calls
- Filter bar may be hiding events — click **Clear Filters**
- Scroll Lock may be on — click **⏸ Scroll Lock** to toggle off

### Match & Replace rules not applying

- Rules only apply to intercept-mode messages, not passthrough traffic
- A script must be loaded that intercepts the relevant message type
- Check `category=intercept` events in Live Feed to confirm interception is happening

---

## QUICK REFERENCE — TOOLBAR ACTIONS

| Button | Tab | Effect |
|---|---|---|
| Connect | All (toolbar) | Opens WebSocket to sidecar |
| Disconnect | All (toolbar) | Closes WebSocket, stops session |
| Refresh Processes | Live Feed | Queries sidecar for current process list |
| Attach | Live Feed | Attaches Frida to selected PID |
| Detach | Live Feed | Detaches Frida from current session |
| Spawn + Inject | Live Feed | Spawns app with pre-loaded scripts |
| Resume | Live Feed | Resumes a spawned process after injection |
| Load Script | Script Library | Loads selected library script into session |
| Call RPC | RPC Console | Calls named method on attached script |
| Send (Enter) | Frida REPL | Evaluates JS in Frida session context |
| Forward | Intercept | Sends (possibly modified) intercepted message |
| Drop | Intercept | Discards intercepted message |
| Generate Report | Report | Produces PDF assessment report |
