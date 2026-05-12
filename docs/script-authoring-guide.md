# FridaLink Script Authoring Guide

A FridaLink library script is a plain `.js` file that Frida executes inside the target process. FridaLink reads the file from disk, passes it to the sidecar, and the sidecar loads it via `session.create_script()`. This document covers every rule you must follow for a script to load correctly, appear in the library, and emit events visible in the Live Feed.

---

## 1. File location and naming

Place the file anywhere under the directory you point the Script Library at. FridaLink walks the tree recursively and picks up every `.js` file it finds. Subdirectory names are used as the default category if no `@category` tag is present.

```
scripts/
  http/
    my_http_hook.js        → category "http"
  native/
    my_native_hook.js      → category "native"
  my_loose_script.js       → category "general"
```

File names can contain spaces but simple lowercase-with-underscores names are easiest to work with.

---

## 2. Metadata header

The first lines of the file must contain metadata tags as single-line comments. FridaLink's parser looks for lines matching `// @tagname value` anywhere in the file, but putting them at the top is the convention.

```javascript
// @name My Hook Script
// @category http
// @description One sentence describing what this script observes or modifies.
// @version 1.0
```

| Tag | Required | Effect if missing |
|---|---|---|
| `@name` | Recommended | Falls back to the filename without extension |
| `@category` | Recommended | Falls back to the parent directory name, then `"general"` |
| `@description` | Optional | Left blank in the library panel |
| `@version` | Optional | Defaults to `"1.0"` |

Category is a free-form string. The built-in scripts use: `http`, `native`, `tls`, `webview`, `java`, `helper`. Use whatever makes sense for your script — it only affects sorting and display.

---

## 3. Script structure

### 3a. Scripts that use the Java API (most scripts)

Any script that calls `Java.use()`, `Java.perform()`, or `Java.registerClass()` must wait for the Android Runtime (ART) to be ready before calling those APIs. This is mandatory when the script is pre-loaded during a spawn, because spawn pauses the process before ART has started.

**Always use this pattern instead of `setImmediate`:**

```javascript
'use strict';

// @name My Java Hook
// @category java
// @description Hooks com.example.Foo.bar() and emits args/retval.
// @version 1.0

(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);   // retry every 50 ms until ART is up
        return;
    }
    Java.perform(function () {
        // all Java hooks go here
    });
})();
```

**Do not use `setImmediate(() => { Java.perform(...) })`** — that pattern works when attaching to a running process but fails on spawn because `setImmediate` fires before ART starts, and `Java` is not yet defined.

### 3b. Scripts that use the native API only

Scripts that only call `Interceptor.attach`, `Module.findExportByName`, `Process.*`, etc. do not need `waitForJava` — the native API is available immediately.

```javascript
'use strict';

// @name My Native Hook
// @category native
// @description Hooks libc write() and logs byte counts.
// @version 1.0

const ptr = Process.findModuleByName('libc.so').findExportByName('write');
if (ptr) {
    Interceptor.attach(ptr, {
        onEnter(args) {
            this.fd  = args[0].toInt32();
            this.len = args[2].toInt32();
        },
        onLeave(retval) {
            emit({ category: 'native', module: 'libc', target: 'write',
                   summary: `write fd=${this.fd} bytes=${this.len}` });
        },
    });
}
```

---

## 4. Emitting events

Every event visible in the Live Feed comes from a `send()` call with a specific shape. Copy this `emit()` helper verbatim into your script:

```javascript
function emit(event) {
    send({
        type:          'fridalink_event',
        timestamp:     new Date().toISOString(),
        thread_id:     String(Process.getCurrentThreadId()),
        script_source: TAG,           // TAG is a const you define (see below)
        severity:      'info',        // default; override per-event
        ...event,                     // caller fields override defaults
    });
}
```

Define `TAG` at the top of your script to identify it in the module column:

```javascript
const TAG = 'my_hook';
```

### Event fields

| Field | Type | Description |
|---|---|---|
| `category` | string | Groups events in filters. Use `http`, `native`, `tls`, `java`, `webview`, `script`, `error`, or your own. |
| `module` | string | The class, library, or subsystem being observed. e.g. `okhttp3`, `libc`, `libgame.so` |
| `target` | string | The specific method, URL, symbol, or endpoint. |
| `summary` | string | Human-readable one-liner shown in the event table. |
| `severity` | string | `info` (default), `warn`, `error`. Controls row colour in the Live Feed. |
| `args` | string | String representation of call arguments. |
| `retval` | string | String representation of the return value. |
| `backtrace` | string | Newline-separated call stack. Populate with `Thread.backtrace()` — see section 7. |
| `correlation_id` | string | Optional. Link related events (e.g. request + response share an ID). |

Only `category`, `module`, `target`, and `summary` are required. All other fields are optional and default to empty string.

### Severity colours in Live Feed

| Value | Row colour |
|---|---|
| `info` | Default background |
| `warn` | Light yellow |
| `error` | Light red |

---

## 5. Minimal working script — Java hook

```javascript
// @name Auth Token Observer
// @category java
// @description Intercepts AuthManager.getToken() and logs the returned token.
// @version 1.0

'use strict';

const TAG = 'auth';

function emit(event) {
    send({
        type: 'fridalink_event',
        timestamp: new Date().toISOString(),
        thread_id: String(Process.getCurrentThreadId()),
        script_source: TAG,
        severity: 'info',
        ...event,
    });
}

(function waitForJava() {
    if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(waitForJava, 50);
        return;
    }
    Java.perform(function () {

        var AuthManager = Java.use('com.example.auth.AuthManager');

        AuthManager.getToken.implementation = function () {
            var token = this.getToken();
            emit({
                category: 'java',
                module:   'AuthManager',
                target:   'getToken',
                summary:  'getToken() called',
                retval:   token ? token.toString() : 'null',
            });
            return token;
        };

        emit({ category: 'script', module: TAG, target: 'load',
               summary: 'Auth token observer loaded' });
    });
})();
```

---

## 6. Minimal working script — native hook

```javascript
// @name Open Syscall Observer
// @category native
// @description Logs every file path passed to libc open().
// @version 1.0

'use strict';

const TAG = 'open_observer';

function emit(event) {
    send({
        type: 'fridalink_event',
        timestamp: new Date().toISOString(),
        thread_id: String(Process.getCurrentThreadId()),
        script_source: TAG,
        severity: 'info',
        ...event,
    });
}

function resolveExport(mod, name) {
    try {
        const m = Process.findModuleByName(mod);
        if (m) { const p = m.findExportByName(name); if (p) return p; }
    } catch (_) {}
    for (const m of Process.enumerateModules()) {
        const p = m.findExportByName(name);
        if (p) return p;
    }
    return null;
}

const openPtr = resolveExport('libc.so', 'open');
if (openPtr) {
    Interceptor.attach(openPtr, {
        onEnter(args) {
            try { this.path = args[0].readCString(); } catch (_) { this.path = '?'; }
        },
        onLeave(retval) {
            emit({
                category: 'native', module: 'libc', target: this.path,
                summary:  `open("${this.path}") → fd=${retval.toInt32()}`,
                args:     this.path,
                retval:   String(retval.toInt32()),
            });
        },
    });
    emit({ category: 'script', module: TAG, target: 'load', summary: 'open() observer loaded' });
} else {
    emit({ category: 'error', module: TAG, target: 'load',
           summary: 'open() not found — hook skipped', severity: 'warn' });
}
```

---

## 7. Backtraces

Backtraces show what called the hooked function. Rules for safe use:

- **Do not capture backtraces inside `dlopen` hooks.** The Android linker holds `dl_mutex` for the entire call. Any backtrace mechanism that enumerates modules will try to acquire the same lock → deadlock → watchdog kills the process.
- For all other hooks (Java methods, `connect`, `send`, etc.), capture in `onEnter` — not `onLeave`. The stack is in its cleanest state on the way in.
- Use `Backtracer.ACCURATE` (uses the platform's CFI/DWARF tables). It returns an empty array gracefully on stripped binaries rather than crashing.

```javascript
// inside onEnter only, never inside dlopen
this.bt = '';
try {
    this.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join('\n    ');
} catch (_) {}

// then include it in the emit() call:
emit({
    category: 'native', module: 'libc', target: this.endpoint,
    summary:  `connect → ${this.endpoint}`,
    backtrace: this.bt,
});
```

The backtrace appears under the **CALL STACK** section in the Event Details panel.

---

## 8. Receiving messages from the host (Match & Replace)

Scripts can receive messages pushed from the Burp extension via `script.post()`. Use `recv()` to handle them. `recv()` is one-shot — re-arm it inside the callback to receive future messages.

```javascript
function listenForRules() {
    recv('update_rules', function (message) {
        activeRules = (message.rules || []).filter(r => r.enabled !== false);
        listenForRules(); // re-arm for next push
    });
}
listenForRules();
```

The built-in `okhttp_observer.js` uses this pattern to apply Match & Replace rules pushed from the M&R tab.

---

## 9. Common mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| `setImmediate(() => { Java.perform(...) })` | `ReferenceError: 'Java' is not defined` on spawn | Replace with the `waitForJava` polling pattern |
| `if (!Java.available)` in `waitForJava` | `ReferenceError: 'Java' is not defined` — the check itself throws before it can protect | Must be `if (typeof Java === 'undefined' \|\| !Java.available)` — `typeof` never throws |
| Calling `Thread.backtrace()` inside a `dlopen` hook | Process killed by watchdog on resume | Never call backtrace inside dlopen hooks |
| Passing a JS array `[obj]` where Java expects `Type[]` | Silent crash when the hooked method is called | Use `Java.array('Lpackage/Type;', [obj])` |
| Using `Module.findExportByName('lib.so', 'sym')` (static 2-arg form) | `TypeError: not a function` on Frida 16+ | Use `Process.findModuleByName('lib.so').findExportByName('sym')` |
| Forgetting to re-arm `recv()` | Only the first pushed message is received | Call `recv(type, cb)` again at the end of the callback |
| Hooking an interface method with `.implementation =` without calling `this.$super` | Original method is silently dropped | Call `return this.originalMethod(...)` or `this.$super.method(...)` at the end |

---

## 10. Quick reference

```
.js file anywhere under the library directory
│
├── // @name        Display name in the library panel
├── // @category    Column + folder for sorting
├── // @description One-line description
└── // @version     Version string
```

```
send({
    type:           'fridalink_event',   ← required, tells sidecar this is a live event
    timestamp:      new Date().toISOString(),
    thread_id:      String(Process.getCurrentThreadId()),
    script_source:  TAG,
    severity:       'info' | 'warn' | 'error',
    category:       'http' | 'java' | 'native' | 'tls' | ...,
    module:         'ClassName' | 'library.so',
    target:         'methodName' | 'url' | 'symbol',
    summary:        'Human readable one-liner',
    args:           'string',
    retval:         'string',
    backtrace:      'frame\n    frame\n    ...',
    correlation_id: 'optional-id',
});
```
