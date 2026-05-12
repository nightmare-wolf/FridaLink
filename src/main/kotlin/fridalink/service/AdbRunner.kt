package fridalink.service

import fridalink.model.ShellEnv
import java.util.concurrent.TimeUnit

/**
 * Wrapper around the `adb` CLI for device-level MASVS checks.
 *
 * Prerequisites:
 *  - Android Debug Bridge (adb) must be installed and on the system PATH.
 *    Install via Android SDK Platform-Tools or standalone download.
 *  - A device must be connected via USB or running on an emulator with USB
 *    debugging enabled.
 *
 * Usage:
 *   val adb = AdbRunner()
 *   if (adb.isAvailable()) {
 *       val checks = adb.runMasvsChecks("com.example.app")
 *   }
 */
class AdbRunner {

    /**
     * Detects the host operating system and whether a POSIX shell (bash) is
     * available.  On Windows, scans common installation paths for Git Bash.
     *
     * Note: `adb shell` commands always execute on the *device's* Linux shell —
     * host bash availability only matters for host-side file analysis.
     */
    fun detectShellEnv(): ShellEnv {
        val osName = System.getProperty("os.name", "").lowercase()
        val isWindows = osName.contains("windows")

        if (!isWindows) {
            // Linux / macOS — bash is always available
            val version = try {
                runProcess(listOf("bash", "--version"), timeoutSeconds = 5)
                    .lines().firstOrNull()?.trim() ?: ""
            } catch (_: Exception) { "" }
            return ShellEnv(isWindows = false, gitBashPath = null, hasBash = true, gitBashVersion = version)
        }

        // Windows — scan known Git for Windows installation paths
        val candidates = buildList {
            add("C:\\Git\\bin\\bash.exe")
            add("C:\\Program Files\\Git\\bin\\bash.exe")
            add("C:\\Program Files (x86)\\Git\\bin\\bash.exe")
            val localAppData = System.getenv("LOCALAPPDATA") ?: ""
            if (localAppData.isNotBlank()) add("$localAppData\\Programs\\Git\\bin\\bash.exe")
            val userProfile = System.getenv("USERPROFILE") ?: ""
            if (userProfile.isNotBlank()) add("$userProfile\\AppData\\Local\\Programs\\Git\\bin\\bash.exe")
        }

        val found = candidates.firstOrNull { java.io.File(it).exists() }
        val version = if (found != null) {
            try {
                runProcess(listOf(found, "--version"), timeoutSeconds = 5)
                    .lines().firstOrNull()?.trim() ?: ""
            } catch (_: Exception) { "" }
        } else ""

        return ShellEnv(isWindows = true, gitBashPath = found, hasBash = found != null, gitBashVersion = version)
    }

    /** True if `adb` is on the PATH and responds to `adb version`. */
    fun isAvailable(): Boolean {
        return try {
            runProcess(listOf("adb", "version"), timeoutSeconds = 5)
                .contains("Android Debug Bridge")
        } catch (_: Exception) { false }
    }

    /**
     * Returns serial numbers of connected/authorized devices.
     * Returns an empty list if adb is unavailable or no devices are attached.
     */
    fun getDevices(): List<String> {
        return try {
            runProcess(listOf("adb", "devices"), timeoutSeconds = 5)
                .lines()
                .drop(1) // skip "List of devices attached" header
                .filter { it.contains("\tdevice") }
                .map { it.substringBefore("\t").trim() }
        } catch (_: Exception) { emptyList() }
    }

    /**
     * True if [serial] looks like a TCP/IP connection (IP:port or hostname:port).
     * USB device serials are alphanumeric strings like "R3CT108ABCD" or "emulator-5554".
     */
    fun isTcpSerial(serial: String): Boolean =
        serial.matches(Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+""")) ||
        (serial.contains(':') && !serial.startsWith("emulator-"))

    /**
     * Returns the best serial to use when none is explicitly provided:
     * - Prefers USB (non-TCP) devices over TCP/IP connections
     * - Skips [excludeHost] (the sidecar host IP) to avoid targeting the wrong machine
     * - Falls back to any TCP device if no USB device is found
     */
    fun preferredSerial(devices: List<String>, excludeHost: String? = null): String? {
        val filtered = if (excludeHost != null)
            devices.filter { !it.startsWith(excludeHost) }
        else
            devices
        return filtered.firstOrNull { !isTcpSerial(it) } ?: filtered.firstOrNull()
    }

    /** Run `adb shell <cmd>` and return trimmed stdout. */
    fun shell(cmd: String, serial: String? = null): String {
        return runProcess(buildAdbArgs(serial, "shell", cmd), timeoutSeconds = 20).trim()
    }

    /** Run arbitrary `adb <args>` and return trimmed stdout. */
    fun run(args: List<String>, serial: String? = null): String {
        return runProcess(buildList {
            add("adb")
            if (serial != null) { add("-s"); add(serial) }
            addAll(args)
        }, timeoutSeconds = 30).trim()
    }

    /**
     * Run all MASVS-relevant ADB checks for [pkg] on [serial] (first connected
     * device if null).  Returns a map of check-key → result string.
     *
     * All checks produce values that MasvsChecker.evaluateAdbResults() maps to PASS/FAIL.
     * Keys are prefixed by MASVS domain for easy display grouping.
     */
    fun runMasvsChecks(pkg: String, serial: String? = null): Map<String, String> {
        val results = mutableMapOf<String, String>()

        // ── MASVS-CODE-1 — debuggable ────────────────────────────────────────
        results["ro.debuggable"]  = shell("getprop ro.debuggable", serial)
        results["ro.build.type"]  = shell("getprop ro.build.type", serial)

        val runAsOut = shell("run-as $pkg id 2>&1", serial)
        results["app.debuggable"] = when {
            runAsOut.contains("not debuggable", ignoreCase = true) -> "false"
            runAsOut.contains("uid=")                              -> "true"
            else                                                   -> "unknown (${runAsOut.take(80)})"
        }
        val pmFlags = shell("pm dump $pkg 2>/dev/null | grep -E 'pkgFlags|flags=' | head -3", serial)
        results["app.flags"] = pmFlags.ifBlank { "not accessible" }

        // ── MASVS-STORAGE-6 — allowBackup ────────────────────────────────────
        val backupFlag = shell("pm dump $pkg 2>/dev/null | grep -i 'allowBackup\\|backup' | head -3", serial)
        results["app.allowBackup"] = backupFlag.ifBlank { "not found in pm dump" }

        // ── MASVS-STORAGE-1 — local data access ──────────────────────────────
        val sharedPrefs = shell("run-as $pkg ls shared_prefs/ 2>/dev/null || echo 'not accessible'", serial)
        results["app.sharedPrefsFiles"] = sharedPrefs

        val extStorage = shell("ls /sdcard/Android/data/$pkg/ 2>/dev/null || echo 'not accessible'", serial)
        results["app.externalStorage"] = extStorage

        // World-readable / world-writable files in app data directory
        val worldReadable = shell(
            "run-as $pkg find /data/data/$pkg -type f \\( -perm -004 -o -perm -002 \\) 2>/dev/null | head -20 || echo 'not accessible'",
            serial
        )
        results["app.worldReadableFiles"] = worldReadable

        // SQLite databases accessible
        val dbFiles = shell("run-as $pkg ls databases/ 2>/dev/null || echo 'not accessible'", serial)
        results["app.databases"] = dbFiles

        // Contents of SharedPreferences (look for tokens/secrets)
        val spContents = if (sharedPrefs != "not accessible" && sharedPrefs.isNotBlank()) {
            val firstFile = sharedPrefs.trim().lines().firstOrNull()?.trim() ?: ""
            if (firstFile.endsWith(".xml")) {
                shell("run-as $pkg cat shared_prefs/$firstFile 2>/dev/null | head -40 || echo 'not accessible'", serial)
            } else "no xml prefs found"
        } else "not accessible"
        results["app.sharedPrefsContents"] = spContents.take(1000)

        // Logcat for sensitive data leakage (last 200 lines for this package)
        val logcatOut = shell("logcat -d -v brief -t 200 2>/dev/null | grep -i '$pkg' | head -50 || echo 'not accessible'", serial)
        results["app.logcat"] = logcatOut.take(2000)

        // ── MASVS-NETWORK-1 — cleartext ──────────────────────────────────────
        val nscXml = shell(
            "cat /data/app/*$pkg*/*.apk 2>/dev/null | grep -a -o 'cleartextTrafficPermitted=[\"a-z]*' | head -5 || echo 'not accessible'",
            serial
        )
        results["network.cleartext"] = nscXml

        // Check if app makes HTTP (not HTTPS) connections via logcat
        val httpUsage = shell("logcat -d -t 500 2>/dev/null | grep -i 'http://' | grep -v 'https://' | head -10 || echo 'none detected'", serial)
        results["network.httpUsage"] = httpUsage.take(500)

        // ── MASVS-NETWORK-2 — certificate validation ─────────────────────────
        // Check if app accepts self-signed / invalid certs (TrustManager overrides)
        val trustMgrCheck = shell(
            "run-as $pkg grep -r 'X509TrustManager\\|checkServerTrusted\\|allowAllHostnames' /data/data/$pkg/ 2>/dev/null | head -5 || echo 'not accessible'",
            serial
        )
        results["network.trustManager"] = trustMgrCheck

        // ── MASVS-NETWORK-3 — certificate pinning ────────────────────────────
        val pinnerCheck = shell(
            "pm dump $pkg 2>/dev/null | grep -i 'certificatepinner\\|trustkit\\|certipin' | head -3",
            serial
        )
        results["ssl.pinning.class"] = pinnerCheck.ifBlank { "not found in package dump" }

        // ── MASVS-CRYPTO-2 — hardcoded keys in accessible files ──────────────
        val hardcodedKeys = shell(
            "run-as $pkg grep -r -i 'password\\|secret\\|api_key\\|private_key\\|token' shared_prefs/ databases/ 2>/dev/null | head -10 || echo 'not accessible'",
            serial
        )
        results["crypto.hardcodedKeys"] = hardcodedKeys.take(500)

        // ── MASVS-RESILIENCE-1 — root ────────────────────────────────────────
        val suBinaries = listOf(
            shell("which su 2>/dev/null", serial),
            shell("which magisk 2>/dev/null", serial),
            shell("ls /sbin/su 2>/dev/null", serial),
            shell("ls /system/xbin/su 2>/dev/null", serial),
            shell("ls /system/bin/su 2>/dev/null", serial),
            shell("getprop ro.build.tags 2>/dev/null", serial),
        ).filter { it.isNotBlank() && !it.contains("No such file") && !it.contains("not found") }
        results["root.indicators"] = if (suBinaries.isNotEmpty())
            "found: ${suBinaries.joinToString("; ")}"
        else
            "not found"

        // Magisk specifically
        val magiskVer = shell("magisk -v 2>/dev/null || echo 'not found'", serial)
        results["root.magisk"] = magiskVer

        // ── MASVS-RESILIENCE-2 — anti-debug / ptrace ─────────────────────────
        val ptraceCheck = shell("cat /proc/\$(pidof $pkg 2>/dev/null)/status 2>/dev/null | grep -i TracerPid | head -1 || echo 'not accessible'", serial)
        results["resilience.tracerPid"] = ptraceCheck

        // ── MASVS-RESILIENCE-4 — emulator ────────────────────────────────────
        results["device.model"]    = shell("getprop ro.product.model", serial)
        results["device.hardware"] = shell("getprop ro.hardware", serial)
        results["device.product"]  = shell("getprop ro.product.name", serial)
        results["device.fingerprint"] = shell("getprop ro.build.fingerprint", serial).take(120)

        // ── MASVS-RESILIENCE-6 — Frida server ────────────────────────────────
        val fridaProc = shell("ps -A 2>/dev/null | grep -i frida || ps 2>/dev/null | grep -i frida", serial)
        results["frida.server"] = fridaProc.ifBlank { "not detected" }

        // ── MASVS-PLATFORM-1 — exported components ───────────────────────────
        val exportedActivities = shell(
            "pm dump $pkg 2>/dev/null | grep -E 'Activity.*exported=true|exported=true.*Activity' | head -10 || echo 'none found'",
            serial
        )
        results["platform.exportedActivities"] = exportedActivities.take(500)

        val exportedProviders = shell(
            "pm dump $pkg 2>/dev/null | grep -E 'Provider.*exported=true|exported=true' | grep -i 'provider' | head -5 || echo 'none found'",
            serial
        )
        results["platform.exportedProviders"] = exportedProviders.take(500)

        // ── MASVS-STORAGE-7 — keystore usage ─────────────────────────────────
        val keystoreEntries = shell(
            "run-as $pkg ls /data/data/$pkg/files/keystore/ 2>/dev/null || " +
            "ls /data/misc/keystore/user_0/ 2>/dev/null | grep $pkg | head -5 || echo 'not accessible'",
            serial
        )
        results["storage.keystore"] = keystoreEntries

        // ── MASVS-CODE-2 — WebView JavaScript / deprecated API usage ──────────
        // pm dump won't show runtime WebView state, but can reveal registered activities
        val webviewPmCheck = shell(
            "pm dump $pkg 2>/dev/null | grep -i 'webview\\|javascript\\|setJava' | head -10 || echo 'not found'",
            serial
        )
        results["code.webviewCheck"] = webviewPmCheck.take(500)

        // Logcat for runtime WebView JS enable calls
        val webviewLogcat = shell(
            "logcat -d -t 300 2>/dev/null | grep -i 'webview\\|setJavaScriptEnabled' | head -10 || echo 'none detected'",
            serial
        )
        results["code.webviewLogcat"] = webviewLogcat.take(500)

        // ── MASVS-CODE-3 — native binary security features ───────────────────
        // Locate .so files in the app's install path
        val nativeLibPaths = shell(
            "find /data/app -path '*$pkg*' -name '*.so' -maxdepth 6 2>/dev/null | head -8 || echo 'not found'",
            serial
        )
        results["code.nativeLibPaths"] = nativeLibPaths.take(600)

        // Try readelf on the first .so found (available on some Android versions)
        val firstSo = nativeLibPaths.trim().lines()
            .firstOrNull { it.endsWith(".so") }?.trim() ?: ""
        val readelfResult = if (firstSo.isNotBlank()) {
            shell(
                "readelf -d '$firstSo' 2>/dev/null | grep -E 'NEEDED|RELRO|GNU_STACK|BIND_NOW|PIE' | head -10 || echo 'readelf not available on device'",
                serial
            )
        } else "no .so files located"
        results["code.nativeSecurityFeatures"] = readelfResult.take(600)

        // ── MASVS-CODE-4 — exported services (third-party IPC surface) ───────
        val exportedServices = shell(
            "pm dump $pkg 2>/dev/null | grep -E 'Service\\s|Service:' | grep -i 'exported=true' | head -10 || echo 'none found'",
            serial
        )
        results["code.exportedServices"] = exportedServices.take(500)

        // ── MASVS-CODE-5 — ContentProviders (SQL injection surface) ──────────
        val contentProviders = shell(
            "pm dump $pkg 2>/dev/null | grep -A2 -B1 -i 'Provider' | grep -i 'exported\\|authority' | head -15 || echo 'none found'",
            serial
        )
        results["code.contentProviders"] = contentProviders.take(500)

        // Declared permissions (needed for input validation surface assessment)
        val declaredPerms = shell(
            "pm dump $pkg 2>/dev/null | grep -E 'permission.*declared|declares.*permission' | head -10 || echo 'none found'",
            serial
        )
        results["code.declaredPermissions"] = declaredPerms.take(400)

        return results
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun buildAdbArgs(serial: String?, vararg args: String): List<String> = buildList {
        add("adb")
        if (serial != null) { add("-s"); add(serial) }
        addAll(args.toList())
    }

    private fun runProcess(args: List<String>, timeoutSeconds: Long): String {
        val pb = ProcessBuilder(args)
        pb.redirectErrorStream(true)
        val proc = pb.start()
        val output = proc.inputStream.bufferedReader().readText()
        proc.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (proc.isAlive) proc.destroyForcibly()
        return output
    }
}
