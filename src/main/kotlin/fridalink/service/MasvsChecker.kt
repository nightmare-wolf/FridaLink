package fridalink.service

import fridalink.model.ApkFinding
import fridalink.model.FindingSeverity
import fridalink.model.MasvsItem
import fridalink.model.MasvsStatus
import fridalink.model.RuntimeEvent

/**
 * Manages the OWASP MASVS v2 checklist.
 * Auto-populates evidence from captured Frida events and static analysis findings.
 */
object MasvsChecker {

    fun buildChecklist(): List<MasvsItem> = listOf(
        // ---- MASVS-STORAGE ----
        MasvsItem("MASVS-STORAGE-1", "MASVS-STORAGE", "Sensitive Data Not Stored Locally",
            "The app does not store sensitive data (PII, credentials, session tokens) in unprotected local storage such as SharedPreferences, SQLite in cleartext, or external storage.",
            "MASTG-TEST-0001", "L1"),
        MasvsItem("MASVS-STORAGE-2", "MASVS-STORAGE", "No Sensitive Data in App Logs",
            "The app does not write sensitive data to system logs accessible via logcat.",
            "MASTG-TEST-0002", "L1"),
        MasvsItem("MASVS-STORAGE-3", "MASVS-STORAGE", "No Sensitive Data in Process Memory",
            "Sensitive data (keys, plaintext credentials) is not left in process memory longer than necessary.",
            "MASTG-TEST-0015", "L2"),
        MasvsItem("MASVS-STORAGE-4", "MASVS-STORAGE", "No Sensitive Data in Clipboard",
            "The app prevents sensitive data from being copied to the system clipboard.",
            "MASTG-TEST-0003", "L1"),
        MasvsItem("MASVS-STORAGE-5", "MASVS-STORAGE", "Keyboard Cache Disabled for Sensitive Fields",
            "Keyboard autocomplete cache is disabled on sensitive input fields.",
            "MASTG-TEST-0004", "L1"),
        MasvsItem("MASVS-STORAGE-6", "MASVS-STORAGE", "No Sensitive Data in Backup",
            "The app excludes sensitive data from Android backups (android:allowBackup=false or BackupAgent).",
            "MASTG-TEST-0005", "L1"),
        MasvsItem("MASVS-STORAGE-7", "MASVS-STORAGE", "App Uses Android Keystore for Cryptographic Keys",
            "Cryptographic keys are generated and stored in the Android Hardware Keystore, not in app files.",
            "MASTG-TEST-0018", "L2"),

        // ---- MASVS-CRYPTO ----
        MasvsItem("MASVS-CRYPTO-1", "MASVS-CRYPTO", "Strong Cryptography Used",
            "The app uses industry-standard algorithms (AES-256-GCM, ChaCha20-Poly1305). No ECB mode, no MD5/SHA1 for security purposes, no DES/3DES.",
            "MASTG-TEST-0014", "L1"),
        MasvsItem("MASVS-CRYPTO-2", "MASVS-CRYPTO", "No Hardcoded Cryptographic Keys",
            "Cryptographic keys are not hardcoded in the application binary or stored in cleartext on disk.",
            "MASTG-TEST-0010", "L1"),
        MasvsItem("MASVS-CRYPTO-3", "MASVS-CRYPTO", "Proper Key Management",
            "Cryptographic keys have appropriate lifetimes, are rotated periodically, and are destroyed when no longer needed.",
            "MASTG-TEST-0069", "L2"),

        // ---- MASVS-AUTH ----
        MasvsItem("MASVS-AUTH-1", "MASVS-AUTH", "Secure Authentication Mechanism",
            "If the app provides user authentication, it uses a secure mechanism with proper session management.",
            "MASTG-TEST-0028", "L1"),
        MasvsItem("MASVS-AUTH-2", "MASVS-AUTH", "Session Tokens Are Random and Sufficient Length",
            "Session identifiers are generated with a cryptographically secure PRNG and have sufficient entropy.",
            "MASTG-TEST-0029", "L1"),
        MasvsItem("MASVS-AUTH-3", "MASVS-AUTH", "Session Invalidation on Logout",
            "Sessions are invalidated server-side on logout or after inactivity timeout.",
            "MASTG-TEST-0030", "L1"),
        MasvsItem("MASVS-AUTH-4", "MASVS-AUTH", "Biometric Auth Uses StrongBox",
            "If biometric authentication is used, it is bound to Android Keystore with StrongBox.",
            "MASTG-TEST-0033", "L2"),

        // ---- MASVS-NETWORK ----
        MasvsItem("MASVS-NETWORK-1", "MASVS-NETWORK", "TLS Used for All Connections",
            "All network communication uses TLS 1.2 or TLS 1.3. No cleartext HTTP in production.",
            "MASTG-TEST-0020", "L1"),
        MasvsItem("MASVS-NETWORK-2", "MASVS-NETWORK", "TLS Certificate Validation",
            "The app properly validates TLS certificates and does not accept self-signed certs or ignore certificate errors.",
            "MASTG-TEST-0021", "L1"),
        MasvsItem("MASVS-NETWORK-3", "MASVS-NETWORK", "Certificate Pinning Implemented",
            "The app implements certificate pinning for critical API endpoints to prevent MITM even with compromised CAs.",
            "MASTG-TEST-0022", "L2"),
        MasvsItem("MASVS-NETWORK-4", "MASVS-NETWORK", "Strong TLS Configuration",
            "TLS is configured with modern cipher suites. No SSLv3, TLS 1.0, RC4, or export ciphers.",
            "MASTG-TEST-0025", "L1"),
        MasvsItem("MASVS-NETWORK-5", "MASVS-NETWORK", "No Sensitive Data in Third-Party Traffic",
            "Third-party SDKs and analytics do not receive sensitive user data without proper disclosure.",
            "MASTG-TEST-0052", "L1"),

        // ---- MASVS-PLATFORM ----
        MasvsItem("MASVS-PLATFORM-1", "MASVS-PLATFORM", "App Uses Android IPC Safely",
            "IPC mechanisms (Intents, Binders, Content Providers) do not leak sensitive data and are properly access-controlled.",
            "MASTG-TEST-0027", "L1"),
        MasvsItem("MASVS-PLATFORM-2", "MASVS-PLATFORM", "WebViews Are Hardened",
            "WebViews disable JavaScript where not needed, do not load untrusted URLs, and disable file:// access.",
            "MASTG-TEST-0039", "L1"),
        MasvsItem("MASVS-PLATFORM-3", "MASVS-PLATFORM", "No Sensitive Data via Deep Links",
            "Deep link handlers validate input and do not expose sensitive functionality to external callers.",
            "MASTG-TEST-0098", "L1"),
        MasvsItem("MASVS-PLATFORM-4", "MASVS-PLATFORM", "No Implicit Intent Data Leakage",
            "Implicit intents do not carry sensitive data that could be intercepted by malicious apps.",
            "MASTG-TEST-0037", "L2"),

        // ---- MASVS-CODE ----
        MasvsItem("MASVS-CODE-1", "MASVS-CODE", "App Is Not Debuggable in Production",
            "The app is not compiled with android:debuggable=true in release builds.",
            "MASTG-TEST-0044", "L1"),
        MasvsItem("MASVS-CODE-2", "MASVS-CODE", "App Does Not Use Deprecated APIs",
            "The app does not use deprecated or vulnerable APIs (e.g., DES, RC4, MD5 for security).",
            "MASTG-TEST-0045", "L1"),
        MasvsItem("MASVS-CODE-3", "MASVS-CODE", "Free Security Features Enabled",
            "App binary uses compiler security features: PIE, stack canaries, RELRO.",
            "MASTG-TEST-0046", "L2"),
        MasvsItem("MASVS-CODE-4", "MASVS-CODE", "No Third-Party Vulnerable Components",
            "All third-party libraries are up to date. No known CVEs in bundled dependencies.",
            "MASTG-TEST-0047", "L1"),
        MasvsItem("MASVS-CODE-5", "MASVS-CODE", "Input Validation",
            "All user input is validated and sanitized. No injection vulnerabilities (SQL, command, format string).",
            "MASTG-TEST-0048", "L1"),

        // ---- MASVS-RESILIENCE ----
        MasvsItem("MASVS-RESILIENCE-1", "MASVS-RESILIENCE", "Root/Jailbreak Detection",
            "The app detects rooted/jailbroken devices and takes appropriate action.",
            "MASTG-TEST-0053", "R"),
        MasvsItem("MASVS-RESILIENCE-2", "MASVS-RESILIENCE", "Anti-Debugging Protection",
            "The app detects and responds to debugger attachment. Anti-debugging mechanisms are in place.",
            "MASTG-TEST-0054", "R"),
        MasvsItem("MASVS-RESILIENCE-3", "MASVS-RESILIENCE", "File Integrity Checks",
            "The app verifies its own integrity at runtime and detects code/resource tampering.",
            "MASTG-TEST-0055", "R"),
        MasvsItem("MASVS-RESILIENCE-4", "MASVS-RESILIENCE", "Emulator Detection",
            "The app detects emulator environments and behaves differently or refuses to run.",
            "MASTG-TEST-0056", "R"),
        MasvsItem("MASVS-RESILIENCE-5", "MASVS-RESILIENCE", "Obfuscation Applied",
            "Code is obfuscated to hinder reverse engineering. Class names, methods, and strings are obfuscated.",
            "MASTG-TEST-0059", "R"),
        MasvsItem("MASVS-RESILIENCE-6", "MASVS-RESILIENCE", "Anti-Frida Protection",
            "The app detects Frida injection and dynamic instrumentation frameworks.",
            "MASTG-TEST-0060", "R"),
    )

    /**
     * Auto-populate MASVS checklist based on:
     *  1. APK static analysis findings
     *  2. Captured Frida runtime events
     *  3. ADB device-level check results (optional — pass emptyMap() if ADB not run)
     */
    fun autoEvaluate(
        items: List<MasvsItem>,
        apkFindings: List<ApkFinding>,
        events: List<RuntimeEvent>,
        adbResults: Map<String, String> = emptyMap(),
    ): List<MasvsItem> {
        val updated = items.map { it.copy() }.toMutableList()

        // ---- 1. APK static analysis findings → MASVS items ----
        for (finding in apkFindings) {
            if (finding.masvsRef.isBlank()) continue
            val item = updated.firstOrNull { it.id == finding.masvsRef } ?: continue
            when (finding.severity) {
                FindingSeverity.CRITICAL, FindingSeverity.HIGH -> {
                    item.status   = MasvsStatus.FAIL
                    item.evidence = (item.evidence + "\n[STATIC] ${finding.title}: ${finding.evidence}").trim()
                }
                FindingSeverity.MEDIUM -> {
                    if (item.status == MasvsStatus.NOT_TESTED) item.status = MasvsStatus.FAIL
                    item.evidence = (item.evidence + "\n[STATIC] ${finding.title}: ${finding.evidence}").trim()
                }
                else -> {
                    item.evidence = (item.evidence + "\n[STATIC] ${finding.title}").trim()
                }
            }
        }

        // ---- 1b. MASVS-RESILIENCE-1: resolve from static root detection findings ----
        // "resilience-positive" findings = app HAS detection code (set PASS if no bypass also found)
        // "resilience" findings with MASVS-RESILIENCE-1 = bypass pattern detected (already FAIL via loop above)
        val hasRootDetectionCode = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-1"
        }
        val hasRootDetectionBypass = apkFindings.any { f ->
            f.category == "resilience" && f.masvsRef == "MASVS-RESILIENCE-1" &&
            f.severity in listOf(FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM)
        }
        when {
            hasRootDetectionBypass ->
                addEvidence(updated, "MASVS-RESILIENCE-1",
                    "[STATIC] Root detection bypass pattern found — implementation present but hardcoded to fail")
            hasRootDetectionCode ->
                setPassed(updated, "MASVS-RESILIENCE-1",
                    "[STATIC] Root detection code found in decompiled source — implementation confirmed, verify bypass difficulty via Frida")
        }

        // ---- 1c. Additional positive resilience indicators ----

        // MASVS-NETWORK-3: Certificate pinning in source code
        val hasCertPinningCode = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-NETWORK-3"
        }
        if (hasCertPinningCode) {
            val pinEvidence = apkFindings.filter { f ->
                f.category == "resilience-positive" && f.masvsRef == "MASVS-NETWORK-3"
            }.joinToString("; ") { it.title.substringBefore(" — ") }
            addEvidence(updated, "MASVS-NETWORK-3",
                "[STATIC] Certificate pinning code detected: $pinEvidence — verify bypass difficulty and pin rotation process")
        }

        // MASVS-RESILIENCE-3: Tamper / signature integrity checks
        val hasTamperCheckCode = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-3"
        }
        if (hasTamperCheckCode) {
            val tamperEvidence = apkFindings.filter { f ->
                f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-3"
            }.joinToString("; ") { it.title.substringBefore(" — ") }
            setPassed(updated, "MASVS-RESILIENCE-3",
                "[STATIC] App integrity / tamper detection code found: $tamperEvidence — verify server-side validation")
        }

        // MASVS-RESILIENCE-6: Anti-Frida / anti-instrumentation code
        val hasFridaDetectionCode = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-6"
        }
        if (hasFridaDetectionCode) {
            val fridaEvidence = apkFindings.filter { f ->
                f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-6"
            }.joinToString("; ") { it.title.substringBefore(" — ") }
            addEvidence(updated, "MASVS-RESILIENCE-6",
                "[STATIC] Anti-Frida/anti-instrumentation code present: $fridaEvidence")
        }

        // MASVS-RESILIENCE-4: Emulator detection code
        val hasEmulatorDetectionCode = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-RESILIENCE-4"
        }
        if (hasEmulatorDetectionCode) {
            setPassed(updated, "MASVS-RESILIENCE-4",
                "[STATIC] Emulator detection code found in decompiled source — verify detection cannot be trivially bypassed")
        }

        // MASVS-STORAGE-4: Screenshot prevention (FLAG_SECURE)
        val hasFlagSecure = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-STORAGE-4"
        }
        if (hasFlagSecure) {
            setPassed(updated, "MASVS-STORAGE-4",
                "[STATIC] FLAG_SECURE detected — screen capture / Recent Apps preview prevented for this Activity")
        }

        // MASVS-STORAGE-7: Encrypted storage (Keystore, Realm, SQLCipher)
        val hasEncryptedStorage = apkFindings.any { f ->
            f.category == "resilience-positive" && f.masvsRef == "MASVS-STORAGE-7"
        }
        if (hasEncryptedStorage) {
            val stEvidence = apkFindings.filter { f ->
                f.category == "resilience-positive" && f.masvsRef == "MASVS-STORAGE-7"
            }.joinToString("; ") { it.title.substringBefore(" — ") }
            setPassed(updated, "MASVS-STORAGE-7",
                "[STATIC] Encrypted storage implementation found: $stEvidence — verify keys are in Android Keystore")
        }

        // ---- 2. Additional checks derived from static findings ----
        // MASVS-CRYPTO-1: weak algorithm patterns in findings
        val hasWeakCrypto = apkFindings.any { f ->
            f.category == "crypto" && (f.title.contains("ECB", ignoreCase = true) ||
                f.title.contains("DES", ignoreCase = true) ||
                f.title.contains("MD5", ignoreCase = true) ||
                f.title.contains("SHA1", ignoreCase = true))
        }
        if (hasWeakCrypto) setFail(updated, "MASVS-CRYPTO-1", "[STATIC] Weak cryptographic algorithm(s) detected in binary")

        // MASVS-CRYPTO-2: hardcoded key patterns
        val hasHardcodedKey = apkFindings.any { f ->
            f.category in listOf("secrets", "hardcoded") ||
            (f.masvsRef.contains("CRYPTO") && f.title.contains("hardcoded", ignoreCase = true))
        }
        if (hasHardcodedKey) setFail(updated, "MASVS-CRYPTO-2", "[STATIC] Hardcoded key or credential detected in binary")

        // MASVS-CODE-1: debuggable flag from manifest findings
        val debuggableInManifest = apkFindings.any { f ->
            f.title.contains("debuggable", ignoreCase = true) || f.evidence.contains("debuggable=true", ignoreCase = true)
        }
        if (debuggableInManifest) setFail(updated, "MASVS-CODE-1", "[STATIC] android:debuggable=true found in AndroidManifest.xml")

        // MASVS-CODE-1: "code" category source findings (e.g. from DecompiledSourceScanner manifest check)
        apkFindings.filter { f -> f.category == "code" }.forEach { cf ->
            if (cf.severity in listOf(FindingSeverity.CRITICAL, FindingSeverity.HIGH))
                setFail(updated, "MASVS-CODE-1", "[STATIC] ${cf.title}")
            else
                addEvidence(updated, "MASVS-CODE-1", "[STATIC] ${cf.title}")
        }

        // MASVS-CODE-2: deprecated/weak API usage from crypto category findings
        val hasWeakApi = apkFindings.any { f ->
            f.category == "crypto" && f.severity in listOf(FindingSeverity.CRITICAL, FindingSeverity.HIGH)
        }
        if (hasWeakApi) setFail(updated, "MASVS-CODE-2",
            "[STATIC] Deprecated or weak cryptographic API usage detected in decompiled source — " +
            "see MASVS-CRYPTO-1 for details")

        // MASVS-CODE-3: native library security features — informational from static
        val nativeFindings = apkFindings.filter { f -> f.category == "native" }
        if (nativeFindings.isNotEmpty()) {
            addEvidence(updated, "MASVS-CODE-3",
                "[STATIC] ${nativeFindings.size} native library finding(s) — " +
                "verify PIE/RELRO/stack canaries via: readelf -d lib/arm64-v8a/libil2cpp.so | grep -E 'RELRO|PIE|GNU_STACK'")
        }

        // MASVS-CODE-4: third-party library CVE surface from detected SDKs
        val hasKnownSdkIssue = apkFindings.any { f ->
            f.category in listOf("configuration", "native") &&
            (f.title.contains("third", ignoreCase = true) || f.title.contains("native lib", ignoreCase = true))
        }
        if (hasKnownSdkIssue) addEvidence(updated, "MASVS-CODE-4",
            "[STATIC] Third-party/native libraries detected — manual CVE check recommended for each bundled SDK")

        // MASVS-CODE-5: exported components accepting external input
        val hasExportedComponentFinding = apkFindings.any { f ->
            f.category == "platform" &&
            (f.title.contains("export", ignoreCase = true) || f.title.contains("provider", ignoreCase = true))
        }
        if (hasExportedComponentFinding) setFail(updated, "MASVS-CODE-5",
            "[STATIC] Exported components detected — input validation must be enforced for all externally callable components")

        // MASVS-NETWORK-1: cleartext traffic config or http:// URLs in static findings
        val hasCleartextStatic = apkFindings.any { f ->
            f.masvsRef == "MASVS-NETWORK-1" ||
            f.category == "network" && (f.evidence.contains("http://", ignoreCase = true) ||
                f.evidence.contains("cleartextTrafficPermitted", ignoreCase = true))
        }
        if (hasCleartextStatic) setFail(updated, "MASVS-NETWORK-1", "[STATIC] Cleartext HTTP usage or cleartextTrafficPermitted=true detected")

        // MASVS-PLATFORM-2: WebView issues from source scanner
        val webviewFindings = apkFindings.filter { f -> f.category == "webview" }
        webviewFindings.forEach { wf ->
            setFail(updated, "MASVS-PLATFORM-2", "[STATIC] ${wf.title}: ${wf.evidence.take(120)}")
        }

        // MASVS-CODE-5: deserialization and SQL injection findings
        val deserializationFindings = apkFindings.filter { f -> f.category == "deserialization" }
        deserializationFindings.forEach { df ->
            setFail(updated, "MASVS-CODE-5", "[STATIC] ${df.title}")
        }
        val sqlInjectionFindings = apkFindings.filter { f -> f.category == "sql-injection" }
        sqlInjectionFindings.forEach { sf ->
            addEvidence(updated, "MASVS-CODE-5", "[STATIC] ${sf.title}: ${sf.description.take(80)}")
        }

        // MASVS-CRYPTO-1: extended crypto weaknesses (AES ECB default, RSA no OAEP, CBC padding oracle, hardcoded IV)
        val cryptoExtraFindings = apkFindings.filter { f ->
            f.category == "crypto" && (f.title.contains("AES ECB", ignoreCase = true) ||
                f.title.contains("RSA Without", ignoreCase = true) ||
                f.title.contains("CBC Padding", ignoreCase = true) ||
                f.title.contains("Hardcoded Cryptographic IV", ignoreCase = true) ||
                f.title.contains("Insecure PRNG", ignoreCase = true) ||
                f.title.contains("java.util.Random", ignoreCase = true))
        }
        cryptoExtraFindings.forEach { cf ->
            setFail(updated, "MASVS-CRYPTO-1", "[STATIC] ${cf.title.take(80)}")
        }

        // MASVS-STORAGE-6: allowBackup=true in manifest findings
        val allowBackupStatic = apkFindings.any { f ->
            f.evidence.contains("allowBackup=true", ignoreCase = true) ||
            f.title.contains("backup", ignoreCase = true)
        }
        if (allowBackupStatic) setFail(updated, "MASVS-STORAGE-6", "[STATIC] android:allowBackup=true detected in AndroidManifest.xml")

        // MASVS-PLATFORM-2: WebView findings
        val hasWebViewIssue = apkFindings.any { f ->
            f.masvsRef == "MASVS-PLATFORM-2" || f.category == "webview"
        }
        if (hasWebViewIssue) setFail(updated, "MASVS-PLATFORM-2", "[STATIC] WebView configuration issue detected")

        // ---- 3. Frida runtime events ----
        val hasSSLPinBypass   = events.any { it.summary.contains("ssl_unpin", ignoreCase = true) || it.category == "ssl_unpin" }
        val hasCleartextHttp  = events.any { it.category == "http" && it.target.contains("http://") }
        val hasNativeNet      = events.any { it.category == "caller_net" }
        val hasKcp            = events.any { it.category == "kcp" }
        val hasClipboard      = events.any { it.category == "clipboard" }
        val hasLogcat         = events.any { it.category == "log" && it.severity == "warn" }
        val hasWebView        = events.any { it.category == "webview" }
        val hasIntentLeak     = events.any { it.category == "intent" && it.severity != "info" }
        val hasBiometric      = events.any { it.category == "biometric" }
        val hasKeystore       = events.any { it.category == "keystore" }

        if (hasSSLPinBypass) {
            setFail(updated, "MASVS-NETWORK-3", "[DYNAMIC] SSL pinning bypassed — Frida ssl_unpin hook active during session")
        }
        if (hasCleartextHttp) {
            setFail(updated, "MASVS-NETWORK-1", "[DYNAMIC] Cleartext HTTP request captured at runtime: ${events.first { it.category == "http" && it.target.contains("http://") }.target}")
        }
        if (hasNativeNet) {
            addEvidence(updated, "MASVS-NETWORK-2", "[DYNAMIC] Native library making direct TLS connections — bypasses Java TLS validation")
        }
        if (hasKcp) {
            addEvidence(updated, "MASVS-NETWORK-4", "[DYNAMIC] KCP (reliable UDP) protocol detected — encrypted non-TLS channel")
        }
        if (hasClipboard) {
            addEvidence(updated, "MASVS-STORAGE-4", "[DYNAMIC] Clipboard read/write event detected during session")
        }
        if (hasLogcat) {
            addEvidence(updated, "MASVS-STORAGE-2", "[DYNAMIC] Sensitive data logged to logcat (warn-level Frida log event captured)")
        }
        if (hasWebView) {
            addEvidence(updated, "MASVS-PLATFORM-2", "[DYNAMIC] WebView activity detected during session — verify JS and URL restrictions")
        }
        if (hasIntentLeak) {
            addEvidence(updated, "MASVS-PLATFORM-4", "[DYNAMIC] Intent with potentially sensitive data intercepted during session")
        }
        if (hasBiometric) {
            addEvidence(updated, "MASVS-AUTH-4", "[DYNAMIC] Biometric authentication API called — verify Keystore binding")
        }
        if (hasKeystore) {
            setPassed(updated, "MASVS-STORAGE-7", "[DYNAMIC] Android Keystore API usage detected during session")
        }

        // If Frida injected successfully, anti-Frida/anti-debug not working
        if (events.isNotEmpty()) {
            setFail(updated, "MASVS-RESILIENCE-6", "[DYNAMIC] Frida injection successful — no Frida detection triggered during session")
            setFail(updated, "MASVS-RESILIENCE-2", "[DYNAMIC] Application attached without triggering anti-debug response")
        }

        // ---- 4. ADB device-level results ----
        if (adbResults.isNotEmpty()) {
            evaluateAdbResults(updated, adbResults)
        }

        return updated
    }

    private fun evaluateAdbResults(updated: MutableList<MasvsItem>, adb: Map<String, String>) {
        // ── MASVS-CODE-1 ─────────────────────────────────────────────────────
        val roDebuggable = adb["ro.debuggable"]?.trim()
        if (roDebuggable == "1") {
            addEvidence(updated, "MASVS-CODE-1", "[ADB] ro.debuggable=1 — device OS is running in debug mode")
        }
        val buildType = adb["ro.build.type"]?.trim()
        if (buildType != null && buildType in listOf("userdebug", "eng")) {
            addEvidence(updated, "MASVS-CODE-1", "[ADB] ro.build.type=$buildType — non-production Android build")
        }
        when (adb["app.debuggable"]) {
            "true"  -> setFail(updated,   "MASVS-CODE-1", "[ADB] run-as succeeded — android:debuggable=true confirmed on device")
            "false" -> setPassed(updated, "MASVS-CODE-1", "[ADB] run-as returned 'not debuggable' — android:debuggable=false confirmed on device")
        }

        // ── MASVS-STORAGE-1 ─────────────────────────────────────────────────
        val sharedPrefs = adb["app.sharedPrefsFiles"] ?: ""
        if (sharedPrefs.isNotBlank() && sharedPrefs != "not accessible" && !sharedPrefs.contains("error", ignoreCase = true)) {
            addEvidence(updated, "MASVS-STORAGE-1", "[ADB] Shared preferences files accessible: $sharedPrefs")
        }
        val extStorage = adb["app.externalStorage"] ?: ""
        if (extStorage.isNotBlank() && extStorage != "not accessible") {
            setFail(updated, "MASVS-STORAGE-1", "[ADB] App files visible in external storage: ${extStorage.take(200)}")
        }
        val worldReadable = adb["app.worldReadableFiles"] ?: ""
        when {
            worldReadable.isNotBlank() && worldReadable != "not accessible" &&
            !worldReadable.contains("not found", ignoreCase = true) &&
            !worldReadable.startsWith("not accessible") ->
                setFail(updated, "MASVS-STORAGE-1", "[ADB] World-readable/writable files detected:\n${worldReadable.take(400)}")
            worldReadable.isNotBlank() ->
                addEvidence(updated, "MASVS-STORAGE-1", "[ADB] World-readable file check: $worldReadable")
        }
        val databases = adb["app.databases"] ?: ""
        if (databases.isNotBlank() && databases != "not accessible") {
            addEvidence(updated, "MASVS-STORAGE-1", "[ADB] Database files present: $databases")
        }
        val spContents = adb["app.sharedPrefsContents"] ?: ""
        if (spContents.isNotBlank() && spContents != "not accessible" && !spContents.contains("no xml prefs found")) {
            val secretKeywords = listOf("password", "token", "secret", "api_key", "private_key", "credential")
            if (secretKeywords.any { spContents.contains(it, ignoreCase = true) }) {
                setFail(updated, "MASVS-STORAGE-1", "[ADB] Possible secret/credential found in SharedPreferences:\n${spContents.take(200)}")
            } else {
                addEvidence(updated, "MASVS-STORAGE-1", "[ADB] SharedPreferences accessible (no obvious plaintext secrets)")
            }
        }

        // ── MASVS-STORAGE-2 ─────────────────────────────────────────────────
        val logcat = adb["app.logcat"] ?: ""
        if (logcat.isNotBlank() && logcat != "not accessible") {
            val sensitiveInLog = listOf("password", "token", "secret", "credit", "ssn", "private_key")
                .any { logcat.contains(it, ignoreCase = true) }
            if (sensitiveInLog) {
                setFail(updated, "MASVS-STORAGE-2", "[ADB] Sensitive keyword(s) found in logcat output — possible data leakage")
            } else {
                addEvidence(updated, "MASVS-STORAGE-2", "[ADB] Logcat checked — ${logcat.lines().size} app lines captured, no obvious sensitive data")
            }
        }

        // ── MASVS-STORAGE-6 ─────────────────────────────────────────────────
        val backupInfo = adb["app.allowBackup"] ?: ""
        when {
            backupInfo.contains("true",  ignoreCase = true) && backupInfo.contains("backup", ignoreCase = true) ->
                setFail(updated, "MASVS-STORAGE-6", "[ADB] pm dump confirms allowBackup=true — app data extractable via adb backup")
            backupInfo.contains("false", ignoreCase = true) && backupInfo.contains("backup", ignoreCase = true) ->
                setPassed(updated, "MASVS-STORAGE-6", "[ADB] pm dump confirms allowBackup=false — backup restricted")
        }

        // ── MASVS-STORAGE-7 ─────────────────────────────────────────────────
        val keystoreEntries = adb["storage.keystore"] ?: ""
        if (keystoreEntries.isNotBlank() && keystoreEntries != "not accessible") {
            setPassed(updated, "MASVS-STORAGE-7", "[ADB] Keystore entries detected: $keystoreEntries")
        }

        // ── MASVS-CRYPTO-2 ─────────────────────────────────────────────────
        val hardcodedKeys = adb["crypto.hardcodedKeys"] ?: ""
        if (hardcodedKeys.isNotBlank() && hardcodedKeys != "not accessible") {
            setFail(updated, "MASVS-CRYPTO-2", "[ADB] Potential hardcoded key/credential in app data:\n${hardcodedKeys.take(300)}")
        }

        // ── MASVS-NETWORK-1 ─────────────────────────────────────────────────
        val cleartext = adb["network.cleartext"] ?: ""
        when {
            cleartext.contains("true",  ignoreCase = true) ->
                setFail(updated, "MASVS-NETWORK-1", "[ADB] cleartextTrafficPermitted=true found in APK network config")
            cleartext.contains("false", ignoreCase = true) ->
                setPassed(updated, "MASVS-NETWORK-1", "[ADB] cleartextTrafficPermitted=false — cleartext disabled in NSC")
        }
        val httpUsage = adb["network.httpUsage"] ?: ""
        when {
            httpUsage.isNotBlank() && httpUsage != "none detected" && !httpUsage.contains("not accessible") ->
                setFail(updated, "MASVS-NETWORK-1", "[ADB] HTTP (cleartext) traffic detected in logcat:\n${httpUsage.take(200)}")
            httpUsage == "none detected" ->
                addEvidence(updated, "MASVS-NETWORK-1", "[ADB] No cleartext HTTP observed in logcat sample")
        }

        // ── MASVS-NETWORK-2 ─────────────────────────────────────────────────
        val trustMgr = adb["network.trustManager"] ?: ""
        if (trustMgr.isNotBlank() && trustMgr != "not accessible") {
            setFail(updated, "MASVS-NETWORK-2", "[ADB] Custom TrustManager / allowAllHostnames found in app files:\n${trustMgr.take(200)}")
        }

        // ── MASVS-NETWORK-3 ─────────────────────────────────────────────────
        val pinnerClass = adb["ssl.pinning.class"] ?: ""
        if (pinnerClass.contains("certificatepinner", ignoreCase = true) ||
            pinnerClass.contains("trustkit", ignoreCase = true)) {
            addEvidence(updated, "MASVS-NETWORK-3", "[ADB] Certificate pinner class found in package info — verify bypass success")
        }

        // ── MASVS-PLATFORM-1 ────────────────────────────────────────────────
        val exportedActivities = adb["platform.exportedActivities"] ?: ""
        when {
            exportedActivities.isNotBlank() && exportedActivities != "none found" &&
            !exportedActivities.contains("not found", ignoreCase = true) ->
                setFail(updated, "MASVS-PLATFORM-1", "[ADB] Exported activities detected:\n${exportedActivities.take(300)}")
            exportedActivities == "none found" ->
                addEvidence(updated, "MASVS-PLATFORM-1", "[ADB] No explicitly exported activities found")
        }
        val exportedProviders = adb["platform.exportedProviders"] ?: ""
        if (exportedProviders.isNotBlank() && exportedProviders != "none found" &&
            !exportedProviders.contains("not found", ignoreCase = true)) {
            setFail(updated, "MASVS-PLATFORM-1", "[ADB] Exported content providers detected:\n${exportedProviders.take(300)}")
        }

        // ── MASVS-RESILIENCE-1 ─────────────────────────────────────────────
        // ADB finds root binaries on the TEST DEVICE — this is a precondition for the pentest,
        // not evidence that the app's own root detection fails. Use as context only; pass/fail is
        // determined by static analysis of the app's code (see section 1b above).
        val rootInfo   = adb["root.indicators"] ?: ""
        val magiskInfo = adb["root.magisk"] ?: ""
        when {
            rootInfo.startsWith("found:") ->
                addEvidence(updated, "MASVS-RESILIENCE-1",
                    "[ADB] Test device is rooted ($rootInfo) — optimal condition to verify whether the app's root detection triggers and cannot be bypassed")
            rootInfo == "not found" && (magiskInfo.contains("not found") || magiskInfo.isBlank()) ->
                addEvidence(updated, "MASVS-RESILIENCE-1",
                    "[ADB] Test device does not appear to be rooted — re-test on a rooted device to fully validate MASVS-RESILIENCE-1")
        }
        if (magiskInfo.isNotBlank() && !magiskInfo.contains("not found") && !magiskInfo.contains("not detected")) {
            addEvidence(updated, "MASVS-RESILIENCE-1",
                "[ADB] Magisk present on test device ($magiskInfo) — use Magisk DenyList / Shamiko to test if app detects via SafetyNet/Play Integrity")
        }

        // ── MASVS-RESILIENCE-2 ─────────────────────────────────────────────
        val tracerPid = adb["resilience.tracerPid"] ?: ""
        if (tracerPid.isNotBlank() && tracerPid != "not accessible") {
            val pid = tracerPid.substringAfter("TracerPid:", "").trim().substringBefore("\n").trim()
            when {
                pid == "0" -> addEvidence(updated, "MASVS-RESILIENCE-2", "[ADB] TracerPid=0 — no debugger attached at time of ADB check")
                pid.isNotBlank() -> addEvidence(updated, "MASVS-RESILIENCE-2", "[ADB] TracerPid=$pid — process may be traced/debugged")
            }
        }

        // ── MASVS-RESILIENCE-4 ─────────────────────────────────────────────
        val model    = adb["device.model"] ?: ""
        val hardware = adb["device.hardware"] ?: ""
        val product  = adb["device.product"] ?: ""
        val fingerprint = adb["device.fingerprint"] ?: ""
        val emulatorPatterns = listOf("generic", "unknown", "goldfish", "ranchu", "sdk_gphone", "emulator", "android_x86")
        val isEmulator = emulatorPatterns.any { pat ->
            model.contains(pat, ignoreCase = true) ||
            hardware.contains(pat, ignoreCase = true) ||
            product.contains(pat, ignoreCase = true) ||
            fingerprint.contains(pat, ignoreCase = true)
        }
        if (isEmulator) {
            setFail(updated, "MASVS-RESILIENCE-4", "[ADB] Emulator indicators detected — model='$model' hw='$hardware' product='$product'")
        } else if (model.isNotBlank()) {
            addEvidence(updated, "MASVS-RESILIENCE-4", "[ADB] Physical device: model='$model' hw='$hardware'")
        }
        if (fingerprint.isNotBlank()) {
            addEvidence(updated, "MASVS-RESILIENCE-4", "[ADB] Build fingerprint: ${fingerprint.take(80)}")
        }

        // ── MASVS-RESILIENCE-6 ─────────────────────────────────────────────
        val fridaServer = adb["frida.server"] ?: ""
        if (fridaServer != "not detected" && fridaServer.isNotBlank()) {
            addEvidence(updated, "MASVS-RESILIENCE-6", "[ADB] Frida server process detected on device: ${fridaServer.take(120)}")
        }

        // ── MASVS-CODE-2 — Deprecated / Insecure APIs ──────────────────────
        val webviewCheck = adb["code.webviewCheck"] ?: ""
        if (webviewCheck.isNotBlank() && webviewCheck != "not found" &&
            !webviewCheck.contains("not found", ignoreCase = true)) {
            if (webviewCheck.contains("setJavaScriptEnabled", ignoreCase = true)) {
                setFail(updated, "MASVS-CODE-2",
                    "[ADB] pm dump reports WebView with JavaScript usage:\n${webviewCheck.take(200)}")
                setFail(updated, "MASVS-PLATFORM-2",
                    "[ADB] WebView JavaScript usage confirmed by pm dump — review all WebView configurations")
            } else {
                addEvidence(updated, "MASVS-CODE-2",
                    "[ADB] WebView references in pm dump (no explicit setJavaScriptEnabled):\n${webviewCheck.take(200)}")
            }
        }
        val webviewLogcat = adb["code.webviewLogcat"] ?: ""
        if (webviewLogcat.isNotBlank() && webviewLogcat != "none detected" &&
            !webviewLogcat.contains("not accessible", ignoreCase = true)) {
            setFail(updated, "MASVS-PLATFORM-2",
                "[ADB] WebView/setJavaScriptEnabled call detected in logcat:\n${webviewLogcat.take(300)}")
        }

        // ── MASVS-CODE-3 — Binary security features (PIE / RELRO / stack canaries) ──
        val nativeSecFeatures = adb["code.nativeSecurityFeatures"] ?: ""
        when {
            nativeSecFeatures.contains("GNU_RELRO", ignoreCase = true) ||
            nativeSecFeatures.contains("BIND_NOW",  ignoreCase = true) ->
                setPassed(updated, "MASVS-CODE-3",
                    "[ADB] RELRO/BIND_NOW detected in native library ELF headers:\n${nativeSecFeatures.take(200)}")
            nativeSecFeatures.contains("readelf not available", ignoreCase = true) ->
                addEvidence(updated, "MASVS-CODE-3",
                    "[ADB] readelf unavailable on device — run host-side:\n" +
                    "  readelf -d <unpacked>/lib/arm64-v8a/libil2cpp.so | grep -E 'RELRO|PIE|GNU_STACK|BIND_NOW'")
            nativeSecFeatures.isNotBlank() && !nativeSecFeatures.contains("no .so files") ->
                addEvidence(updated, "MASVS-CODE-3",
                    "[ADB] Native security feature probe result:\n${nativeSecFeatures.take(300)}")
        }
        val nativeLibPaths = adb["code.nativeLibPaths"] ?: ""
        if (nativeLibPaths.isNotBlank() && !nativeLibPaths.contains("not found", ignoreCase = true)) {
            addEvidence(updated, "MASVS-CODE-3",
                "[ADB] Native libraries in app install path:\n${nativeLibPaths.take(400)}")
        }

        // ── MASVS-CODE-4 — Third-party / vulnerable components ─────────────
        if (nativeLibPaths.isNotBlank() && !nativeLibPaths.contains("not found", ignoreCase = true)) {
            addEvidence(updated, "MASVS-CODE-4",
                "[ADB] Native library inventory (check each against NVD/CVE databases):\n${nativeLibPaths.take(400)}")
        }

        // ── MASVS-CODE-5 — Input validation ────────────────────────────────
        val exportedServices = adb["code.exportedServices"] ?: ""
        if (exportedServices.isNotBlank() && exportedServices != "none found" &&
            !exportedServices.contains("not found", ignoreCase = true)) {
            setFail(updated, "MASVS-CODE-4",
                "[ADB] Exported services detected — verify each is intentionally public:\n${exportedServices.take(300)}")
            setFail(updated, "MASVS-CODE-5",
                "[ADB] Exported services accept IPC input from other apps — verify input validation:\n${exportedServices.take(300)}")
        }
        val contentProviders = adb["code.contentProviders"] ?: ""
        if (contentProviders.isNotBlank() && contentProviders != "none found" &&
            !contentProviders.contains("not found", ignoreCase = true)) {
            setFail(updated, "MASVS-CODE-5",
                "[ADB] ContentProvider(s) detected — verify SQL/path injection prevention:\n${contentProviders.take(300)}")
        }
        val declaredPerms = adb["code.declaredPermissions"] ?: ""
        if (declaredPerms.isNotBlank() && declaredPerms != "none found") {
            addEvidence(updated, "MASVS-CODE-5",
                "[ADB] Declared permissions (input surface): ${declaredPerms.take(200)}")
        }
    }

    private fun setFail(items: MutableList<MasvsItem>, id: String, evidence: String) {
        items.firstOrNull { it.id == id }?.let {
            it.status   = MasvsStatus.FAIL
            it.evidence = (it.evidence + "\n$evidence").trim()
        }
    }

    private fun setPassed(items: MutableList<MasvsItem>, id: String, evidence: String) {
        items.firstOrNull { it.id == id }?.let {
            if (it.status == MasvsStatus.NOT_TESTED) it.status = MasvsStatus.PASS
            it.evidence = (it.evidence + "\n$evidence").trim()
        }
    }

    private fun addEvidence(items: MutableList<MasvsItem>, id: String, evidence: String) {
        items.firstOrNull { it.id == id }?.let {
            it.evidence = (it.evidence + "\n$evidence").trim()
        }
    }
}
