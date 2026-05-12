package fridalink.service

import fridalink.model.ApkFinding
import fridalink.model.FindingSeverity
import java.io.File

/**
 * Scans a jadx-decompiled APK directory for security issues in Java source
 * files and resource/asset files.  Generates [ApkFinding] entries with exact
 * file path + line number references so findings link back to real code.
 *
 * Expected directory layout (jadx default output):
 *   <decompRoot>/
 *     sources/          — decompiled .java files
 *     resources/
 *       assets/         — bundled asset files (JSON, XML, TXT, …)
 *       res/            — compiled resource XML
 *       AndroidManifest.xml
 *
 * Usage:
 *   val findings = DecompiledSourceScanner().scan("/path/to/decompiled") { msg -> log(msg) }
 */
class DecompiledSourceScanner {

    // ----------------------------------------------------------------
    // Secret patterns — label → Regex.  Applied to both Java source
    // lines and plaintext asset file lines.
    // ----------------------------------------------------------------
    private val SECRET_PATTERNS: List<Pair<String, Regex>> = listOf(
        "AWS Access Key"       to Regex("""AKIA[0-9A-Z]{16}"""),
        "AWS Secret Key"       to Regex("""(?i)aws[._\-]?secret[._\-]?(?:access[._\-]?)?key\s*[=:]\s*["']?([A-Za-z0-9/+]{40})"""),
        "Google API Key"       to Regex("""AIza[0-9A-Za-z\-_]{35}"""),
        "Firebase URL"         to Regex("""https://[a-z0-9\-]+\.firebaseio\.com"""),
        "Private Key (PEM)"    to Regex("""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""),
        "JWT Token"            to Regex("""eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"""),
        "Generic API Key"      to Regex("""(?i)(?:api[_\-]?key|apikey|api_secret|client_secret|client_key)\s*[=:]\s*["']([A-Za-z0-9_\-./+]{16,})["']"""),
        "OAuth Token/Secret"   to Regex("""(?i)(?:oauth|access)[._\-]?(?:token|secret)\s*[=:]\s*["']([A-Za-z0-9_\-./+]{16,})["']"""),
        "App/Channel Secret"   to Regex("""(?i)(?:app|channel)[._\-]?(?:secret|key|channelKey|channelSecret)\s*["']?\s*[=:]\s*["']([A-Za-z0-9_\-./+]{8,})["']"""),
        "Singular Key/Secret"  to Regex("""(?i)singular[._\-]?(?:key|secret|apikey)\s*["']?\s*[=:]\s*["']([A-Za-z0-9_\-./+]{8,})["']"""),
        "Segment Write Key"    to Regex("""(?i)segment[._\-]?(?:key|writeKey)\s*["']?\s*[=:]\s*["']([A-Za-z0-9_\-./+]{16,})["']"""),
        "Facebook Client Token" to Regex("""(?i)(?:facebook|fb)[._\-]?(?:client[._\-]?token|app[._\-]?id|token)\s*["']?\s*[=:]\s*["']([A-Za-z0-9_\-]{8,})["']"""),
        "Hardcoded Password"   to Regex("""(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']"""),
        "Hardcoded Bearer"     to Regex("""(?i)bearer\s+([A-Za-z0-9_\-./+]{20,})"""),
        "Private Key (Base64)" to Regex("""(?i)(?:private[._\-]?key|rsa[._\-]?key|ec[._\-]?key)\s*[=:]\s*["']([A-Za-z0-9+/=]{40,})["']"""),
        "Billing Public Key"   to Regex("""(?i)(?:billing|iab|play)[._\-]?(?:public[._\-]?)?key\s*["']?\s*[=:]\s*["']([A-Za-z0-9+/=]{40,})["']"""),
    )

    // ----------------------------------------------------------------
    // Java-source-specific patterns
    // ----------------------------------------------------------------

    /** Logging of sensitive data via Android Log class. */
    private val LOG_SENSITIVE_PATTERNS = listOf(
        Regex("""Log\.[diveW]\s*\([^,)]*,\s*[^);]*(?:token|secret|password|email|idToken|userId|auth|key|credential)[^)]*\)""", RegexOption.IGNORE_CASE),
        Regex("""(?:Log\.[diveW]|System\.out\.print(?:ln)?|printStackTrace)\s*\([^)]*(?:token|secret|password|email|idToken)\b[^)]*\)""", RegexOption.IGNORE_CASE),
    )

    /** SharedPreferences writes storing sensitive values. */
    private val SHARED_PREFS_PATTERNS = listOf(
        Regex("""putString\s*\(\s*"([^"]*(?:token|secret|password|key|auth|credential|email|userId|user_id)[^"]*)"\s*,""", RegexOption.IGNORE_CASE),
        Regex("""putString\s*\(\s*[A-Z_]{4,}\s*,\s*(?!\s*"[a-z])[^)]{4,}\)"""),   // non-literal value written to prefs
    )

    /** OAuth / CSRF state validation missing. */
    private val OAUTH_NO_STATE_PATTERN = Regex("""processCrSchemeUrl|handleRedirect|onNewIntent|processCallback""", RegexOption.IGNORE_CASE)
    private val OAUTH_STATE_CHECK      = Regex("""(?:state|csrfToken|csrf_token|nonce)""", RegexOption.IGNORE_CASE)

    /** Trust-all TLS implementations. */
    private val TRUST_ALL_PATTERNS = listOf(
        Regex("""override\s+fun\s+checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}"""),
        Regex("""override\s+fun\s+checkClientTrusted\s*\([^)]*\)\s*\{?\s*\}"""),
        Regex("""onReceivedSslError\s*\([^)]*\)\s*\{[^}]*\bproceed\b"""),
        Regex("""setHostnameVerifier\s*\(\s*(?:ALLOW_ALL|AllowAllHostname)""", RegexOption.IGNORE_CASE),
        // Class-name based trust-all patterns (mirrors MobSF android_insecure_ssl rule)
        Regex("""TrustAllSSLSocketFactory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|NullHostnameVerifier"""),
        Regex("""ALLOW_ALL_HOSTNAME_VERIFIER"""),
        Regex("""net\.SSLCertificateSocketFactory\.getInsecure"""),
    )

    /** Client-side security bypass — code that hardcodes or short-circuits root/tamper detection. */
    private val CLIENT_BYPASS_PATTERNS = listOf(
        Regex("""\bdeviceIsRooted\s*[=:]\s*(?:false|"false"|0)""", RegexOption.IGNORE_CASE),
        Regex("""\bisRooted\s*\(\s*\)\s*\{[^}]{0,60}return\s+false""", RegexOption.IGNORE_CASE),
        Regex("""\bplayIntegrityToken\s*[=:]\s*(?:""|null)\s*""", RegexOption.IGNORE_CASE),
        // \b prevents substring matches (e.g. "iRootLength" matching as "RootLength").
        // Negative lookahead excludes common UI/filesystem words: rootView, rootLength, rootDir, etc.
        Regex("""\b(?:root(?!(?:view|length|dir(?:ectory)?|path|node|element|cause|layout|scroll|window|parent|container|group|folder|anchor|offset|height|width)[A-Za-z])|jailbreak|tamper)[A-Za-z]*\s*[=:]\s*(?:false|"false"|0)\s*[;,/]""", RegexOption.IGNORE_CASE),
        // Hardcoded return false inside named root-check methods
        Regex("""\b(?:isRootME?|isRooted|checkRooted|detectRoot|isJailbroken)\s*\([^)]{0,40}\)\s*\{[^}]{0,80}return\s+false""", RegexOption.IGNORE_CASE),
    )

    /**
     * Positive root/jailbreak detection indicators — code that means the app IS checking for root.
     * Findings from these patterns set MASVS-RESILIENCE-1 evidence; MasvsChecker promotes to PASS
     * when no bypass pattern is also present.
     * Pair: human-readable label → regex.
     */
    private val ROOT_DETECTION_PATTERNS: List<Pair<String, Regex>> = listOf(
        "su binary file-exists check" to
            Regex("""new\s+File\s*\(\s*"(?:/sbin/su|/system/(?:bin|xbin)/su|/data/local(?:/xbin|/bin)?/su|/system/app/Superuser)"""),
        "su path array/list initializer" to
            Regex(""""(?:/sbin/su|/system/xbin/su|/system/bin/su|/data/local(?:/xbin|/bin)?/su)""""),
        "Build.TAGS test-keys check" to
            Regex("""Build\.TAGS[^;\n]{0,80}["']test-keys["']"""),
        "Runtime.exec su/which check" to
            Regex("""(?:exec|ProcessBuilder)\s*\([^)]{0,120}(?:"which",\s*"su"|"su"|"/(?:sbin|system/(?:xbin|bin))/su")"""),
        "RootBeer library" to
            Regex("""\bRootBeer\b"""),
        "Root detection method definition/call" to
            Regex("""\b(?:isRoot(?:ed|Me|ME)?|detectRoot|checkRoot|isDeviceRooted|isRootedDevice|hasRootAccess|rootCheck)\s*\("""),
        "Magisk/SuperSU package detection" to
            Regex("""(?:com\.topjohnwu\.magisk|eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.thirdparty\.superuser|com\.koushikdutta\.superuser)"""),
        "SafetyNet/Play Integrity API" to
            Regex("""\b(?:SafetyNetApi\.attest|SafetyNet\.getClient|IntegrityManager|requestIntegrityToken|StandardIntegrityManager|AppIntegrityManager)\b"""),
        "/proc/mounts rw-system check" to
            Regex("""/proc/mounts"""),
        "BusyBox binary check" to
            Regex(""""busybox"""", RegexOption.IGNORE_CASE),
        "Superuser.apk / KingUser existence check" to
            Regex("""(?:Superuser\.apk|com\.koushikdutta\.superuser|SuperSU\.apk|KingUser)"""),
        "SELinux enforce check" to
            Regex("""/sys/fs/selinux/enforce"""),
        "getprop ro.secure/ro.build.tags check" to
            Regex("""getprop[^;\n]{0,50}(?:ro\.secure|ro\.debuggable|ro\.build\.tags|ro\.build\.selinux)"""),
    )

    /** Weak or cleartext storage patterns in Java code. */
    private val CLEARTEXT_STORAGE_PATTERNS = listOf(
        Regex("""MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"""),
        Regex("""getExternalStorage|DIRECTORY_DOCUMENTS|DIRECTORY_DOWNLOADS\).*(?:token|key|secret|password)""", RegexOption.IGNORE_CASE),
        Regex("""openFileOutput\s*\([^,)]+,\s*MODE_WORLD"""),
    )

    /** Weak cryptography — broken or deprecated algorithms. */
    private val WEAK_CRYPTO_PATTERNS = listOf(
        Regex("""getInstance\s*\(\s*"(?:DES|3DES|DESede|RC4|RC2|Blowfish|MD5|SHA1|SHA-1)\b""", RegexOption.IGNORE_CASE),
        Regex("""Cipher\.getInstance\s*\(\s*"AES/ECB"""),
        Regex("""MessageDigest\.getInstance\s*\(\s*"MD5"""),
        Regex("""new\s+SecretKeySpec\s*\([^,)]+,\s*"(?:DES|RC4|MD5)""", RegexOption.IGNORE_CASE),
        Regex("""MessageDigest\.getInstance\s*\(\s*"SHA-?1\b""", RegexOption.IGNORE_CASE),
        Regex("""\.getInstance\s*\(\s*"MD4\b""", RegexOption.IGNORE_CASE),
    )

    /** WebView security misconfigurations. */
    private val WEBVIEW_VULN_PATTERNS: List<Pair<String, Regex>> = listOf(
        "WebView Remote Debugging Enabled" to
            Regex("""setWebContentsDebuggingEnabled\(\s*true\s*\)"""),
        "WebView File/Universal URL Access Enabled" to
            Regex("""setAllowFileAccessFromFileURLs\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\(\s*true\s*\)"""),
        "WebView Loading from External Storage" to
            Regex("""\.loadUrl\([^)]{0,80}getExternalStorageDirectory\("""),
        "WebView Content Access from File URLs" to
            Regex("""setAllowContentAccess\(\s*true\s*\)"""),
    )

    /** Non-cryptographic PRNG — must not be used for security-sensitive operations. */
    private val INSECURE_RANDOM_PATTERN = Regex("""java\.util\.Random\b(?!Access)|(?<![A-Za-z\.])new\s+Random\s*\(\)""")

    /** Unsafe deserialization patterns. */
    private val DESERIALIZATION_PATTERNS: List<Pair<String, Regex>> = listOf(
        "Jackson Unsafe Deserialization (enableDefaultTyping)" to
            Regex("""\.enableDefaultTyping\("""),
        "Java Object Deserialization via ObjectInputStream" to
            Regex("""new\s+ObjectInputStream\s*\("""),
    )

    /** SQLite raw SQL execution — potential SQL injection surface. */
    private val SQL_INJECTION_PATTERNS: List<Pair<String, Regex>> = listOf(
        "SQLite rawQuery — Potential SQL Injection" to
            Regex("""\.rawQuery\s*\("""),
        "SQLite execSQL — Potential SQL Injection" to
            Regex("""\.execSQL\s*\("""),
    )

    /** Extended cryptographic weakness patterns. */
    private val CRYPTO_EXTRA_PATTERNS: List<Pair<String, Regex>> = listOf(
        "AES ECB Mode by Default (Cipher.getInstance(\"AES\"))" to
            Regex("""Cipher\.getInstance\(\s*["']AES["']\s*\)"""),
        "RSA Without OAEP Padding" to
            Regex("""Cipher\.getInstance\(\s*["'][Rr][Ss][Aa]/[^/]{1,40}/NoPadding["']"""),
        "CBC Padding Oracle Risk (PKCS5/PKCS7)" to
            Regex("""Cipher\.getInstance\([^)]{0,80}/CBC/PKCS[57]Padding"""),
        "Hardcoded Cryptographic IV (Predictable)" to
            Regex("""0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00,\s*0x00|0x01,\s*0x02,\s*0x03,\s*0x04,\s*0x05|IvParameterSpec\(\s*new\s+byte\["""),
    )

    /**
     * Positive security indicator patterns — presence of these means the app
     * implements a security control.  Findings use category "resilience-positive"
     * and their masvsRef drives MasvsChecker.autoEvaluate to a PASS/evidence.
     *
     * Triple: (human label, regex, masvsRef)
     */
    private val POSITIVE_SECURITY_PATTERNS: List<Triple<String, Regex, String>> = listOf(
        Triple("Screenshot Prevention (FLAG_SECURE)", Regex("""WindowManager\.LayoutParams\.FLAG_SECURE|(?<![A-Za-z])FLAG_SECURE\b"""), "MASVS-STORAGE-4"),
        Triple("OkHttp/Network Certificate Pinning", Regex("""CertificatePinner\.Builder\(|CertificatePinner\.Pin|PinningHelper\.|PinningSSLSocketFactory"""), "MASVS-NETWORK-3"),
        Triple("TrustKit / Custom SSL Pinning", Regex("""TrustKit\.initializeWithNetworkSecurityConfiguration|\.setPins\(|\.addTrustedCertificate\("""), "MASVS-NETWORK-3"),
        Triple("Frida Server Detection Code", Regex("""fridaserver|LIBFRIDA""", RegexOption.IGNORE_CASE), "MASVS-RESILIENCE-6"),
        Triple("Frida Port Detection (27047)", Regex("""["']27047["']|\b27047\b"""), "MASVS-RESILIENCE-6"),
        Triple("Xposed / Substrate Framework Detection", Regex("""com\.saurik\.substrate|de\.robv\.android\.xposed|XposedBridge|XC_MethodHook"""), "MASVS-RESILIENCE-6"),
        Triple("Package Signature Tamper Check", Regex("""PackageManager\.GET_SIGNATURES|GET_SIGNING_CERTIFICATES"""), "MASVS-RESILIENCE-3"),
        Triple("Play Integrity / SafetyNet API", Regex("""\bIntegrityManager\b|\brequestIntegrityToken\b|\bStandardIntegrityManager\b|SafetyNetApi\.attest|SafetyNet\.getClient"""), "MASVS-RESILIENCE-1"),
        Triple("Certificate Transparency Enforcement", Regex("""CTHostnameVerifierBuilder\(|CTInterceptorBuilder\("""), "MASVS-NETWORK-3"),
        Triple("Tapjacking Prevention", Regex("""setFilterTouchesWhenObscured\(\s*true\s*\)"""), "MASVS-PLATFORM-2"),
        Triple("DexGuard Anti-Tamper / Anti-Debug", Regex("""TamperDetector\.checkApk|CertificateChecker\.checkCertificate|DebugDetector\.is(?:Debuggable|DebuggerConnected|SignedWithDebugKey)"""), "MASVS-RESILIENCE-3"),
        Triple("Emulator Detection Code", Regex("""EmulatorDetector\.isRunningInEmulator|Build\.FINGERPRINT.*generic|Build\.MODEL.*Emulator""", RegexOption.IGNORE_CASE), "MASVS-RESILIENCE-4"),
        Triple("Realm Encrypted Database", Regex("""\.encryptionKey\("""), "MASVS-STORAGE-7"),
        Triple("SQLCipher Encrypted SQLite", Regex("""SQLiteDatabase\.loadLibs\(|net\.sqlcipher"""), "MASVS-STORAGE-7"),
        Triple("Android Keystore Key Generation", Regex("""KeyPairGenerator\.getInstance\([^)]+,\s*["']AndroidKeyStore["']|KeyGenerator\.getInstance\([^)]+,\s*["']AndroidKeyStore["']"""), "MASVS-STORAGE-7"),
    )

    // ----------------------------------------------------------------
    // Entry point
    // ----------------------------------------------------------------

    /**
     * Recursively scan [decompRoot] (a jadx output directory).
     * Returns a merged list of [ApkFinding] entries covering all
     * Java source files, asset files, and resource XML files found.
     */
    fun scan(decompRoot: String, onProgress: (String) -> Unit = {}): List<ApkFinding> {
        val root = File(decompRoot)
        if (!root.exists() || !root.isDirectory) {
            return listOf(ApkFinding(
                severity    = FindingSeverity.INFO,
                category    = "analysis",
                title       = "Decompiled source not found",
                description = "The directory '$decompRoot' does not exist or is not readable.",
                evidence    = "",
                mitigation  = "Run jadx against the APK first: jadx -d <outdir> <app.apk>",
            ))
        }

        val findings = mutableListOf<ApkFinding>()
        val seen = mutableSetOf<String>()   // dedup on (file:line:pattern)

        // ---- Java source files ----
        val sourceDir = File(root, "sources")
        if (sourceDir.exists()) {
            val javaFiles = sourceDir.walkTopDown().filter { it.isFile && it.name.endsWith(".java") }.toList()
            onProgress("Scanning ${javaFiles.size} Java source files...")
            javaFiles.forEach { file ->
                scanJavaFile(file, root, findings, seen, onProgress)
            }
        } else {
            onProgress("No 'sources/' directory found in $decompRoot — looking for .java recursively...")
            root.walkTopDown().filter { it.isFile && it.name.endsWith(".java") }
                .forEach { file -> scanJavaFile(file, root, findings, seen, onProgress) }
        }

        // ---- Assets ----
        val assetsDir = File(root, "resources/assets").let { if (it.exists()) it else File(root, "assets") }
        if (assetsDir.exists()) {
            onProgress("Scanning asset files under ${assetsDir.name}/...")
            assetsDir.walkTopDown().filter { it.isFile }.forEach { file ->
                scanTextFile(file, root, findings, seen)
            }
        }

        // ---- Backup rules / network security config ----
        val resourcesDir = File(root, "resources")
        if (resourcesDir.exists()) {
            resourcesDir.walkTopDown().filter { it.isFile && (
                it.name == "network_security_config.xml" ||
                it.name.endsWith("backup_rules.xml") ||
                it.name.endsWith("data_extraction_rules.xml") ||
                it.name == "strings.xml")
            }.forEach { file ->
                scanTextFile(file, root, findings, seen)
                if (file.name == "network_security_config.xml") {
                    checkNetworkSecurityConfig(file, root, findings)
                }
                if (file.name.endsWith("backup_rules.xml") || file.name.endsWith("data_extraction_rules.xml")) {
                    checkBackupRules(file, root, findings)
                }
            }
        }

        // ---- AndroidManifest.xml (decoded) ----
        val manifest = File(root, "resources/AndroidManifest.xml").let {
            if (it.exists()) it else File(root, "AndroidManifest.xml")
        }
        if (manifest.exists()) {
            checkDecodedManifest(manifest, root, findings)
        }

        onProgress("Decompiled source scan complete — ${findings.size} findings from source analysis")
        return findings.sortedByDescending { it.severity.ordinal }
    }

    // ----------------------------------------------------------------
    // Java source file scanner
    // ----------------------------------------------------------------

    private fun scanJavaFile(
        file: File,
        root: File,
        findings: MutableList<ApkFinding>,
        seen: MutableSet<String>,
        onProgress: (String) -> Unit = {},
    ) {
        val relPath = file.relativeTo(root).path.replace('\\', '/')
        val lines   = try { file.readLines(Charsets.UTF_8) } catch (_: Exception) { return }

        val methodWindow = mutableListOf<String>()   // sliding window for multi-line patterns
        var inOAuthHandler = false

        for ((idx, line) in lines.withIndex()) {
            val lineNum = idx + 1

            // ---- Secret patterns in string literals ----
            for ((label, pattern) in SECRET_PATTERNS) {
                val m = pattern.find(line) ?: continue
                val key = "$relPath:$lineNum:$label"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.HIGH, "secrets",
                    "$label — $relPath:$lineNum",
                    "Hardcoded secret found in decompiled Java source. The value is embedded in the APK binary and can be extracted without special privileges.",
                    buildEvidence(relPath, lineNum, line, lines, "Pattern: $label | Matched: ${m.value.take(120)}"),
                    masvsRef = "MASVS-STORAGE-2", cweRef = "CWE-798", cvss = 8.5)
                break
            }

            // ---- Sensitive logging ----
            for (pattern in LOG_SENSITIVE_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:log"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.MEDIUM, "logging",
                    "Sensitive data logged to Logcat — $relPath:$lineNum",
                    "The release build logs sensitive data (token, email, key, etc.) via Android's Log class. " +
                    "On rooted devices or devices with adb access, logcat output is readable by any app with READ_LOGS permission.",
                    buildEvidence(relPath, lineNum, line, lines, "Log call with sensitive parameter"),
                    masvsRef = "MASVS-STORAGE-2", cweRef = "CWE-532", cvss = 5.5)
                break
            }

            // ---- SharedPreferences storing sensitive values ----
            for (pattern in SHARED_PREFS_PATTERNS) {
                val m = pattern.find(line) ?: continue
                val key = "$relPath:$lineNum:sharedprefs"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.MEDIUM, "storage",
                    "Sensitive value written to SharedPreferences — $relPath:$lineNum",
                    "Sensitive data (token, key, credential, or email) is written to SharedPreferences, which " +
                    "stores data in XML files under /data/data/<pkg>/shared_prefs/. On rooted devices or via " +
                    "adb backup (if allowBackup=true), this data is accessible without the app's keys.",
                    buildEvidence(relPath, lineNum, line, lines, "SharedPreferences.putString with sensitive key"),
                    masvsRef = "MASVS-STORAGE-1", cweRef = "CWE-312", cvss = 5.0)
                break
            }

            // ---- Trust-all TLS patterns ----
            for (pattern in TRUST_ALL_PATTERNS) {
                // Collect multi-line context
                methodWindow.add(line)
                if (methodWindow.size > 6) methodWindow.removeAt(0)
                val ctx = methodWindow.joinToString(" ")
                if (!pattern.containsMatchIn(ctx)) continue
                val key = "$relPath:$lineNum:trustall"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.CRITICAL, "network",
                    "Trust-all TLS implementation — $relPath:$lineNum",
                    "The app implements a custom TrustManager or WebViewClient that accepts ALL TLS certificates, " +
                    "including self-signed and expired certificates. This completely defeats HTTPS and allows " +
                    "a man-in-the-middle attacker to intercept all TLS traffic.",
                    buildEvidence(relPath, lineNum, line, lines, "Custom TrustManager/HostnameVerifier that bypasses validation"),
                    masvsRef = "MASVS-NETWORK-2", cweRef = "CWE-295", cvss = 9.0)
                break
            }

            // ---- Client-side security bypass ----
            // Skip known utility/UI libraries whose variable names (rootLength, rootView, etc.)
            // collide with security-keyword patterns and would produce false positives.
            val isUtilityLib = listOf("okio/", "net/aihelp/", "org/apache/", "retrofit2/",
                "io/reactivex/", "rx/", "com/squareup/okio", "kotlin/")
                .any { relPath.startsWith(it, ignoreCase = true) }
            if (!isUtilityLib) {
                for (pattern in CLIENT_BYPASS_PATTERNS) {
                    if (!pattern.containsMatchIn(line)) continue
                    val key = "$relPath:$lineNum:clientbypass"
                    if (!seen.add(key)) continue
                    addFinding(findings, FindingSeverity.MEDIUM, "resilience",
                        "Client-side security check bypass — $relPath:$lineNum",
                        "A security-sensitive flag (deviceIsRooted, playIntegrityToken, or equivalent) is " +
                        "hardcoded or short-circuited to a non-detecting value in client-side code. " +
                        "An attacker with a patched APK or active Frida session can trivially bypass this. " +
                        "Integrity verification must not rely solely on client-reported values.",
                        buildEvidence(relPath, lineNum, line, lines, "Client-controlled security flag"),
                        masvsRef = "MASVS-RESILIENCE-1", cweRef = "CWE-602", cvss = 6.5)
                    break
                }
            }

            // ---- Positive root detection indicators ----
            for ((label, pattern) in ROOT_DETECTION_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:rootdetect"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.INFO, "resilience-positive",
                    "Root detection implementation — $relPath:$lineNum",
                    "The app contains root/jailbreak detection code ($label). " +
                    "This is a client-side check and can be bypassed via Frida. Verify the detection " +
                    "triggers a server-side attestation (Play Integrity / SafetyNet) or app termination, " +
                    "and test bypass with:\n  Java.use('<class>').<method>.implementation = function() { return false; }",
                    buildEvidence(relPath, lineNum, line, lines, "Root detection indicator: $label"),
                    masvsRef = "MASVS-RESILIENCE-1", cweRef = "CWE-693", cvss = 0.0)
                break
            }

            // ---- Weak cryptography ----
            for (pattern in WEAK_CRYPTO_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:weakcrypto"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.HIGH, "crypto",
                    "Weak cryptographic algorithm — $relPath:$lineNum",
                    "Use of deprecated or broken cryptographic algorithm (DES, RC4, MD5, ECB mode, SHA1) " +
                    "detected in source code. These algorithms are considered cryptographically broken and " +
                    "must not be used for security purposes.",
                    buildEvidence(relPath, lineNum, line, lines, "Weak algorithm in Cipher/MessageDigest instantiation"),
                    masvsRef = "MASVS-CRYPTO-1", cweRef = "CWE-327", cvss = 7.0)
                break
            }

            // ---- Cleartext storage ----
            for (pattern in CLEARTEXT_STORAGE_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:cleartextstorage"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.HIGH, "storage",
                    "World-readable/cleartext file storage — $relPath:$lineNum",
                    "File or SharedPreferences created with MODE_WORLD_READABLE or stored in external " +
                    "storage accessible by other apps.",
                    buildEvidence(relPath, lineNum, line, lines, "World-readable storage mode"),
                    masvsRef = "MASVS-STORAGE-1", cweRef = "CWE-276", cvss = 6.5)
                break
            }

            // ---- WebView vulnerabilities ----
            for ((label, pattern) in WEBVIEW_VULN_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:webview_$label"
                if (!seen.add(key)) continue
                val (sev, cvssScore, desc) = when {
                    label.contains("Remote Debugging") -> Triple(FindingSeverity.HIGH, 7.5,
                        "Remote debugging of WebView is enabled. Chrome DevTools can attach to this WebView " +
                        "from any USB-connected desktop, allowing inspection of JavaScript, cookies, local storage, " +
                        "and full DOM manipulation. Must be disabled in release builds.")
                    label.contains("File/Universal") -> Triple(FindingSeverity.HIGH, 8.1,
                        "WebView allows JavaScript to read files from the filesystem via file:// URLs. " +
                        "Combined with XSS or injected JavaScript, this can exfiltrate arbitrary app files " +
                        "(SharedPreferences, databases, tokens) to a remote server.")
                    label.contains("External Storage") -> Triple(FindingSeverity.HIGH, 6.5,
                        "WebView loads content from external storage (SD card). External storage is world-readable " +
                        "and can be written by any app with WRITE_EXTERNAL_STORAGE permission, enabling " +
                        "content injection attacks.")
                    else -> Triple(FindingSeverity.MEDIUM, 5.0,
                        "WebView configuration issue detected — $label.")
                }
                addFinding(findings, sev, "webview",
                    "$label — $relPath:$lineNum",
                    desc,
                    buildEvidence(relPath, lineNum, line, lines, "WebView misconfiguration: $label"),
                    masvsRef = "MASVS-PLATFORM-2", cweRef = "CWE-749", cvss = cvssScore)
                break
            }

            // ---- Insecure random number generator ----
            if (INSECURE_RANDOM_PATTERN.containsMatchIn(line)) {
                val key = "$relPath:$lineNum:insecurerandom"
                if (seen.add(key)) {
                    addFinding(findings, FindingSeverity.MEDIUM, "crypto",
                        "Insecure PRNG (java.util.Random) — $relPath:$lineNum",
                        "java.util.Random is a pseudo-random number generator (PRNG) that is NOT " +
                        "cryptographically secure. Its output is predictable given a small sample of values. " +
                        "It must not be used to generate session tokens, nonces, IVs, salts, or any " +
                        "security-sensitive random values. Use java.security.SecureRandom instead.",
                        buildEvidence(relPath, lineNum, line, lines, "java.util.Random — not cryptographically secure"),
                        masvsRef = "MASVS-CRYPTO-1", cweRef = "CWE-330", cvss = 6.8)
                }
            }

            // ---- Unsafe deserialization ----
            for ((label, pattern) in DESERIALIZATION_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:deserialize_$label"
                if (!seen.add(key)) continue
                val (cvssScore, desc) = when {
                    label.contains("Jackson") -> 8.1 to
                        "Jackson ObjectMapper.enableDefaultTyping() enables polymorphic type handling for all " +
                        "deserialized objects. When combined with untrusted input, this allows an attacker to " +
                        "specify an arbitrary class name that gets instantiated during deserialization, " +
                        "potentially leading to remote code execution. This is CVE-2017-7525 and related issues."
                    else -> 7.5 to
                        "Java object deserialization of untrusted data can lead to arbitrary code execution. " +
                        "Verify that all data passed to ObjectInputStream originates from a trusted source " +
                        "and consider using a safer serialization format (JSON, Protobuf) with type allowlists."
                }
                addFinding(findings, FindingSeverity.HIGH, "deserialization",
                    "$label — $relPath:$lineNum",
                    desc,
                    buildEvidence(relPath, lineNum, line, lines, "Unsafe deserialization: $label"),
                    masvsRef = "MASVS-CODE-5", cweRef = "CWE-502", cvss = cvssScore)
                break
            }

            // ---- SQL injection surface ----
            for ((label, pattern) in SQL_INJECTION_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:sqlinject_$label"
                if (!seen.add(key)) continue
                addFinding(findings, FindingSeverity.MEDIUM, "sql-injection",
                    "$label — $relPath:$lineNum",
                    "Raw SQL execution detected. If any part of the SQL string is constructed from " +
                    "unsanitized user input or external data (Intent extras, deep-link parameters, server " +
                    "responses), this is a SQL injection vulnerability. Use parameterized queries " +
                    "(query() with selection args) instead of raw string concatenation.",
                    buildEvidence(relPath, lineNum, line, lines, "Raw SQL execution — verify parameterized args"),
                    masvsRef = "MASVS-CODE-5", cweRef = "CWE-89", cvss = 6.5)
                break
            }

            // ---- Extended crypto weaknesses ----
            for ((label, pattern) in CRYPTO_EXTRA_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:cryptoextra_$label"
                if (!seen.add(key)) continue
                val (cvssScore, desc) = when {
                    label.contains("AES ECB") -> 6.5 to
                        "Calling Cipher.getInstance(\"AES\") without specifying a mode returns AES in ECB mode " +
                        "by default on most JVMs. ECB mode encrypts each block independently, producing " +
                        "identical ciphertext for identical plaintext blocks — this leaks data patterns " +
                        "and is deterministically reversible given a known-plaintext block."
                    label.contains("RSA") -> 7.5 to
                        "RSA encryption without OAEP padding (NoPadding mode) is vulnerable to Bleichenbacher's " +
                        "chosen-ciphertext attack and other padding oracle attacks. Always use " +
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding."
                    label.contains("CBC") -> 7.4 to
                        "AES/CBC with PKCS5/PKCS7 padding is vulnerable to padding oracle attacks (POODLE, " +
                        "BEAST-derived). If the decryption result is returned to a client or an error is " +
                        "observable, an attacker can decrypt arbitrary ciphertext in O(n) oracle queries. " +
                        "Prefer AES-GCM (authenticated encryption)."
                    label.contains("IV") -> 8.1 to
                        "Hardcoded or sequential IV values destroy the security of CBC/CTR modes. An IV must be " +
                        "random and unique for each encryption operation. Predictable IVs allow an attacker " +
                        "to determine if two messages start with the same plaintext."
                    else -> 7.0 to "Weak cryptographic configuration detected — $label."
                }
                addFinding(findings, FindingSeverity.HIGH, "crypto",
                    "$label — $relPath:$lineNum",
                    desc,
                    buildEvidence(relPath, lineNum, line, lines, "Crypto weakness: $label"),
                    masvsRef = "MASVS-CRYPTO-1", cweRef = "CWE-327", cvss = cvssScore)
                break
            }

            // ---- Positive security indicators ----
            for ((label, pattern, masvsRef) in POSITIVE_SECURITY_PATTERNS) {
                if (!pattern.containsMatchIn(line)) continue
                val key = "$relPath:$lineNum:positive_$label"
                if (!seen.add(key)) continue
                val desc = when {
                    masvsRef == "MASVS-NETWORK-3" ->
                        "Certificate pinning implementation detected ($label). This prevents MITM attacks " +
                        "even when a CA is compromised. Verify the pin set covers all production endpoints " +
                        "and includes backup pins with a documented rotation process."
                    masvsRef == "MASVS-RESILIENCE-6" ->
                        "Anti-Frida/anti-instrumentation detection code found ($label). " +
                        "Verify bypass difficulty via dynamic testing: load fridalink and confirm detection fires."
                    masvsRef == "MASVS-RESILIENCE-3" ->
                        "Application integrity verification code detected ($label). " +
                        "Verify this triggers a server-side check or forces app exit — client-only checks " +
                        "can be bypassed via Frida."
                    masvsRef == "MASVS-RESILIENCE-1" ->
                        "Play Integrity / SafetyNet attestation detected ($label). " +
                        "Verify attestation results are validated server-side and tokens cannot be replayed."
                    masvsRef == "MASVS-STORAGE-4" ->
                        "FLAG_SECURE detected — prevents screenshot capture and screen recording from " +
                        "capturing sensitive content in the Recent Apps panel and via Android screencap API."
                    masvsRef == "MASVS-STORAGE-7" ->
                        "Encrypted storage implementation detected ($label). " +
                        "Verify the encryption key is stored in Android Keystore and not hardcoded."
                    masvsRef == "MASVS-PLATFORM-2" ->
                        "Tapjacking protection (setFilterTouchesWhenObscured=true) detected. " +
                        "This prevents touch injection through overlay windows."
                    else -> "Positive security control detected ($label)."
                }
                addFinding(findings, FindingSeverity.INFO, "resilience-positive",
                    "$label — $relPath:$lineNum",
                    desc,
                    buildEvidence(relPath, lineNum, line, lines, "Positive indicator: $label"),
                    masvsRef = masvsRef, cweRef = "", cvss = 0.0)
                break
            }

            // ---- OAuth state validation tracking ----
            if (OAUTH_NO_STATE_PATTERN.containsMatchIn(line)) {
                inOAuthHandler = true
                methodWindow.clear()
            }
            if (inOAuthHandler) {
                methodWindow.add(line)
                if (methodWindow.size > 40) {
                    // Scanned 40 lines of the handler — check if state was validated
                    val handlerText = methodWindow.joinToString("\n")
                    if (!OAUTH_STATE_CHECK.containsMatchIn(handlerText)) {
                        val key = "$relPath:$lineNum:oauthstate"
                        if (seen.add(key)) {
                            addFinding(findings, FindingSeverity.HIGH, "auth",
                                "OAuth callback missing state/CSRF validation — $relPath:$lineNum",
                                "The OAuth callback handler does not validate the 'state' parameter. " +
                                "An attacker who can deliver a valid authorization code to the callback URI " +
                                "(e.g., via a malicious app registering the same custom scheme) can force " +
                                "login or account linking (OAuth CSRF / authorization code injection).",
                                buildEvidence(relPath, lineNum, line, lines, "OAuth handler without state parameter check"),
                                masvsRef = "MASVS-AUTH-1", cweRef = "CWE-352", cvss = 7.5)
                        }
                    }
                    inOAuthHandler = false
                    methodWindow.clear()
                }
                if (line.contains("}", ignoreCase = false) && methodWindow.size > 10) {
                    val handlerText = methodWindow.joinToString("\n")
                    if (OAUTH_NO_STATE_PATTERN.containsMatchIn(handlerText) &&
                        !OAUTH_STATE_CHECK.containsMatchIn(handlerText)) {
                        val key = "$relPath:${lineNum}_oauthstate"
                        if (seen.add(key)) {
                            addFinding(findings, FindingSeverity.HIGH, "auth",
                                "OAuth callback missing state/CSRF validation — $relPath:$lineNum",
                                "The OAuth callback handler does not validate the 'state' parameter. " +
                                "An attacker who can deliver a valid authorization code to the callback URI " +
                                "(e.g., via a malicious app registering the same custom scheme) can force " +
                                "login or account linking (OAuth CSRF / authorization code injection).",
                                buildEvidence(relPath, lineNum, line, lines, "OAuth callback handler without state check"),
                                masvsRef = "MASVS-AUTH-1", cweRef = "CWE-352", cvss = 7.5)
                        }
                    }
                    inOAuthHandler = false
                    methodWindow.clear()
                }
            }
        }

        // ---- File-level: WebView JavaScript + JavaScript Interface ----
        // These two calls in the same file constitute a high-risk WebView configuration.
        val fullText = lines.joinToString("\n")
        if (Regex("""setJavaScriptEnabled\(\s*true\s*\)""").containsMatchIn(fullText) &&
            Regex("""addJavascriptInterface\s*\(""").containsMatchIn(fullText)) {
            val key = "$relPath:webview_js_interface"
            if (seen.add(key)) {
                val jsLine = lines.indexOfFirst { Regex("""setJavaScriptEnabled\(\s*true\s*\)""").containsMatchIn(it) } + 1
                addFinding(findings, FindingSeverity.HIGH, "webview",
                    "WebView JavaScript + Java Interface Exposed — $relPath:$jsLine",
                    "The WebView has JavaScript enabled AND exposes Java methods via addJavascriptInterface(). " +
                    "Any JavaScript executing in this WebView (including via XSS or injected content) can call " +
                    "the Java interface methods. On API < 17 all public methods are accessible. " +
                    "On API ≥ 17 only @JavascriptInterface-annotated methods are callable — but if those " +
                    "methods accept unsanitized input the attack surface is still significant.",
                    buildString {
                        appendLine("File    : $relPath")
                        appendLine("Pattern : setJavaScriptEnabled(true) + addJavascriptInterface() in same file")
                        appendLine("CWE     : CWE-749 (Exposed Dangerous Method or Function)")
                        appendLine()
                        val jsLine2 = lines.indexOfFirst { Regex("""setJavaScriptEnabled\(\s*true\s*\)""").containsMatchIn(it) } + 1
                        val ifLine  = lines.indexOfFirst { Regex("""addJavascriptInterface\s*\(""").containsMatchIn(it) } + 1
                        appendLine("setJavaScriptEnabled(true) at line  : $jsLine2")
                        append("addJavascriptInterface()       at line  : $ifLine")
                    },
                    masvsRef = "MASVS-PLATFORM-2", cweRef = "CWE-749", cvss = 8.8)
            }
        }

        // ---- File-level: BuildConfig.DEBUG = true ----
        if (Regex("""\bclass\s+BuildConfig\b""").containsMatchIn(fullText) &&
            Regex("""DEBUG\s*=\s*true""").containsMatchIn(fullText)) {
            val key = "$relPath:buildconfig_debug"
            if (seen.add(key)) {
                val debugLine = lines.indexOfFirst { Regex("""DEBUG\s*=\s*true""").containsMatchIn(it) } + 1
                addFinding(findings, FindingSeverity.HIGH, "code",
                    "BuildConfig.DEBUG = true in decompiled source — $relPath:$debugLine",
                    "The decompiled BuildConfig class shows DEBUG = true. This means the APK was built with " +
                    "debug configuration enabled, which typically enables verbose logging, disables ProGuard " +
                    "shrinking/obfuscation, and may trigger additional debug code paths. Production APKs " +
                    "distributed to users must have DEBUG = false.",
                    buildEvidence(relPath, debugLine, lines.getOrElse(debugLine - 1) { "" }, lines, "BuildConfig.DEBUG=true"),
                    masvsRef = "MASVS-CODE-1", cweRef = "CWE-489", cvss = 5.0)
            }
        }
    }

    // ----------------------------------------------------------------
    // Plaintext asset / resource file scanner
    // ----------------------------------------------------------------

    private fun scanTextFile(
        file: File,
        root: File,
        findings: MutableList<ApkFinding>,
        seen: MutableSet<String>,
    ) {
        // Only scan text-like files; skip large binaries
        if (file.length() > 2_000_000) return
        val ext = file.extension.lowercase()
        if (ext !in setOf("json", "xml", "txt", "properties", "cfg", "conf", "yaml", "yml", "pem", "key", "crt")) return

        val relPath = file.relativeTo(root).path.replace('\\', '/')
        val text = try { file.readText(Charsets.UTF_8) } catch (_: Exception) { return }
        val lines = text.lines()

        // ---- Full PEM block extraction ----
        if (text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----")) {
            val pemBlock = extractPemBlock(text)
            val key = "$relPath:pem"
            if (seen.add(key)) {
                findings.add(ApkFinding(
                    severity    = FindingSeverity.CRITICAL,
                    category    = "secrets",
                    title       = "Private Key (PEM) embedded in asset — $relPath",
                    description = "A PEM-encoded private key is embedded in a bundled asset file. " +
                        "Any attacker who decompiles the APK can extract and use this key to impersonate " +
                        "the server or sign data. Private keys must NEVER be bundled in client-side applications.",
                    evidence    = "File: $relPath\n\nFull PEM block:\n$pemBlock",
                    mitigation  = "Remove the private key from the APK immediately. Revoke and rotate the key. " +
                        "Private keys belong only on server infrastructure with hardware security module (HSM) protection.",
                    masvsRef    = "MASVS-STORAGE-2",
                    cweRef      = "CWE-321",
                    cvssScore   = 9.8,
                ))
            }
        }

        for ((lineIdx, line) in lines.withIndex()) {
            val lineNum = lineIdx + 1
            for ((label, pattern) in SECRET_PATTERNS) {
                val m = pattern.find(line) ?: continue
                // For PEM headers, capture the full block
                val matchedValue = if (label == "Private Key (PEM)") {
                    extractPemBlock(text.substring(text.indexOf(m.value)))
                } else {
                    m.value.take(200)
                }
                val key = "$relPath:$lineNum:$label"
                if (!seen.add(key)) continue

                addFinding(findings, FindingSeverity.HIGH, "secrets",
                    "$label in asset file — $relPath:$lineNum",
                    "Hardcoded secret found in bundled asset file. Asset files are accessible to anyone " +
                    "who opens the APK (it is a ZIP file). No special tools required.",
                    "File     : $relPath\nLine     : $lineNum\nPattern  : $label\nValue    :\n$matchedValue\n\nLine content:\n  ${line.trim().take(300)}",
                    masvsRef = "MASVS-STORAGE-2", cweRef = "CWE-798", cvss = 8.0)
                break
            }
        }
    }

    // ----------------------------------------------------------------
    // Decoded manifest checks
    // ----------------------------------------------------------------

    private fun checkDecodedManifest(manifest: File, root: File, findings: MutableList<ApkFinding>) {
        val relPath = manifest.relativeTo(root).path.replace('\\', '/')
        val text = try { manifest.readText() } catch (_: Exception) { return }
        val lines = text.lines()

        for ((idx, line) in lines.withIndex()) {
            val lineNum = idx + 1

            if (line.contains("android:debuggable=\"true\"")) {
                addFinding(findings, FindingSeverity.HIGH, "code",
                    "android:debuggable=true in manifest — $relPath:$lineNum",
                    "The application is configured as debuggable. On a rooted device or emulator, " +
                    "this allows arbitrary code execution under the app's UID via adb, extraction of " +
                    "SharedPreferences, inspection of memory, and attachment of a Java debugger.",
                    buildEvidence(relPath, lineNum, line, lines, "debuggable=true"),
                    masvsRef = "MASVS-CODE-1", cweRef = "CWE-94", cvss = 8.0)
            }

            if (line.contains("android:allowBackup=\"true\"")) {
                addFinding(findings, FindingSeverity.MEDIUM, "storage",
                    "android:allowBackup=true — $relPath:$lineNum",
                    "The application allows full data backup via adb backup. An attacker with USB access " +
                    "can extract the app's data directory including SharedPreferences, databases, and files " +
                    "without requiring root. Combined with sensitive data in SharedPreferences, this is " +
                    "a high-severity data exposure path.",
                    buildEvidence(relPath, lineNum, line, lines, "allowBackup=true"),
                    masvsRef = "MASVS-STORAGE-6", cweRef = "CWE-312", cvss = 5.5)
            }

            if (line.contains("android:networkSecurityConfig") && !line.contains("<!--")) {
                // Network security config present — positive signal
            }

            // Exported activity/receiver without permission
            if ((line.contains("activity") || line.contains("receiver") || line.contains("provider")) &&
                line.contains("android:exported=\"true\"") &&
                !line.contains("android:permission=")) {
                addFinding(findings, FindingSeverity.MEDIUM, "platform",
                    "Exported component without permission — $relPath:$lineNum",
                    "An Android component (Activity, Receiver, or Provider) is exported without requiring " +
                    "any permission. Any app on the device can interact with it. Verify that this is " +
                    "intentional and that the component validates its inputs.",
                    buildEvidence(relPath, lineNum, line, lines, "exported=true without android:permission"),
                    masvsRef = "MASVS-PLATFORM-1", cweRef = "CWE-926", cvss = 5.0)
            }

            // Custom URL scheme handler — OAuth CSRF surface
            if (line.contains("android:scheme=") && !line.contains("http")) {
                addFinding(findings, FindingSeverity.LOW, "platform",
                    "Custom URL scheme registered — $relPath:$lineNum",
                    "The app registers a custom URL scheme. Custom schemes can be used as OAuth redirect " +
                    "URIs and are vulnerable to URL hijacking on Android (any app can register the same scheme). " +
                    "Verify the OAuth callback validates the state parameter and uses Android App Links (https://) " +
                    "for redirect URIs instead of custom schemes.",
                    buildEvidence(relPath, lineNum, line, lines, "Custom URL scheme"),
                    masvsRef = "MASVS-PLATFORM-3", cweRef = "CWE-939", cvss = 4.0)
            }
        }
    }

    // ----------------------------------------------------------------
    // Network security config check
    // ----------------------------------------------------------------

    private fun checkNetworkSecurityConfig(file: File, root: File, findings: MutableList<ApkFinding>) {
        val relPath = file.relativeTo(root).path.replace('\\', '/')
        val text = try { file.readText() } catch (_: Exception) { return }

        if (text.contains("cleartextTrafficPermitted=\"true\"")) {
            addFinding(findings, FindingSeverity.HIGH, "network",
                "cleartextTrafficPermitted=true in network_security_config.xml",
                "The network security configuration explicitly permits cleartext (HTTP) traffic. " +
                "This allows the app to send data over unencrypted connections, exposing it to " +
                "passive eavesdropping and active MITM attacks on any network.",
                "File: $relPath\n\n${text.take(500)}",
                masvsRef = "MASVS-NETWORK-1", cweRef = "CWE-319", cvss = 7.5)
        }

        if (text.contains("<trust-anchors>") && text.contains("user")) {
            addFinding(findings, FindingSeverity.MEDIUM, "network",
                "User certificates trusted in network_security_config.xml",
                "The network security configuration trusts user-installed certificates. This allows " +
                "the app's TLS traffic to be intercepted by installing a proxy CA certificate, " +
                "bypassing certificate pinning for standard HTTPS connections.",
                "File: $relPath\n\n${text.take(500)}",
                masvsRef = "MASVS-NETWORK-2", cweRef = "CWE-295", cvss = 6.5)
        }
    }

    // ----------------------------------------------------------------
    // Backup rules check
    // ----------------------------------------------------------------

    private fun checkBackupRules(file: File, root: File, findings: MutableList<ApkFinding>) {
        val relPath = file.relativeTo(root).path.replace('\\', '/')
        val text = try { file.readText() } catch (_: Exception) { return }

        // Check if it only excludes AppsFlyer (the Bleach specific case)
        if (text.contains("appsflyer", ignoreCase = true) && !text.contains("apj_sdk_global", ignoreCase = true)) {
            addFinding(findings, FindingSeverity.MEDIUM, "storage",
                "Backup rules exclude only AppsFlyer — sensitive app SharedPrefs not excluded",
                "The backup rules file only excludes AppsFlyer data. App-specific SharedPreferences " +
                "containing authentication tokens and session data (e.g. apj_sdk_global) are not excluded " +
                "from backup, meaning they are recoverable via adb backup if allowBackup=true.",
                "File: $relPath\n\nContent:\n$text",
                masvsRef = "MASVS-STORAGE-6", cweRef = "CWE-312", cvss = 5.0)
        }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private fun extractPemBlock(text: String): String {
        val beginMarkers = listOf(
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        )
        for (marker in beginMarkers) {
            val start = text.indexOf(marker)
            if (start < 0) continue
            val endMarker = marker.replace("BEGIN", "END")
            val end = text.indexOf(endMarker, start)
            if (end < 0) return text.substring(start, minOf(start + 2048, text.length))
            return text.substring(start, end + endMarker.length)
        }
        val start = text.indexOf("-----BEGIN")
        if (start < 0) return ""
        val end = text.indexOf("-----", start + 10)
        return if (end > start) text.substring(start, end + 5) else text.substring(start, minOf(start + 2048, text.length))
    }

    private fun buildEvidence(
        relPath: String,
        lineNum: Int,
        line: String,
        lines: List<String>,
        note: String,
    ): String = buildString {
        appendLine("File    : $relPath")
        appendLine("Line    : $lineNum")
        appendLine("Note    : $note")
        appendLine("")
        val before = (lineNum - 3).coerceAtLeast(0)
        val after  = (lineNum + 2).coerceAtMost(lines.size)
        for (i in before until after) {
            val marker = if (i == lineNum - 1) ">>>" else "   "
            appendLine("$marker ${(i + 1).toString().padStart(4)}  ${lines[i].take(200)}")
        }
    }.trimEnd()

    private fun addFinding(
        findings: MutableList<ApkFinding>,
        severity: FindingSeverity,
        category: String,
        title: String,
        description: String,
        evidence: String,
        masvsRef: String = "",
        cweRef: String = "",
        cvss: Double = 0.0,
    ) {
        findings.add(ApkFinding(
            severity    = severity,
            category    = category,
            title       = title,
            description = description,
            evidence    = evidence,
            mitigation  = buildMitigation(category, severity),
            masvsRef    = masvsRef,
            cweRef      = cweRef,
            cvssScore   = cvss,
        ))
    }

    private fun buildMitigation(category: String, severity: FindingSeverity): String = when (category) {
        "secrets"    -> "Remove hardcoded secret from application code. Rotate the exposed credential immediately. Fetch secrets from a secure remote configuration endpoint or use Android Keystore for key storage."
        "logging"    -> "Remove or guard all Log.d/Log.i/Log.e calls that output sensitive data. Use a debug-only logging wrapper gated on BuildConfig.DEBUG. Consider using a runtime logging SDK (Timber) with production tree that discards logs."
        "storage"    -> "Encrypt sensitive data at rest using Android Keystore AES-GCM. Set allowBackup=false or define comprehensive BackupAgent/BackupRules that exclude sensitive SharedPreferences."
        "network"    -> "Enforce TLS 1.2+ for all connections. Implement certificate pinning for critical API endpoints. Set cleartextTrafficPermitted=false in network_security_config.xml."
        "auth"       -> "Validate the OAuth state parameter in all redirect/callback handlers to prevent CSRF. Use PKCE (RFC 7636) for mobile OAuth flows. Prefer Android App Links over custom URL schemes for redirect URIs."
        "crypto"     -> "Use AES-256-GCM or ChaCha20-Poly1305. Use SHA-256 or SHA-3 for hashing. Never use ECB mode. Store keys in Android Keystore."
        "platform"   -> "Protect exported components with android:permission. Validate all deep-link input parameters server-side."
        "resilience" -> "Perform integrity checks server-side using Play Integrity API attestation. Never trust client-reported security status values."
        "code"       -> "Set android:debuggable=false in the release manifest. ProGuard/R8 obfuscation should be enabled for release builds."
        else         -> "Review and remediate according to OWASP MASVS v2 guidelines."
    }
}
