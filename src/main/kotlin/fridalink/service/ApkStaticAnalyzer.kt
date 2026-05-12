package fridalink.service

import fridalink.model.ApkFinding
import fridalink.model.CertInfo
import fridalink.model.FindingSeverity
import fridalink.model.LibraryInfo
import fridalink.model.UrlReference
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * Performs static analysis on an APK file (which is a ZIP archive).
 * Checks for common Android security issues per OWASP MASVS.
 *
 * Evidence reporting is verbose: each finding includes the exact matched value,
 * byte offset, surrounding context snippet, nearest DEX class descriptor (for
 * .dex files), and the specific pattern label that triggered the finding.
 */
class ApkStaticAnalyzer {

    data class AnalysisResult(
        val findings: List<ApkFinding>,
        val permissions: List<String>,
        val activities: List<String>,
        val services: List<String>,
        val receivers: List<String>,
        val providers: List<String>,
        val urls: List<String>,
        val urlRefs: List<UrlReference>,
        val hasNativeLibs: Boolean,
        val nativeLibs: List<String>,
        val libraries: List<LibraryInfo>,
        val signingInfo: String,
        val certInfo: CertInfo?,
        val minSdk: Int,
        val targetSdk: Int,
        val packageName: String,
        val appVersion: String,
        val behaviorProfile: String,
    )

    fun analyze(apkPath: String, onProgress: (String) -> Unit = {}): AnalysisResult {
        val findings = mutableListOf<ApkFinding>()
        val permissions = mutableListOf<String>()
        val activities = mutableListOf<String>()
        val services = mutableListOf<String>()
        val receivers = mutableListOf<String>()
        val providers = mutableListOf<String>()
        val urls = mutableListOf<String>()
        val nativeLibs = mutableListOf<String>()
        val allDexStrings = mutableListOf<String>()
        var signingInfo = ""
        var certInfo: CertInfo? = null
        var minSdk = 0
        var targetSdk = 0
        var packageName = ""
        var appVersion = ""

        try {
            ZipFile(apkPath).use { apk ->
                val entries = apk.entries().toList()
                onProgress("APK contains ${entries.size} entries")

                for (entry in entries) {
                    when {
                        // ---- AndroidManifest.xml ----
                        entry.name == "AndroidManifest.xml" -> {
                            onProgress("Scanning AndroidManifest.xml...")
                            val bytes = apk.getInputStream(entry).readBytes()
                            val strings = extractStringsFromBinaryXml(bytes)
                            extractPermissions(strings).let { permissions.addAll(it) }
                            packageName = extractPackageName(strings)
                            extractActivities(strings).let { activities.addAll(it) }
                            extractServices(strings).let { services.addAll(it) }
                            extractReceivers(strings).let { receivers.addAll(it) }
                            extractProviders(strings).let { providers.addAll(it) }
                            minSdk = extractSdkVersion(strings, "minSdkVersion")
                            targetSdk = extractSdkVersion(strings, "targetSdkVersion")
                            appVersion = extractAppVersion(strings)
                            checkManifestSecurity(strings, bytes, findings)
                        }

                        // ---- DEX files — verbose byte-offset string scanning ----
                        entry.name.endsWith(".dex") -> {
                            onProgress("Scanning ${entry.name} for secrets...")
                            val bytes = apk.getInputStream(entry).readBytes()
                            val strs = extractAsciiStrings(bytes, minLen = 8)
                            allDexStrings.addAll(strs)
                            scanForSecretsFromBytes(bytes, entry.name, findings)
                            extractUrls(strs).let { urls.addAll(it) }
                        }

                        // ---- Assets ----
                        entry.name.startsWith("assets/") && !entry.isDirectory -> {
                            onProgress("Scanning ${entry.name}...")
                            val bytes = apk.getInputStream(entry).readBytes()
                            val isText = entry.name.endsWith(".json") || entry.name.endsWith(".xml") ||
                                entry.name.endsWith(".yaml") || entry.name.endsWith(".yml") ||
                                entry.name.endsWith(".txt") || entry.name.endsWith(".properties") ||
                                entry.name.endsWith(".cfg") || entry.name.endsWith(".conf")
                            if (isText) {
                                val text = try { bytes.toString(Charsets.UTF_8) } catch (_: Exception) { "" }
                                scanForSecretsFromText(text, entry.name, findings)
                                checkCleartextConfig(text, entry.name, findings)
                                extractUrls(listOf(text)).let { urls.addAll(it) }
                            } else {
                                scanForSecretsFromBytes(bytes, entry.name, findings)
                            }
                        }

                        // ---- Native libs ----
                        entry.name.startsWith("lib/") && entry.name.endsWith(".so") -> {
                            nativeLibs.add(entry.name)
                        }

                        // ---- Signing cert ----
                        entry.name.startsWith("META-INF/") &&
                            (entry.name.endsWith(".RSA") || entry.name.endsWith(".DSA") || entry.name.endsWith(".EC")) -> {
                            signingInfo = entry.name
                            if (certInfo == null) {
                                onProgress("Parsing signing certificate from ${entry.name}...")
                                certInfo = parseCertInfo(apk.getInputStream(entry).readBytes(), entry.name)
                            }
                        }

                        // ---- Network security config ----
                        entry.name == "res/xml/network_security_config.xml" -> {
                            onProgress("Checking network_security_config.xml...")
                            val text = apk.getInputStream(entry).bufferedReader().readText()
                            checkNetworkSecurityConfig(text, findings)
                        }

                        // ---- Backup rules ----
                        entry.name.endsWith("backup_rules.xml") || entry.name.endsWith("data_extraction_rules.xml") -> {
                            val text = apk.getInputStream(entry).bufferedReader().readText()
                            if (text.contains("exclude") || text.contains("requireTransportSecurity")) {
                                onProgress("Backup rules found in ${entry.name}")
                            }
                        }
                    }
                }

                // ---- Post-analysis checks ----
                checkPermissions(permissions, findings)
                checkNativeLibs(nativeLibs, findings)
                checkSdkVersions(minSdk, targetSdk, findings)
                checkNetworkSecurity(urls, findings)
            }
        } catch (e: Exception) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.INFO,
                category    = "analysis",
                title       = "APK Analysis Error",
                description = "Could not fully analyze APK: ${e.message}",
                evidence    = e.stackTraceToString().take(500),
                mitigation  = "Ensure the APK is not corrupted.",
            ))
        }

        val distinctUrls = urls.distinct().sorted()
        val libraries = detectLibraries(allDexStrings, nativeLibs.distinct())
        val behaviorProfile = buildBehaviorProfile(
            packageName = packageName,
            appVersion  = appVersion,
            minSdk      = minSdk,
            targetSdk   = targetSdk,
            permissions = permissions.distinct().sorted(),
            activities  = activities.distinct(),
            services    = services.distinct(),
            receivers   = receivers.distinct(),
            providers   = providers.distinct(),
            nativeLibs  = nativeLibs.distinct().sorted(),
            libraries   = libraries,
            urls        = distinctUrls,
            certInfo    = certInfo,
        )

        return AnalysisResult(
            findings      = findings.sortedByDescending { it.severity.ordinal },
            permissions   = permissions.distinct().sorted(),
            activities    = activities.distinct(),
            services      = services.distinct(),
            receivers     = receivers.distinct(),
            providers     = providers.distinct(),
            urls          = distinctUrls,
            urlRefs       = buildUrlRefs(distinctUrls),
            hasNativeLibs = nativeLibs.isNotEmpty(),
            nativeLibs    = nativeLibs.distinct().sorted(),
            libraries     = libraries,
            signingInfo   = signingInfo,
            certInfo      = certInfo,
            minSdk        = minSdk,
            targetSdk     = targetSdk,
            packageName   = packageName,
            appVersion    = appVersion,
            behaviorProfile = behaviorProfile,
        )
    }

    // ----------------------------------------------------------------
    // Secret scanning — verbose binary (DEX / binary assets)
    // ----------------------------------------------------------------

    /**
     * Scans a byte array for secret patterns.
     * Reports one ApkFinding per unique match, with:
     *   - The exact matched value
     *   - Byte offset (decimal + hex)
     *   - Surrounding printable-ASCII context (~80 chars)
     *   - Nearest DEX class descriptor (for .dex files)
     *   - The pattern label that triggered the finding
     */
    private fun scanForSecretsFromBytes(bytes: ByteArray, source: String, findings: MutableList<ApkFinding>) {
        val isDex = source.endsWith(".dex")
        val strings = extractAsciiStringsWithOffsets(bytes)
        val seen = mutableSetOf<String>()   // de-duplicate identical matched values

        for ((offset, str) in strings) {
            for ((pattern, label) in SECRET_PATTERNS) {
                val matchResult = pattern.find(str) ?: continue
                val matchedValue = matchResult.value.take(120)
                if (!seen.add(matchedValue)) continue   // skip exact duplicates

                // Printable-ASCII context around the match in the raw byte stream
                val ctxStart = maxOf(0, offset - 50)
                val ctxEnd   = minOf(bytes.size, offset + str.length + 50)
                val ctxRaw   = buildString {
                    for (i in ctxStart until ctxEnd) {
                        val c = bytes[i].toInt() and 0xFF
                        append(if (c in 32..126) c.toChar() else '.')
                    }
                }.trim()

                // Nearest DEX class descriptor (scan backwards up to 4KB)
                val nearestClass = if (isDex) findNearestDexClass(bytes, offset) else ""

                val evidence = buildString {
                    appendLine("Pattern triggered : $label")
                    appendLine("Matched value     : $matchedValue")
                    appendLine("Location          : $source")
                    appendLine("Byte offset       : $offset (0x${offset.toString(16).uppercase()})")
                    if (nearestClass.isNotEmpty())
                        appendLine("Nearest DEX class : $nearestClass")
                    appendLine("Context snippet   : ...${ctxRaw.take(150)}...")
                }.trimEnd()

                findings.add(ApkFinding(
                    severity    = FindingSeverity.HIGH,
                    category    = "secrets",
                    title       = "$label Detected — $source",
                    description = "A hardcoded secret matching the '$label' pattern was found embedded in the application binary at byte offset $offset. This value can be extracted from the APK by anyone with reverse-engineering tools (apktool, jadx, strings) without any special privileges.",
                    evidence    = evidence,
                    mitigation  = "Remove hardcoded secrets from the application binary. Store API keys server-side or use Android Keystore API. Rotate any exposed credentials immediately. Add ProGuard/R8 obfuscation as a deterrent (but not a fix).",
                    masvsRef    = "MASVS-STORAGE-2",
                    cweRef      = "CWE-798",
                    cvssScore   = 8.5,
                ))
                break   // first matching pattern wins for this string
            }
        }
    }

    /**
     * Scans a plaintext asset file for secret patterns.
     * Reports one ApkFinding per match with exact line number, line content,
     * and one line of before/after context.
     */
    private fun scanForSecretsFromText(text: String, source: String, findings: MutableList<ApkFinding>) {
        if (text.isBlank()) return
        val lines = text.lines()
        val seen = mutableSetOf<String>()

        for ((lineIdx, line) in lines.withIndex()) {
            for ((pattern, label) in SECRET_PATTERNS) {
                val matchResult = pattern.find(line) ?: continue
                val matchedValue = matchResult.value.take(120)
                if (!seen.add(matchedValue)) continue

                val lineNum    = lineIdx + 1
                val ctxBefore  = if (lineIdx > 0) lines[lineIdx - 1].trim().take(120) else ""
                val ctxAfter   = if (lineIdx + 1 < lines.size) lines[lineIdx + 1].trim().take(120) else ""
                val matchStart = matchResult.range.first
                val matchEnd   = matchResult.range.last

                val evidence = buildString {
                    appendLine("Pattern triggered : $label")
                    appendLine("Matched value     : $matchedValue")
                    appendLine("File              : $source")
                    appendLine("Line              : $lineNum  (columns ${matchStart + 1}–${matchEnd + 1})")
                    appendLine("Line content      : ${line.trim().take(200)}")
                    if (ctxBefore.isNotEmpty()) appendLine("Context (line ${lineNum - 1}) : $ctxBefore")
                    if (ctxAfter.isNotEmpty())  appendLine("Context (line ${lineNum + 1}) : $ctxAfter")
                }.trimEnd()

                findings.add(ApkFinding(
                    severity    = FindingSeverity.HIGH,
                    category    = "secrets",
                    title       = "$label in $source (line $lineNum)",
                    description = "A hardcoded secret was found in a bundled asset file at line $lineNum. Asset files are plain-text resources accessible to anyone who decompiles the APK with apktool or unzips it directly.",
                    evidence    = evidence,
                    mitigation  = "Remove hardcoded secrets from bundled asset files. Fetch sensitive configuration from a secure server endpoint at runtime with mutual TLS.",
                    masvsRef    = "MASVS-STORAGE-2",
                    cweRef      = "CWE-312",
                    cvssScore   = 8.0,
                ))
                break
            }
        }
    }

    // ----------------------------------------------------------------
    // String extraction helpers
    // ----------------------------------------------------------------

    /** Returns (byteOffset, string) pairs for all printable ASCII runs ≥ minLen bytes. */
    private fun extractAsciiStringsWithOffsets(bytes: ByteArray, minLen: Int = 8): List<Pair<Int, String>> {
        val result = mutableListOf<Pair<Int, String>>()
        val sb = StringBuilder()
        var start = 0
        for (i in bytes.indices) {
            val c = bytes[i].toInt() and 0xFF
            if (c in 32..126) {
                if (sb.isEmpty()) start = i
                sb.append(c.toChar())
            } else {
                if (sb.length >= minLen) result.add(start to sb.toString())
                sb.clear()
            }
        }
        if (sb.length >= minLen) result.add(start to sb.toString())
        return result
    }

    private fun extractAsciiStrings(bytes: ByteArray, minLen: Int = 6): List<String> =
        extractAsciiStringsWithOffsets(bytes, minLen).map { it.second }

    /**
     * Scans backward from [offset] in [bytes] looking for a DEX class descriptor
     * of the form `Lcom/example/ClassName;`.  Returns the descriptor string, or ""
     * if none found within 4 KB.
     */
    private fun findNearestDexClass(bytes: ByteArray, offset: Int): String {
        val lookback = minOf(4096, offset)
        var i = offset - 1
        while (i >= offset - lookback && i >= 0) {
            if ((bytes[i].toInt() and 0xFF) == 'L'.code) {
                val sb = StringBuilder("L")
                var j = i + 1
                var valid = true
                while (j < bytes.size && j < i + 300) {
                    val c = bytes[j].toInt() and 0xFF
                    when {
                        c == ';'.code -> { sb.append(';'); break }
                        c in ('A'.code..'Z'.code) || c in ('a'.code..'z'.code) ||
                        c == '/'.code || c == '_'.code || c == '$'.code ||
                        c in ('0'.code..'9'.code) -> sb.append(c.toChar())
                        else -> { valid = false; break }
                    }
                    j++
                }
                val candidate = sb.toString()
                if (valid && candidate.length > 8 && candidate.endsWith(";") && candidate.contains("/"))
                    return candidate
            }
            i--
        }
        return ""
    }

    private fun extractStringsFromBinaryXml(bytes: ByteArray): List<String> {
        val result = mutableListOf<String>()
        var i = 0
        // UTF-16LE scan (Android binary XML uses UTF-16LE string pool)
        while (i < bytes.size - 1) {
            val b1 = bytes[i].toInt() and 0xFF
            val b2 = bytes[i + 1].toInt() and 0xFF
            if (b1 in 32..126 && b2 == 0) {
                val sb = StringBuilder()
                while (i < bytes.size - 1) {
                    val c1 = bytes[i].toInt() and 0xFF
                    val c2 = bytes[i + 1].toInt() and 0xFF
                    if (c1 == 0 && c2 == 0) { i += 2; break }
                    if (c1 in 32..126 && c2 == 0) { sb.append(c1.toChar()); i += 2 }
                    else { i++; break }
                }
                if (sb.length >= 4) result.add(sb.toString())
            } else i++
        }
        result.addAll(extractAsciiStrings(bytes, 4))
        return result.distinct()
    }

    // ----------------------------------------------------------------
    // Manifest security checks — verbose attribute evidence
    // ----------------------------------------------------------------

    private fun checkManifestSecurity(strings: List<String>, bytes: ByteArray, findings: MutableList<ApkFinding>) {
        val allText = strings.joinToString(" ")

        /** Builds verbose evidence for a binary-XML attribute finding. */
        fun attrEvidence(attrKeyword: String, value: String): String {
            // Find the string(s) in the pool that contain the attribute keyword
            val matchIndices = strings.mapIndexedNotNull { idx, s ->
                if (s.contains(attrKeyword, ignoreCase = true)) idx else null
            }
            val poolCtx = matchIndices.flatMap { idx ->
                val from = maxOf(0, idx - 2)
                val to   = minOf(strings.size - 1, idx + 3)
                strings.subList(from, to + 1).mapIndexed { i, s -> "[${from + i}] \"$s\"" }
            }.distinct().joinToString("  ")

            // Byte offset of the UTF-16LE encoded keyword in the binary XML
            val keyword16 = attrKeyword.map { it.code.toByte() }.toByteArray()
            var byteOff = -1
            outer@ for (k in 0..bytes.size - keyword16.size * 2) {
                var ok = true
                for (j in keyword16.indices) {
                    if ((bytes[k + j * 2].toInt() and 0xFF) != keyword16[j].toInt() and 0xFF) { ok = false; break }
                }
                if (ok) { byteOff = k; break@outer }
            }

            return buildString {
                appendLine("Attribute         : $attrKeyword = \"$value\"")
                appendLine("Source            : AndroidManifest.xml (binary XML / AXML format)")
                if (byteOff >= 0)
                    appendLine("Byte offset       : $byteOff (0x${byteOff.toString(16).uppercase()}) in binary XML blob")
                appendLine("String pool match : ${matchIndices.firstOrNull()?.let { "pool index $it" } ?: "not found as UTF-16LE token"}")
                if (poolCtx.isNotEmpty())
                    append("Nearby pool items : $poolCtx")
            }.trimEnd()
        }

        if (allText.contains("android:debuggable") && allText.contains("true")) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "configuration",
                title       = "Debuggable Flag Enabled (android:debuggable=\"true\")",
                description = "The application has android:debuggable set to true in AndroidManifest.xml. This flag allows any process on the device to attach a JDWP debugger to the app, inspect runtime memory, dump Dalvik heap, and extract secrets at runtime without root.",
                evidence    = attrEvidence("debuggable", "true"),
                mitigation  = "Remove android:debuggable from the <application> tag in the release manifest. Verify the build pipeline does not re-inject it. Check: `aapt dump badging release.apk | grep -i debug`.",
                masvsRef    = "MASVS-RESILIENCE-2",
                cweRef      = "CWE-489",
                cvssScore   = 7.5,
            ))
        }

        if (allText.contains("android:allowBackup") && allText.contains("true")) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.MEDIUM,
                category    = "configuration",
                title       = "ADB Backup Enabled (android:allowBackup=\"true\")",
                description = "android:allowBackup=true permits the application data directory to be extracted via `adb backup` without root access. An attacker with physical or ADB access can obtain session tokens, cached credentials, and local databases.",
                evidence    = attrEvidence("allowBackup", "true"),
                mitigation  = "Set android:allowBackup=\"false\". On API 31+ also set android:dataExtractionRules pointing to a rules file that explicitly excludes sensitive SharedPreferences and databases.",
                masvsRef    = "MASVS-STORAGE-1",
                cweRef      = "CWE-312",
                cvssScore   = 5.5,
            ))
        }

        if (!allText.contains("android:networkSecurityConfig")) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.MEDIUM,
                category    = "network",
                title       = "No Network Security Config Defined",
                description = "The application does not reference a network_security_config.xml. Without this file, the app trusts all user-installed CA certificates (common on test/jailbroken devices), enabling trivial MITM interception via Burp Suite or mitmproxy.",
                evidence    = buildString {
                    appendLine("Attribute         : android:networkSecurityConfig")
                    appendLine("Result            : NOT PRESENT in <application> tag")
                    appendLine("Source            : AndroidManifest.xml (binary XML)")
                    append("Impact            : App trusts user CAs → Burp Suite MITM requires zero extra setup on rooted device")
                }.trimEnd(),
                mitigation  = "Create res/xml/network_security_config.xml with cleartextTrafficPermitted=\"false\" and certificate pins for all production API domains. Reference it via android:networkSecurityConfig in <application>.",
                masvsRef    = "MASVS-NETWORK-1",
                cweRef      = "CWE-295",
                cvssScore   = 6.5,
            ))
        }

        if (allText.contains("android:usesCleartextTraffic") && allText.contains("true")) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "network",
                title       = "Cleartext HTTP Traffic Explicitly Allowed",
                description = "android:usesCleartextTraffic=true permits the application to open unencrypted HTTP connections. All data sent over HTTP is readable and modifiable by any network observer (coffee-shop MITM, ISP, malicious hotspot).",
                evidence    = attrEvidence("usesCleartextTraffic", "true"),
                mitigation  = "Set android:usesCleartextTraffic=\"false\" and migrate all API endpoints to HTTPS. Use a network_security_config.xml with cleartextTrafficPermitted=\"false\" globally.",
                masvsRef    = "MASVS-NETWORK-1",
                cweRef      = "CWE-319",
                cvssScore   = 7.0,
            ))
        }

        if (allText.contains("android:exported=\"true\"")) {
            // Find which components are exported
            val exportedComponents = strings.filter { s ->
                s.contains("exported") || (s.contains("Activity") && strings.contains("true")) ||
                (s.contains("Service") && strings.contains("true"))
            }.take(8)
            val componentCtx = exportedComponents.joinToString(", ") { "\"$it\"" }
            findings.add(ApkFinding(
                severity    = FindingSeverity.MEDIUM,
                category    = "configuration",
                title       = "Exported Components Detected",
                description = "One or more Activities, Services, or BroadcastReceivers are exported (android:exported=true). Exported components can be started by any app on the device without authentication, potentially allowing unauthorized access to functionality or data.",
                evidence    = buildString {
                    appendLine("Attribute         : android:exported = \"true\"")
                    appendLine("Source            : AndroidManifest.xml")
                    append("Nearby pool items : $componentCtx")
                }.trimEnd(),
                mitigation  = "Audit all exported components. Add android:permission=\"com.yourapp.PERMISSION\" to restrict callers. Remove android:exported=true from components that do not require external invocation.",
                masvsRef    = "MASVS-PLATFORM-1",
                cweRef      = "CWE-926",
                cvssScore   = 5.3,
            ))
        }
    }

    // ----------------------------------------------------------------
    // Other security checks
    // ----------------------------------------------------------------

    private fun checkPermissions(permissions: List<String>, findings: MutableList<ApkFinding>) {
        val dangerous = permissions.filter { perm ->
            DANGEROUS_PERMISSIONS_LIST.any { d -> perm.contains(d) }
        }
        if (dangerous.isNotEmpty()) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.MEDIUM,
                category    = "permissions",
                title       = "Dangerous Permissions Declared (${dangerous.size} found)",
                description = "The app declares sensitive permissions that may not be required for core game functionality. Unnecessary permissions expand the attack surface and risk user data exposure.",
                evidence    = buildString {
                    appendLine("Total dangerous permissions : ${dangerous.size}")
                    dangerous.forEachIndexed { i, p -> appendLine("  [${i+1}] $p") }
                }.trimEnd(),
                mitigation  = "Remove permissions not required. Follow least-privilege. Document the business justification for each dangerous permission in the privacy policy.",
                masvsRef    = "MASVS-PLATFORM-1",
                cweRef      = "CWE-250",
                cvssScore   = 4.5,
            ))
        }
    }

    private fun checkNativeLibs(libs: List<String>, findings: MutableList<ApkFinding>) {
        if (libs.isEmpty()) return
        val interesting = libs.filter { lib ->
            lib.contains("hades") || lib.contains("game") || lib.contains("unity") ||
            lib.contains("il2cpp") || lib.contains("ssl") || lib.contains("crypto")
        }
        if (interesting.isNotEmpty()) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.INFO,
                category    = "native",
                title       = "Native Libraries with Embedded Crypto/SSL (${interesting.size} libs)",
                description = "The application includes native libraries that appear to implement TLS/SSL and cryptographic operations. These bypass the standard Android Java TLS stack and may implement custom certificate validation (or no validation).",
                evidence    = buildString {
                    appendLine("Matched native libs (${interesting.size}):")
                    interesting.forEachIndexed { i, l -> appendLine("  [${i+1}] $l") }
                    append("All native libs: ${libs.joinToString(", ")}")
                }.trimEnd(),
                mitigation  = "Audit native libraries for embedded OpenSSL/BoringSSL with disabled cert validation. Hook with Frida's openssl_observer.js to inspect TLS traffic in real time.",
                masvsRef    = "MASVS-NETWORK-2",
                cweRef      = "CWE-295",
                cvssScore   = 6.0,
            ))
        }
    }

    private fun checkSdkVersions(minSdk: Int, targetSdk: Int, findings: MutableList<ApkFinding>) {
        if (minSdk in 1..20) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "configuration",
                title       = "Very Low minSdkVersion ($minSdk) — Android ${sdkToVersion(minSdk)}",
                description = "App supports Android versions below 5.0 (API 21). These versions lack critical security features including full-disk encryption, improved TLS defaults, and security-enhanced SELinux policies.",
                evidence    = buildString {
                    appendLine("minSdkVersion  : $minSdk  (Android ${sdkToVersion(minSdk)})")
                    appendLine("targetSdkVersion: $targetSdk")
                    append("Risk            : Devices running API ≤$minSdk have unfixed kernel/framework CVEs")
                }.trimEnd(),
                mitigation  = "Raise minSdkVersion to at least 26 (Android 8.0). Older devices have known unfixed vulnerabilities and cannot benefit from modern platform security features.",
                masvsRef    = "MASVS-CODE-1",
                cvssScore   = 5.0,
            ))
        } else if (minSdk in 21..25) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.LOW,
                category    = "configuration",
                title       = "Low minSdkVersion ($minSdk) — Android ${sdkToVersion(minSdk)}",
                description = "App supports Android 5.x/6.x which have several known unfixed vulnerabilities.",
                evidence    = "minSdkVersion=$minSdk (Android ${sdkToVersion(minSdk)}), targetSdkVersion=$targetSdk",
                mitigation  = "Raise minSdkVersion to 28+ (Android 9.0) for stronger TLS defaults and other security improvements.",
                masvsRef    = "MASVS-CODE-1",
                cvssScore   = 3.0,
            ))
        }
    }

    private fun checkNetworkSecurity(urls: List<String>, findings: MutableList<ApkFinding>) {
        val httpUrls = urls.filter {
            it.startsWith("http://") && !it.startsWith("http://localhost") && !it.startsWith("http://127.")
        }.distinct()
        if (httpUrls.isNotEmpty()) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "network",
                title       = "Hardcoded Cleartext HTTP URLs (${httpUrls.size} found)",
                description = "Cleartext HTTP URLs were found hardcoded in the application DEX or assets. Traffic to these endpoints is not encrypted and is vulnerable to passive interception and active MITM tampering.",
                evidence    = buildString {
                    appendLine("Total HTTP URLs found: ${httpUrls.size}")
                    httpUrls.take(15).forEachIndexed { i, u -> appendLine("  [${i+1}] $u") }
                    if (httpUrls.size > 15) append("  ... and ${httpUrls.size - 15} more")
                }.trimEnd(),
                mitigation  = "Replace all http:// URLs with https://. Implement HSTS headers on the server. Add cleartext traffic blocking via network_security_config.xml.",
                masvsRef    = "MASVS-NETWORK-1",
                cweRef      = "CWE-319",
                cvssScore   = 7.0,
            ))
        }
    }

    private fun checkCleartextConfig(text: String, filename: String, findings: MutableList<ApkFinding>) {
        if (text.isBlank()) return
        val sensitiveKeywords = listOf("password", "api_key", "apikey", "secret", "token", "private_key",
            "access_key", "client_secret", "auth_key", "encryption_key")
        val lines = text.lines()
        val matchingLines = lines.mapIndexedNotNull { idx, line ->
            val lower = line.lowercase()
            val keyword = sensitiveKeywords.firstOrNull { lower.contains(it) } ?: return@mapIndexedNotNull null
            if (lower.contains("placeholder") || lower.contains("example") || lower.contains("your_") ||
                lower.contains("TODO") || lower.contains("fixme")) return@mapIndexedNotNull null
            Triple(idx + 1, keyword, line.trim())
        }
        if (matchingLines.isNotEmpty()) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "secrets",
                title       = "Potential Secrets in Config File: $filename",
                description = "Configuration file contains fields that appear to hold sensitive credentials or API keys. Asset files are trivially accessible by unzipping the APK.",
                evidence    = buildString {
                    appendLine("File              : $filename")
                    appendLine("Matching lines    : ${matchingLines.size}")
                    matchingLines.take(10).forEach { (lineNum, keyword, lineContent) ->
                        appendLine("  Line $lineNum [keyword: $keyword]:")
                        appendLine("    ${lineContent.take(200)}")
                    }
                    if (matchingLines.size > 10) append("  ... and ${matchingLines.size - 10} more lines")
                }.trimEnd(),
                mitigation  = "Remove all secrets from bundled config files. Fetch sensitive configuration from a secure endpoint at runtime with mutual TLS authentication.",
                masvsRef    = "MASVS-STORAGE-2",
                cweRef      = "CWE-312",
                cvssScore   = 7.5,
            ))
        }
    }

    private fun checkNetworkSecurityConfig(text: String, findings: MutableList<ApkFinding>) {
        if (text.contains("cleartextTrafficPermitted=\"true\"")) {
            val lineNum = text.lines().indexOfFirst { it.contains("cleartextTrafficPermitted") } + 1
            findings.add(ApkFinding(
                severity    = FindingSeverity.HIGH,
                category    = "network",
                title       = "Network Security Config Permits Cleartext Traffic",
                description = "network_security_config.xml explicitly allows cleartext (HTTP) traffic.",
                evidence    = buildString {
                    appendLine("File              : res/xml/network_security_config.xml")
                    appendLine("Line              : $lineNum")
                    appendLine("Trigger           : cleartextTrafficPermitted=\"true\"")
                    append("File preview      : ${text.take(400)}")
                }.trimEnd(),
                mitigation  = "Set cleartextTrafficPermitted=\"false\" globally. Restrict any debug-only exceptions to debug builds.",
                masvsRef    = "MASVS-NETWORK-1",
                cweRef      = "CWE-319",
                cvssScore   = 7.0,
            ))
        }
        if (!text.contains("<pin-set") && !text.contains("pin")) {
            findings.add(ApkFinding(
                severity    = FindingSeverity.MEDIUM,
                category    = "network",
                title       = "Certificate Pinning Not Configured in Network Security Config",
                description = "network_security_config.xml exists but does not define any certificate pins. Without pinning, any trusted CA can issue a fraudulent certificate for the app's domains, enabling MITM attacks.",
                evidence    = buildString {
                    appendLine("File              : res/xml/network_security_config.xml")
                    appendLine("Missing element   : <pin-set> / <pin digest=\"SHA-256\">")
                    append("File content      : ${text.take(300)}")
                }.trimEnd(),
                mitigation  = "Add <pin-set expiration=\"YYYY-MM-DD\"><pin digest=\"SHA-256\">base64hash</pin></pin-set> for all production domains. Include 2 backup pins and a rotation process.",
                masvsRef    = "MASVS-NETWORK-2",
                cweRef      = "CWE-295",
                cvssScore   = 6.5,
            ))
        }
    }

    // ----------------------------------------------------------------
    // Manifest parsing helpers
    // ----------------------------------------------------------------

    private fun extractPermissions(strings: List<String>): List<String> =
        strings.filter { it.startsWith("android.permission.") || it.startsWith("com.") }
               .filter { it.contains(".") && it.length < 120 }

    private fun extractPackageName(strings: List<String>): String =
        strings.firstOrNull { it.matches(Regex("com\\.[a-zA-Z0-9._]{3,60}")) } ?: ""

    private fun extractActivities(strings: List<String>): List<String> =
        strings.filter { it.contains("Activity") && it.startsWith("com.") }

    private fun extractServices(strings: List<String>): List<String> =
        strings.filter { it.contains("Service") && it.startsWith("com.") }

    private fun extractReceivers(strings: List<String>): List<String> =
        strings.filter { it.contains("Receiver") && it.startsWith("com.") }

    private fun extractProviders(strings: List<String>): List<String> =
        strings.filter { it.contains("Provider") && it.startsWith("com.") }

    private fun extractSdkVersion(strings: List<String>, key: String): Int {
        val idx = strings.indexOfFirst { it.contains(key) }
        if (idx >= 0 && idx + 1 < strings.size)
            return strings[idx + 1].toIntOrNull() ?: 0
        return strings.filter { it.matches(Regex("\\d{1,3}")) }
                       .mapNotNull { it.toIntOrNull() }
                       .filter { it in 1..40 }
                       .firstOrNull() ?: 0
    }

    private fun extractAppVersion(strings: List<String>): String =
        strings.firstOrNull { it.matches(Regex("\\d+\\.\\d+\\.\\d+(\\.\\d+)?")) } ?: ""

    private fun extractUrls(strings: List<String>): List<String> {
        val urlRe = Regex("""https?://[a-zA-Z0-9._/\-?=&%@:+#]+""")
        return strings.flatMap { urlRe.findAll(it).map { m -> m.value } }.distinct()
    }

    private fun sdkToVersion(sdk: Int): String = when (sdk) {
        in 1..4 -> "1.x"; 5 -> "2.0"; 6 -> "2.0.1"; 7 -> "2.1"; 8 -> "2.2"
        9, 10 -> "2.3"; in 11..13 -> "3.x"; 14, 15 -> "4.0"; in 16..18 -> "4.1–4.3"
        19, 20 -> "4.4"; 21, 22 -> "5.x"; 23 -> "6.0"; 24, 25 -> "7.x"
        26, 27 -> "8.x"; 28 -> "9.0"; 29 -> "10"; 30 -> "11"; 31, 32 -> "12"
        33 -> "13"; 34 -> "14"; 35 -> "15"; else -> "API $sdk"
    }

    // ----------------------------------------------------------------
    // URL references builder
    // ----------------------------------------------------------------

    private fun buildUrlRefs(urls: List<String>): List<UrlReference> {
        val urlRe = Regex("""(https?)://([a-zA-Z0-9._\-]+)(/[^\s]*)?""")
        val geoLocator = GeoLocator()
        return urls.mapNotNull { url ->
            val m = urlRe.find(url) ?: return@mapNotNull null
            val scheme = m.groupValues[1]
            val domain = m.groupValues[2].trimEnd('.')
            UrlReference(
                url = url,
                sources = emptyList(),   // source files not tracked at this level
                domain = domain,
                scheme = scheme,
                threatLabel = geoLocator.classifyDomain(domain),
            )
        }.distinctBy { it.url }
    }

    // ----------------------------------------------------------------
    // SDK / library detection from DEX strings
    // ----------------------------------------------------------------

    private fun detectLibraries(dexStrings: List<String>, nativeLibsInApk: List<String> = emptyList()): List<LibraryInfo> {
        val detected = mutableListOf<LibraryInfo>()
        val foundPrefixes = mutableSetOf<String>()
        val slashified = dexStrings.map { it.replace('.', '/') }   // DEX uses slash-separated class names

        // Also scan native lib names themselves for SDK hints
        val nativeLibBasenames = nativeLibsInApk.map { it.substringAfterLast('/') }

        for (sig in KNOWN_SDK_SIGNATURES) {
            if (foundPrefixes.contains(sig.prefix)) continue
            val slashPrefix = sig.prefix.replace('.', '/')
            val foundByDex = slashified.any { s -> s.contains(slashPrefix) } ||
                             dexStrings.any { s -> s.startsWith(sig.prefix) }
            val foundByNative = sig.nativeLibHints.isNotEmpty() &&
                                sig.nativeLibHints.any { hint -> nativeLibBasenames.any { it == hint } }
            if (foundByDex || foundByNative) {
                foundPrefixes.add(sig.prefix)
                // Match actual .so paths from the APK
                val foundSoFiles = if (sig.nativeLibHints.isNotEmpty()) {
                    nativeLibsInApk.filter { libPath ->
                        val basename = libPath.substringAfterLast('/')
                        sig.nativeLibHints.any { hint -> basename == hint }
                    }
                } else emptyList()

                detected.add(LibraryInfo(
                    packagePrefix  = sig.prefix,
                    displayName    = sig.name,
                    knownIssue     = sig.issue,
                    risk           = sig.risk,
                    details        = sig.details,
                    nativeLibHints = sig.nativeLibHints,
                    foundNativeLibs = foundSoFiles,
                ))
            }
        }

        // Also list all .so files that didn't match any known SDK as an "Unknown Native Library" entry
        val matchedSoFiles = detected.flatMap { it.foundNativeLibs }.toSet()
        val unmatchedSo = nativeLibsInApk.filter { path ->
            val basename = path.substringAfterLast('/')
            // Only flag .so files not claimed by any known SDK and not standard Android libs
            !matchedSoFiles.contains(path) &&
            !basename.startsWith("libandroid") &&
            !basename.startsWith("libc.so") &&
            !basename.startsWith("libm.so") &&
            !basename.startsWith("libz.so") &&
            !basename.startsWith("libc++") &&
            !basename.startsWith("liblog") &&
            !basename.startsWith("libGLES") &&
            !basename.startsWith("libEGL")
        }
        if (unmatchedSo.isNotEmpty()) {
            // Group by architecture to avoid duplicates
            val uniqueNames = unmatchedSo.map { it.substringAfterLast('/') }.distinct().sorted()
            detected.add(LibraryInfo(
                packagePrefix   = "(native)",
                displayName     = "Unidentified Native Libraries (${uniqueNames.size})",
                knownIssue      = "Unknown native code — reverse engineer with Ghidra/IDA for protocol analysis",
                risk            = "medium",
                details         = "These native libraries (.so files) were found in the APK but do not match any known SDK signature. " +
                    "Native code can implement custom network protocols, encryption, anti-debugging, or game logic. " +
                    "Use Frida to hook functions at runtime, or Ghidra/IDA Pro to disassemble statically.\n\n" +
                    "Files found:\n" + unmatchedSo.joinToString("\n") { "  $it" },
                nativeLibHints  = uniqueNames,
                foundNativeLibs = unmatchedSo,
            ))
        }

        return detected.sortedByDescending { riskOrder(it.risk) }
    }

    private fun riskOrder(risk: String) = when (risk) {
        "critical" -> 4; "high" -> 3; "medium" -> 2; "low" -> 1; else -> 0
    }

    // ----------------------------------------------------------------
    // Certificate parsing
    // ----------------------------------------------------------------

    private fun parseCertInfo(pkcs7Bytes: ByteArray, fileName: String): CertInfo? {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            val certs = cf.generateCertificates(pkcs7Bytes.inputStream()).toList()
            val cert = certs.firstOrNull() as? X509Certificate ?: return null

            val algo = cert.sigAlgName ?: "Unknown"
            val keySize = try {
                val pub = cert.publicKey
                val bits = when (pub.algorithm) {
                    "RSA"  -> (pub as? java.security.interfaces.RSAPublicKey)?.modulus?.bitLength()
                    "EC"   -> (pub as? java.security.interfaces.ECPublicKey)?.params?.curve?.field?.fieldSize
                    else   -> null
                }
                if (bits != null) "$bits-bit ${pub.algorithm}" else pub.algorithm
            } catch (_: Exception) { "Unknown" }

            val subjectStr = cert.subjectDN?.name ?: "Unknown"
            val isDebug = subjectStr.contains("Android Debug", ignoreCase = true) ||
                subjectStr.contains("debug", ignoreCase = true)

            val sha256 = try {
                val md = java.security.MessageDigest.getInstance("SHA-256")
                val digest = md.digest(cert.encoded)
                digest.joinToString(":") { "%02X".format(it) }
            } catch (_: Exception) { "" }

            val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", java.util.Locale.US)

            CertInfo(
                subject          = subjectStr,
                issuer           = cert.issuerDN?.name ?: "Unknown",
                notBefore        = try { fmt.format(cert.notBefore) } catch (_: Exception) { cert.notBefore.toString() },
                notAfter         = try { fmt.format(cert.notAfter)  } catch (_: Exception) { cert.notAfter.toString() },
                algorithm        = algo,
                keySize          = keySize,
                isDebugCert      = isDebug,
                sha256Fingerprint = sha256,
                rawText          = buildString {
                    appendLine("Source            : $fileName")
                    appendLine("Subject           : $subjectStr")
                    appendLine("Issuer            : ${cert.issuerDN?.name ?: "Unknown"}")
                    appendLine("Valid From        : ${try { fmt.format(cert.notBefore) } catch (_: Exception) { cert.notBefore.toString() }}")
                    appendLine("Valid Until       : ${try { fmt.format(cert.notAfter)  } catch (_: Exception) { cert.notAfter.toString() }}")
                    appendLine("Algorithm         : $algo")
                    appendLine("Key Size          : $keySize")
                    appendLine("Debug Certificate : $isDebug")
                    appendLine("SHA-256 Fingerprint:")
                    appendLine("  $sha256")
                }.trimEnd(),
            )
        } catch (_: Exception) { null }
    }

    // ----------------------------------------------------------------
    // Behavior profile builder
    // ----------------------------------------------------------------

    private fun buildBehaviorProfile(
        packageName: String,
        appVersion: String,
        minSdk: Int,
        targetSdk: Int,
        permissions: List<String>,
        activities: List<String>,
        services: List<String>,
        receivers: List<String>,
        providers: List<String>,
        nativeLibs: List<String>,
        libraries: List<LibraryInfo>,
        urls: List<String>,
        certInfo: CertInfo?,
    ): String = buildString {
        appendLine("=== APK Behavior Profile ===")
        appendLine()
        appendLine("Package    : $packageName")
        appendLine("Version    : ${appVersion.ifBlank { "unknown" }}")
        appendLine("Min SDK    : $minSdk (Android ${sdkToVersion(minSdk)})")
        appendLine("Target SDK : $targetSdk (Android ${sdkToVersion(targetSdk)})")
        appendLine()

        // Signing
        if (certInfo != null) {
            appendLine("── Signing Certificate ──────────────────")
            appendLine("  Subject   : ${certInfo.subject}")
            appendLine("  Algorithm : ${certInfo.algorithm}  Key: ${certInfo.keySize}")
            appendLine("  Valid     : ${certInfo.notBefore}  →  ${certInfo.notAfter}")
            if (certInfo.isDebugCert) appendLine("  ⚠  DEBUG CERTIFICATE — do not ship to production!")
            appendLine()
        }

        // Permissions summary
        appendLine("── Permissions (${permissions.size} total) ──────────────")
        val dangerous = permissions.filter { p -> DANGEROUS_PERMISSIONS_LIST.any { p.contains(it) } }
        if (dangerous.isNotEmpty()) {
            appendLine("  Dangerous (${dangerous.size}):")
            dangerous.take(20).forEach { appendLine("    • $it") }
        }
        val normal = permissions - dangerous.toSet()
        if (normal.isNotEmpty()) {
            appendLine("  Normal (${normal.size}):")
            normal.take(15).forEach { appendLine("    • $it") }
            if (normal.size > 15) appendLine("    … and ${normal.size - 15} more")
        }
        appendLine()

        // Components
        appendLine("── Android Components ──────────────────────")
        appendLine("  Activities : ${activities.size}")
        appendLine("  Services   : ${services.size}")
        appendLine("  Receivers  : ${receivers.size}")
        appendLine("  Providers  : ${providers.size}")
        if (services.isNotEmpty()) {
            appendLine("  Service list:")
            services.take(10).forEach { appendLine("    • $it") }
        }
        if (receivers.isNotEmpty()) {
            appendLine("  Receiver list:")
            receivers.take(10).forEach { appendLine("    • $it") }
        }
        appendLine()

        // Native
        if (nativeLibs.isNotEmpty()) {
            appendLine("── Native Libraries (${nativeLibs.size}) ──────────────────")
            nativeLibs.forEach { appendLine("  $it") }
            appendLine()
        }

        // Detected SDKs
        if (libraries.isNotEmpty()) {
            appendLine("── Detected SDKs / Libraries (${libraries.size}) ──────────")
            for (lib in libraries) {
                val risk = if (lib.risk != "none") "  ⚠ ${lib.risk.uppercase()}" else ""
                appendLine("  ${lib.displayName.padEnd(30)} ${lib.packagePrefix}$risk")
                if (lib.knownIssue.isNotBlank()) appendLine("    → ${lib.knownIssue}")
            }
            appendLine()
        }

        // Network summary
        val httpsUrls = urls.count { it.startsWith("https://") }
        val httpUrls  = urls.count { it.startsWith("http://")  && !it.startsWith("http://localhost") && !it.startsWith("http://127.") }
        appendLine("── Network Activity ─────────────────────────")
        appendLine("  Total embedded URLs : ${urls.size}  (HTTPS: $httpsUrls, HTTP: $httpUrls)")
        if (httpUrls > 0) appendLine("  ⚠  $httpUrls cleartext HTTP URL(s) found — MITM risk")
        val uniqueDomains = urls.mapNotNull { u ->
            try { Regex("""https?://([a-zA-Z0-9._\-]+)""").find(u)?.groupValues?.get(1) } catch (_: Exception) { null }
        }.distinct()
        appendLine("  Unique domains : ${uniqueDomains.size}")
        uniqueDomains.take(20).forEach { appendLine("    • $it") }
        if (uniqueDomains.size > 20) appendLine("    … and ${uniqueDomains.size - 20} more")

        // Behavioral flags
        appendLine()
        appendLine("── Behavioral Flags ─────────────────────────")
        val flags = mutableListOf<String>()
        if (permissions.any { it.contains("ACCESS_FINE_LOCATION") || it.contains("ACCESS_COARSE_LOCATION") })
            flags += "GPS / location tracking"
        if (permissions.any { it.contains("CAMERA") })
            flags += "Camera access"
        if (permissions.any { it.contains("RECORD_AUDIO") })
            flags += "Microphone access"
        if (permissions.any { it.contains("READ_CONTACTS") || it.contains("WRITE_CONTACTS") })
            flags += "Contacts access"
        if (permissions.any { it.contains("READ_EXTERNAL_STORAGE") || it.contains("WRITE_EXTERNAL_STORAGE") || it.contains("MANAGE_EXTERNAL_STORAGE") })
            flags += "External storage access"
        if (permissions.any { it.contains("READ_PHONE_STATE") })
            flags += "Device identifiers (READ_PHONE_STATE)"
        if (nativeLibs.any { it.contains("ssl") || it.contains("crypto") || it.contains("il2cpp") })
            flags += "Custom native TLS/crypto — may bypass standard certificate validation"
        if (libraries.any { it.risk == "critical" })
            flags += "High-risk SDKs detected (see SDK list above)"
        if (httpUrls > 0)
            flags += "Cleartext HTTP endpoints embedded"
        if (flags.isEmpty()) flags += "No notable behavioral flags"
        flags.forEach { appendLine("  • $it") }
    }.trimEnd()

    // ----------------------------------------------------------------
    // Constants
    // ----------------------------------------------------------------

    private val DANGEROUS_PERMISSIONS_LIST = listOf(
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "READ_CONTACTS", "WRITE_CONTACTS",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE", "READ_CALL_LOG",
        "CAMERA", "RECORD_AUDIO",
        "SEND_SMS", "RECEIVE_SMS",
        "READ_SMS", "RECEIVE_MMS",
        "PROCESS_OUTGOING_CALLS",
        "ACCESS_BACKGROUND_LOCATION",
        "MANAGE_EXTERNAL_STORAGE",
    )

    private data class SdkSignature(
        val prefix: String,
        val name: String,
        val issue: String,
        val risk: String,
        val details: String = "",
        val nativeLibHints: List<String> = emptyList(),
    )

    /** Known SDK package prefixes mapped to display name, known issue, risk level, and verbose details. */
    private val KNOWN_SDK_SIGNATURES: List<SdkSignature> = listOf(

        // ── Chinese data entities ─────────────────────────────────────────────
        SdkSignature(
            prefix = "com.bytedance",
            name   = "ByteDance SDK",
            issue  = "Chinese data entity — potential device data exfiltration",
            risk   = "critical",
            details = """ByteDance is the parent company of TikTok and Toutiao. Its SDKs embed deep device telemetry
collection routines including hardware identifiers (IMEI, serial), installed app lists, clipboard monitoring,
and precise location data. The SDK has been shown to use obfuscated native code (libmsaoaidsec.so) to resist
reverse engineering and to transmit data to servers in mainland China (bytedance.com, snssdk.com).
In 2023 the FTC confirmed TikTok/ByteDance collected US user data and routed it to China-based employees.
GDPR enforcement actions have been filed in multiple EU countries. This SDK's presence in a non-ByteDance app
is a high-severity finding that should be disclosed to the client immediately.""",
            nativeLibHints = listOf("libmsaoaidsec.so", "libpnsdk.so", "libeffect.so"),
        ),

        SdkSignature(
            prefix = "com.ss.android",
            name   = "TikTok/ByteDance (SS)",
            issue  = "Chinese data entity — same telemetry risk as ByteDance",
            risk   = "critical",
            details = """The com.ss.android namespace is ByteDance's legacy TikTok/TopBuzz package space.
Functions identically to com.bytedance in terms of data collection and exfiltration risk.
Frequently seen embedded inside third-party SDKs that have licensing agreements with ByteDance.""",
            nativeLibHints = listOf("libmsaoaidsec.so"),
        ),

        SdkSignature(
            prefix = "com.tiktok",
            name   = "TikTok SDK",
            issue  = "Chinese data entity — ByteDance TikTok tracking",
            risk   = "critical",
            details = """Direct TikTok SDK inclusion. Collects device fingerprint, behavioural analytics, and
content preferences. Sends data to servers controlled by ByteDance. TikTok has been banned from
government devices in the US, UK, EU, Canada, and Australia due to data sovereignty concerns.
Presence in a third-party app (not TikTok itself) suggests a partnership/distribution agreement with ByteDance.""",
            nativeLibHints = listOf("libmsaoaidsec.so"),
        ),

        SdkSignature(
            prefix = "com.tencent",
            name   = "Tencent SDK",
            issue  = "Chinese data entity — WeChat/QQ telemetry",
            risk   = "critical",
            details = """Tencent is the parent company of WeChat, QQ, and PUBG Mobile. Its Android SDKs (Bugly,
TPNS push, TBS WebView, MMKV) may collect device IDs, network state, and usage data sent to Tencent's
servers. Tencent operates under Chinese intelligence laws (NSL 2017) requiring cooperation with state
security agencies. Bugly (crash reporting) is widely embedded and still routes crash data through Tencent infrastructure.
MMKV, while open-source, originates from Tencent and its data storage format may be audited by Tencent.
Key native libraries to examine: libBugly.so, libqmsp.so.""",
            nativeLibHints = listOf("libBugly.so", "libqmsp.so", "libtpns.so"),
        ),

        SdkSignature(
            prefix = "com.alibaba",
            name   = "Alibaba SDK",
            issue  = "Chinese data entity — Alibaba/Taobao analytics",
            risk   = "high",
            details = """Alibaba SDKs (UT Analytics, UTdid device ID, Alibaba Push, AliOS) collect device
fingerprints and commerce behaviour. UTdid generates a persistent device identifier tied to Alibaba's
infrastructure. Data is routed through Aliyun (Alibaba Cloud) servers, subject to Chinese data regulations.""",
            nativeLibHints = listOf("libsgmainso.so", "libsgsecuritybody.so"),
        ),

        SdkSignature(
            prefix = "com.aliyun",
            name   = "Aliyun / Alibaba Cloud",
            issue  = "Chinese data entity — Alibaba Cloud infrastructure",
            risk   = "high",
            details = """Aliyun is Alibaba's cloud computing arm. Its presence in an APK can mean the app uses
Alibaba's push notification service, OSS storage SDK, or security SDK (EMAS). All data transits through
Alibaba-controlled infrastructure in China. The Alibaba EMAS Mobile Security SDK (libsgmainso.so) includes
anti-tampering and device fingerprinting features that exfiltrate hardware identifiers.""",
            nativeLibHints = listOf("libsgmainso.so", "libsgsecuritybody.so"),
        ),

        // ── Mobile Attribution ────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.appsflyer",
            name   = "AppsFlyer Attribution",
            issue  = "Cross-app device fingerprinting and install attribution",
            risk   = "high",
            details = """AppsFlyer is the world's largest mobile attribution platform. It assigns a unique
device identifier (AppsFlyer ID + GAID/IDFA) and tracks install sources, in-app events, revenue, and
lifetime value across all apps using the SDK. This creates a cross-app profile of the user's device activity.
AppsFlyer transmits data to servers in the US and Israel (appsflyer.com). The SDK collects: GAID, install
referrer, first launch timestamp, in-app purchase events, and custom funnels defined by the publisher.
From a MASVS-PRIVACY-1 perspective this must be disclosed in the app's privacy policy.""",
            nativeLibHints = listOf("libappsflyersdk.so"),
        ),

        SdkSignature(
            prefix = "io.branch",
            name   = "Branch.io Attribution",
            issue  = "Cross-app deep-link attribution and device graph",
            risk   = "high",
            details = """Branch provides deep-link routing and attribution. Its device graph correlates installs
across devices using probabilistic fingerprinting (IP + UA + screen size). Branch collects GAID, IP address,
user-agent, referrer metadata, and custom conversion events. Data is sent to api2.branch.io and stored in the US.
The device graph aspect means Branch can attribute activity across apps and sessions even without GAID consent.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.kochava",
            name   = "Kochava Attribution",
            issue  = "Device fingerprinting and attribution — FTC enforcement history",
            risk   = "high",
            details = """Kochava is a mobile attribution platform. In 2022 the FTC sued Kochava for selling
precise geolocation data that could be used to track individuals to sensitive locations (healthcare providers,
places of worship, domestic violence shelters). The FTC alleged Kochava's data broker marketplace sold data
without adequate user consent. The SDK collects GAID, IP, install referrer, and location. Presence of this
SDK is a significant privacy risk finding.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.adjust",
            name   = "Adjust Attribution",
            issue  = "Cross-app attribution and behavioural analytics",
            risk   = "medium",
            details = """Adjust is a mobile measurement company (acquired by AppLovin in 2021). Collects install
referrers, GAID, and in-app event data for conversion tracking. Data is sent to app.adjust.com (US/EU).
Lower risk than AppsFlyer/Kochava as Adjust has stronger GDPR consent flows, but still performs cross-app
device fingerprinting. AppLovin ownership means attribution data may feed into AppLovin's ad targeting.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.singular.sdk",
            name   = "Singular Attribution",
            issue  = "Attribution analytics with ad-spend aggregation",
            risk   = "medium",
            details = """Singular unifies mobile attribution with marketing cost data (ROI analytics). Collects
GAID, install referrer, in-app events, and revenue. Smaller than AppsFlyer/Adjust. Data sent to api.singular.net (US).
Standard attribution SDK risk profile — cross-app GAID tracking, event collection.""",
            nativeLibHints = listOf(),
        ),

        // ── Behavioral Analytics ──────────────────────────────────────────────
        SdkSignature(
            prefix = "com.amplitude",
            name   = "Amplitude Analytics",
            issue  = "Behavioural event analytics — user journey recording",
            risk   = "medium",
            details = """Amplitude is a product analytics platform. It records every user action (taps, screens
visited, feature usage) along with device metadata and sends structured event streams to api.amplitude.com (US).
Amplitude can capture PII if developers log it as event properties (e.g. userID, email). The SDK supports
identity resolution across sessions. Privacy risk depends on what events the developer logs — the SDK itself
does not impose limits on property values.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.mixpanel",
            name   = "Mixpanel Analytics",
            issue  = "Behavioural event analytics",
            risk   = "medium",
            details = """Mixpanel is a user analytics platform with funnel, retention, and cohort analysis.
Collects user events, distinct IDs, and super properties (persistent key-value pairs set by the developer).
Events are sent to api.mixpanel.com (US). Similar PII-in-properties risk as Amplitude.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.mparticle",
            name   = "mParticle Analytics",
            issue  = "Multi-channel analytics data broker and routing platform",
            risk   = "medium",
            details = """mParticle is a Customer Data Platform (CDP) that acts as a routing hub — it collects
user event data and forwards it to dozens of other analytics/attribution/ad platforms (Amplitude, Adjust,
AppsFlyer, etc.). A single mParticle integration can implicitly enable multiple downstream data processors.
Collecting device ID, events, and user attributes; data sent to nativesdks.mparticle.com (US).""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.segment",
            name   = "Segment Analytics",
            issue  = "CDP data router — forwards to multiple downstream processors",
            risk   = "medium",
            details = """Segment (Twilio) is another CDP/analytics router. Like mParticle it acts as a middle
layer that collects events and routes them to connected destinations (e.g. Amplitude, Mixpanel, Salesforce,
Facebook). The risk is the breadth of downstream data sharing. Data sent to api.segment.io / api.segment.com (US).""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.fullstory",
            name   = "FullStory Session Replay",
            issue  = "Full session recording — captures all UI interactions including sensitive screens",
            risk   = "high",
            details = """FullStory records complete user sessions: every tap, scroll, and screen transition is
replayed server-side. This is among the highest-risk analytics SDKs from a privacy perspective because it
may capture screens containing passwords, payment details, health information, or other PII even if the
developer intended to exclude them. FullStory provides masking APIs but misconfiguration is common.
GDPR/CCPA require explicit consent for session recording. Data is sent to fullstory.com (US).""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.heap",
            name   = "Heap Analytics",
            issue  = "Retroactive behavioural analytics — auto-captures all events",
            risk   = "medium",
            details = """Heap's differentiator is autocapture: it automatically records every interaction
without requiring manual event instrumentation. This means sensitive interactions may be captured
unintentionally. Data is sent to heapanalytics.com (US). Privacy risk is higher than instrumented SDKs
because developers may not realise what data is being collected.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.clevertap",
            name   = "CleverTap Analytics",
            issue  = "Marketing analytics, push, and in-app messaging — user profiling",
            risk   = "medium",
            details = """CleverTap is a marketing automation platform. It records user events, builds segments,
and triggers push notifications and in-app messages based on behaviour. Collects device ID, events, and
allows user identity resolution. Based in India; data stored in US/EU/India depending on configuration.
Focus on marketing automation means profiles are built specifically for re-engagement targeting.""",
            nativeLibHints = listOf(),
        ),

        // ── Advertising ───────────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.google.android.gms.ads",
            name   = "Google Mobile Ads (AdMob)",
            issue  = "Ad delivery and user profiling via Google's ad network",
            risk   = "medium",
            details = """Google AdMob delivers targeted advertisements using Google's advertising ID (GAID).
It collects GAID, app activity, device metadata, and inferred interests to build ad profiles. Data flows
to Google's ad infrastructure. Since Google is a first-party in many ecosystems this is lower severity
than third-party ad networks, but it still contributes to cross-app user profiling. COPPA restrictions
apply if the app has a children's audience.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.facebook.ads",
            name   = "Facebook Audience Network",
            issue  = "Facebook ad network — cross-app user profiling using Facebook identity graph",
            risk   = "high",
            details = """Facebook Audience Network (FAN) serves ads in third-party apps using Facebook's
identity graph. Even if the user has no Facebook account, Meta correlates device activity via GAID and
email hashes against its shadow profiles. In 2019 a researcher found FAN transmitted device data before
any user interaction. Meta has been fined €1.2B (Ireland DPC) and faces ongoing GDPR enforcement.
This SDK links app behaviour to Facebook profiles, enabling cross-context surveillance.""",
            nativeLibHints = listOf("libfbads.so"),
        ),

        SdkSignature(
            prefix = "com.ironsource",
            name   = "ironSource Ads",
            issue  = "Ad mediation layer — delegates to multiple ad networks",
            risk   = "medium",
            details = """ironSource (now Unity) is an ad mediation platform that wraps multiple ad networks
(AdMob, AppLovin, Unity, Facebook) in a single SDK. Each network adapter it loads can independently
collect GAID and device data. The mediation layer itself collects app usage for performance reporting.
Post-merger with Unity, data may feed into Unity's game developer and advertiser ecosystem.""",
            nativeLibHints = listOf("libironSource.so"),
        ),

        SdkSignature(
            prefix = "com.applovin",
            name   = "AppLovin MAX Ads",
            issue  = "Ad network and mediation — device fingerprinting",
            risk   = "medium",
            details = """AppLovin MAX is an ad mediation and network platform. It collects GAID, device model,
OS version, and bidding signals. AppLovin also owns Adjust (attribution), giving it unusual breadth:
it can correlate ad impressions to installs to in-app behaviour across its entire network. Data sent
to US-based AppLovin servers. AppLovin's programmatic bidding exposes bid request data to hundreds of
DSPs, each of which may log device identifiers.""",
            nativeLibHints = listOf("libnative_sdk.so"),
        ),

        SdkSignature(
            prefix = "com.unity3d.ads",
            name   = "Unity Ads",
            issue  = "In-game ad network",
            risk   = "low",
            details = """Unity Ads is Unity's advertising SDK for games. Collects GAID, device metrics, and
game session data for ad targeting. Risk is lower than pure ad networks because Unity's primary business
is the game engine; ad data collection is ancillary. Data sent to unityads.unity3d.com (US).""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.adcolony",
            name   = "AdColony Ads",
            issue  = "Video ad network",
            risk   = "low",
            details = """AdColony (now Digital Turbine) serves video ads in mobile games. Collects standard
ad-network signals: GAID, app metadata, device characteristics. Relatively standard risk profile.
Data sent to adcolony.com (US).""",
            nativeLibHints = listOf(),
        ),

        // ── Crash & Performance Monitoring ────────────────────────────────────
        SdkSignature(
            prefix = "com.bugsnag",
            name   = "Bugsnag Crash Reporting",
            issue  = "",
            risk   = "low",
            details = """Bugsnag captures unhandled exceptions and ANR events with a stack trace, device
metadata (OS, device model, memory), and optionally user-defined breadcrumbs. Data is sent to
sessions.bugsnag.com (US/EU). PII risk is limited to any user context the developer explicitly attaches.
Requires review of what custom metadata is configured.""",
            nativeLibHints = listOf("libbugsnag-ndk.so"),
        ),

        SdkSignature(
            prefix = "io.sentry",
            name   = "Sentry Error Monitoring",
            issue  = "",
            risk   = "low",
            details = """Sentry is an open-source error monitoring platform with a cloud-hosted SaaS option.
Captures stack traces, breadcrumbs, request payloads, and device metadata on crash. Can optionally
capture HTTP request/response details which may include auth tokens or PII. Data sent to sentry.io or
self-hosted instance. Scrubbing rules should be reviewed to ensure tokens are redacted.""",
            nativeLibHints = listOf("libsentry.so", "libsentry-android.so"),
        ),

        SdkSignature(
            prefix = "com.crashlytics",
            name   = "Crashlytics (Firebase)",
            issue  = "",
            risk   = "low",
            details = """Crashlytics (now part of Firebase) captures crash reports with symbolicated stack
traces and device metadata. Integrated with Firebase Analytics for user journey context. Data is sent
to Firebase/Google infrastructure. Lower data collection surface than full analytics SDKs — focused
on crash events rather than behavioural tracking.""",
            nativeLibHints = listOf("libcrashlytics.so", "libcrashlytics-handler.so"),
        ),

        // ── Push / CRM ────────────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.onesignal",
            name   = "OneSignal Push",
            issue  = "",
            risk   = "low",
            details = """OneSignal is a push notification platform. Collects device push token, device
metadata, and notification interaction data (delivered, opened, clicked). Minimal PII unless the
developer passes user identity attributes. Data sent to onesignal.com (US).""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "com.braze",
            name   = "Braze CRM",
            issue  = "Behavioural marketing CRM — user profiling for retention/re-engagement",
            risk   = "medium",
            details = """Braze is an enterprise marketing automation platform. It maintains per-user profiles
combining: custom attributes (set by developer), purchase events, in-app behaviour, location history,
push/email engagement, and device metadata. Braze enables fine-grained audience segmentation and
personalised campaigns. The breadth of the user profile makes this a higher-sensitivity analytics SDK.
Data sent to sdk.iad-XX.braze.com (US). Formerly known as Appboy.""",
            nativeLibHints = listOf(),
        ),

        // ── Google / Firebase ─────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.google.firebase",
            name   = "Firebase (Google)",
            issue  = "",
            risk   = "low",
            details = """Firebase is Google's mobile backend platform (Analytics, Crashlytics, Remote Config,
Cloud Messaging, Auth, Firestore). Firebase Analytics automatically collects ~50 predefined events and
device properties. Remote Config can change app behaviour server-side without an update. Auth supports
Google/Facebook SSO. Data flows to Google's infrastructure. Risk level depends on which Firebase services
are used — Analytics and Remote Config increase data collection surface.""",
            nativeLibHints = listOf(),
        ),

        // ── Social / Identity ─────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.facebook.core",
            name   = "Facebook Core SDK",
            issue  = "Facebook cross-app identity tracking and user graph",
            risk   = "medium",
            details = """The Facebook Core SDK is the base layer for all Meta SDKs. It automatically logs app
events (AppEvents) including app installs, launches, and custom events. It also performs App Indexing
to allow Facebook to understand app content. The SDK correlates the device's GAID with Facebook account
data to build cross-app identity links even without Facebook Login being used. Data sent to graph.facebook.com.""",
            nativeLibHints = listOf("libfb.so"),
        ),

        SdkSignature(
            prefix = "com.facebook.login",
            name   = "Facebook Login SDK",
            issue  = "Facebook SSO — identity linkage between Facebook account and app account",
            risk   = "medium",
            details = """Facebook Login enables single sign-on using a Facebook account. When used, Meta receives
the login event and can correlate the user's app activity with their Facebook profile. The SDK requests
Facebook profile permissions and may allow Meta to see which apps the user logs into. GDPR/CCPA require
explicit disclosure. Data sent to graph.facebook.com.""",
            nativeLibHints = listOf("libfb.so"),
        ),

        // ── Game Engines ──────────────────────────────────────────────────────
        SdkSignature(
            prefix = "com.unity3d.player",
            name   = "Unity Engine",
            issue  = "",
            risk   = "none",
            details = """The Unity game engine runtime. Presence indicates the app is built with Unity.
No inherent privacy risk from the engine itself, but the game likely includes Unity Ads, Unity Analytics,
or third-party SDKs integrated via the Unity Asset Store. Check for com.unity3d.ads and other Unity
sub-packages for the actual risk surface.""",
            nativeLibHints = listOf("libunity.so", "libil2cpp.so"),
        ),

        SdkSignature(
            prefix = "cocos2d",
            name   = "Cocos2d Engine",
            issue  = "",
            risk   = "none",
            details = """Cocos2d is an open-source game engine popular in Chinese mobile games. No inherent
privacy risk from the engine itself. Historically common in games with Chinese publisher involvement,
which may co-occur with ByteDance/Tencent SDK inclusions.""",
            nativeLibHints = listOf("libcocos2dcpp.so"),
        ),

        // ── Network Libraries (informational) ────────────────────────────────
        SdkSignature(
            prefix = "okhttp3",
            name   = "OkHttp3",
            issue  = "",
            risk   = "none",
            details = """OkHttp3 is Square's open-source HTTP client for Android. No data collection.
Its presence is useful for dynamic analysis: OkHttp uses its own certificate pinning / TrustManager,
meaning standard SSLUnpinning hooks (TrustManager.checkServerTrusted) may bypass it, but
OkHttp-specific hooks (OkHttpClient, okhttp3.CertificatePinner) are more reliable for interception.""",
            nativeLibHints = listOf(),
        ),

        SdkSignature(
            prefix = "retrofit2",
            name   = "Retrofit2",
            issue  = "",
            risk   = "none",
            details = """Retrofit2 is Square's type-safe HTTP client wrapper around OkHttp3. No data
collection. Useful for understanding the API structure: Retrofit interfaces define API endpoints,
making them targets for static analysis to enumerate server endpoints.""",
            nativeLibHints = listOf(),
        ),
    )

    private val SECRET_PATTERNS = listOf(
        Regex("""(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})""")       to "API Key",
        Regex("""(?i)(secret|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{16,})""") to "Secret Key",
        Regex("""(?i)(password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})""")                to "Password",
        Regex("""(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{16,})""") to "Auth Token",
        Regex("""AIza[0-9A-Za-z\-_]{35}""")                                               to "Google API Key",
        Regex("""AAAA[A-Za-z0-9_\-]{50,}""")                                              to "Firebase Server Key",
        Regex("""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----""")                              to "Private Key (PEM)",
        Regex("""(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["']?AKIA[0-9A-Z]{16}""")   to "AWS Access Key",
        Regex("""(?i)(client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{16,})""")       to "OAuth Client Secret",
        Regex("""(?i)(bearer\s+)([A-Za-z0-9_\-\.]{20,})""")                               to "Bearer Token",
    )
}
