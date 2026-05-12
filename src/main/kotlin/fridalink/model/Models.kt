package fridalink.model

data class ReplEntry(
    val code: String,
    val result: String?,   // null when error
    val error: String?,    // null when success
    val timestamp: String,
)

data class TargetProcess(
    val pid: Int,
    val name: String,
    val platform: String,
    val state: String,
    val selected: Boolean = false,
    val attached: Boolean = false,
)

data class RuntimeEvent(
    val id: String = "",               // assigned by controller — used for bookmarking
    val timestamp: String,
    val process: String,
    val category: String,
    val module: String,
    val target: String,
    val summary: String,
    // Extended observability fields — populated by sidecar and Frida scripts
    val severity: String = "info",       // info | warn | error
    val threadId: String = "",
    val scriptSource: String = "",
    val correlationId: String = "",
    val args: String = "",
    val retval: String = "",
    val backtrace: String = "",          // native/Java call stack, if emitted by script
    val raw: String = "",
    val details: Map<String, String> = emptyMap(),
)

data class InterceptItem(
    val id: String,
    val timestamp: String,
    val process: String,
    val direction: String,
    val channel: String,
    val summary: String,
    val payload: String,
    val editable: Boolean = true,
)

data class CustomScript(
    val id: String,
    val name: String,
    val language: String = "javascript",
    val description: String = "",
    val content: String = "",
)

/**
 * A script discovered on disk by ScriptLibraryManager.
 * The [enabled] flag tracks whether it has been loaded into the active session.
 */
data class LibraryScript(
    val id: String,
    val name: String,
    val category: String = "general",
    val description: String = "",
    val version: String = "1.0",
    val path: String = "",
    val content: String = "",
    val enabled: Boolean = false,
)

/**
 * A single Match & Replace rule applied to OkHttp response bodies.
 */
data class MatchReplaceRule(
    val id: String,
    val enabled: Boolean = true,
    val urlPattern: String = "",    // empty = all URLs
    val matchText: String = "",
    val replaceText: String = "",
    val isRegex: Boolean = false,
    val comment: String = "",
)

data class SidecarConfig(
    val host: String = "127.0.0.1",
    val port: Int = 7766,
)

// ----------------------------------------------------------------
// Traffic analysis — captured from Burp proxy history
// ----------------------------------------------------------------
data class TrafficEntry(
    val id: String,
    val method: String,
    val host: String,
    val url: String,
    val path: String,
    val statusCode: Int,
    val mimeType: String,
    val requestLength: Int,
    val responseLength: Int,
    val params: List<String>,       // query + body param names
    val requestHeaders: String,     // full request headers block
    val requestBody: String,
    val responseHeaders: String,
    val responseBody: String,
    val notes: String = "",
    val timestamp: String = "",
    val ip: String = "",            // resolved server IP (populated by geo lookup)
)

// ----------------------------------------------------------------
// Geolocation result for a server IP
// ----------------------------------------------------------------
data class GeoResult(
    val ip: String,
    val country: String,
    val countryCode: String,        // ISO 3166-1 alpha-2 (US, JP, SG, ...)
    val city: String,
    val regionName: String,
    val lat: Double,
    val lon: Double,
    val org: String,
    val isp: String,
    val asn: String = "",           // AS number + name, e.g. "AS15169 Google LLC"
    val reverse: String = "",       // reverse DNS / PTR record
    val isProxy: Boolean = false,   // VPN / proxy / TOR exit node detected
    val isHosting: Boolean = false, // hosting / datacenter / cloud provider
    val timezone: String = "",      // IANA timezone, e.g. "America/Los_Angeles"
    val isUS: Boolean,
    val status: String,             // "success" | "fail:..." | "local"
    val threatLabel: String = "",   // e.g. "Tracker", "Analytics", "Data Broker (CN)"
    val host: String = "",          // original hostname that was resolved
)

// ----------------------------------------------------------------
// OWASP MASVS v2 checklist item
// ----------------------------------------------------------------
enum class MasvsStatus { NOT_TESTED, PASS, FAIL, NOT_APPLICABLE }

data class MasvsItem(
    val id: String,                  // e.g. "MASVS-NETWORK-1"
    val category: String,            // e.g. "MASVS-NETWORK"
    val control: String,             // short title
    val description: String,         // full description
    val testId: String,              // e.g. "MASTG-TEST-0021"
    val level: String,               // L1 | L2 | R
    var status: MasvsStatus = MasvsStatus.NOT_TESTED,
    var evidence: String = "",
    var notes: String = "",
)

// ----------------------------------------------------------------
// APK static analysis finding
// ----------------------------------------------------------------
enum class FindingSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }

data class ApkFinding(
    val severity: FindingSeverity,
    val category: String,            // e.g. "permissions", "network", "crypto"
    val title: String,
    val description: String,
    val evidence: String,            // e.g. the specific permission or string found
    val mitigation: String,
    val masvsRef: String = "",       // e.g. "MASVS-NETWORK-2"
    val cweRef: String = "",         // e.g. "CWE-295"
    val cvssScore: Double = 0.0,
    val isFalsePositive: Boolean = false,  // user-marked false positive — hidden in Findings tab
)

// ----------------------------------------------------------------
// Frida Trace configuration
// ----------------------------------------------------------------
data class FridaTracePattern(
    val id: String,
    val pattern: String,             // e.g. "SSL_*" or "-i getaddrinfo"
    val type: String,                // "include" | "exclude"
    val enabled: Boolean = true,
)

data class FridaTraceConfig(
    val targetPkg: String = "com.crunchyroll.bleachsoulres",
    val includePatterns: List<String> = listOf("SSL_*", "ikcp_*", "GameStart", "GameEnd"),
    val excludePatterns: List<String> = listOf("malloc", "free", "pthread_*"),
    val backtraceDepth: Int = 3,
    val useSpawn: Boolean = true,
)

data class FridaLinkState(
    val connected: Boolean = false,
    val mode: String = "idle",
    val processes: List<TargetProcess> = emptyList(),
    val events: List<RuntimeEvent> = emptyList(),
    val intercepts: List<InterceptItem> = emptyList(),
    val scripts: List<CustomScript> = emptyList(),
    val libraryScripts: List<LibraryScript> = emptyList(),
    val sidecarLogs: List<String> = emptyList(),
    val status: String = "Disconnected",
    val sessionStatus: String = "No FridaLink session",
    val selectedPid: Int? = null,
    val attachedPid: Int? = null,
    val selectedEventIndex: Int? = null,
    val selectedInterceptId: String? = null,
    val matchReplaceRules: List<MatchReplaceRule> = emptyList(),
    val bookmarkedIds: Set<String> = emptySet(),
    // ---- new feature state ----
    val trafficEntries: List<TrafficEntry> = emptyList(),
    val geoResults: Map<String, GeoResult> = emptyMap(),
    val masvsItems: List<MasvsItem> = emptyList(),
    val apkFindings: List<ApkFinding> = emptyList(),
    val fridaTraceOutput: List<String> = emptyList(),
    val tsharkCapturing: Boolean = false,
    val tsharkEntries: List<TrafficEntry> = emptyList(),
    val apkPath: String = "",
    val reportStatus: String = "",
    // ---- ADB device checks ----
    val adbAvailable: Boolean = false,
    val adbDevices: List<String> = emptyList(),
    val adbResults: Map<String, String> = emptyMap(),
    val adbStatus: String = "ADB not checked",
    val adbRawDisplay: String = "",         // formatted text of all raw ADB check results for display
    // ---- Decompiled source analysis ----
    val decompSrcPath: String = "",         // path to jadx-decompiled directory
    val decompSrcFindings: List<ApkFinding> = emptyList(), // findings from source code scan
    // ---- Deep APK analysis results ----
    val analysisUrlRefs: List<UrlReference> = emptyList(),
    val analysisLibraries: List<LibraryInfo> = emptyList(),
    val analysisCertInfo: CertInfo? = null,
    val analysisBehaviorProfile: String = "",
    // ---- Host environment ----
    val hostShellEnv: ShellEnv? = null,     // detected at startup: OS, Git Bash availability
    // ---- Frida REPL ----
    val replHistory: List<ReplEntry> = emptyList(),  // newest-first, capped at 500
)

// ----------------------------------------------------------------
// URL reference — URL + every file it appears in
// ----------------------------------------------------------------
data class UrlReference(
    val url: String,
    val sources: List<String>,      // filenames (dex, assets/…) where URL appears
    val domain: String,
    val scheme: String,             // "http" or "https"
    val threatLabel: String = "",   // from GeoLocator.classifyDomain
)

// ----------------------------------------------------------------
// Detected SDK/library inside the APK
// ----------------------------------------------------------------
data class LibraryInfo(
    val packagePrefix: String,      // e.g. "com.bytedance"
    val displayName: String,        // e.g. "ByteDance SDK"
    val version: String = "",       // version string if detectable
    val knownIssue: String = "",    // empty = no known issue
    val risk: String = "none",      // none / low / medium / high / critical
    val details: String = "",       // verbose description: what it does, privacy implications, known incidents
    val nativeLibHints: List<String> = emptyList(), // .so names known to belong to this SDK
    val foundNativeLibs: List<String> = emptyList(), // actual .so paths found in this APK (e.g. "lib/arm64-v8a/libmsaoaidsec.so")
)

// ----------------------------------------------------------------
// Host shell environment — detected at startup
// ----------------------------------------------------------------
data class ShellEnv(
    val isWindows: Boolean,
    val gitBashPath: String?,         // absolute path to bash.exe on Windows, or null
    val hasBash: Boolean,             // true if bash is available (natively on Linux/macOS or via Git Bash on Windows)
    val gitBashVersion: String = "",  // e.g. "5.2.37(1)-release"
)

// ----------------------------------------------------------------
// APK signing certificate details
// ----------------------------------------------------------------
data class CertInfo(
    val subject: String,
    val issuer: String,
    val notBefore: String,
    val notAfter: String,
    val algorithm: String,          // e.g. "SHA256withRSA"
    val keySize: String,            // e.g. "2048-bit RSA"
    val isDebugCert: Boolean,
    val sha256Fingerprint: String,
    val rawText: String,            // full keytool output
)
