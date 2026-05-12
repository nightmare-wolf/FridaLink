package fridalink.service

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import fridalink.model.CustomScript
import fridalink.model.FridaTraceConfig
import fridalink.model.FridaLinkState
import fridalink.model.InterceptItem
import fridalink.model.LibraryScript
import fridalink.model.MatchReplaceRule
import fridalink.model.MasvsStatus
import fridalink.model.RuntimeEvent
import fridalink.model.SidecarConfig
import fridalink.model.TargetProcess
import fridalink.model.TrafficEntry
import java.io.File
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import javax.swing.Timer
import javax.swing.SwingUtilities

class FridaLinkController(private val api: MontoyaApi) : TelemetryListener {
    private val mapper = jacksonObjectMapper()
    private val listeners = CopyOnWriteArrayList<(FridaLinkState) -> Unit>()
    private val stateLock = Any()
    private val sidecarProcessManager = SidecarProcessManager()
    private val scriptLibraryManager  = ScriptLibraryManager()
    private val exporter              = EventExporter()
    private val trafficAnalyzer       = BurpTrafficAnalyzer(api)
    private val geoLocator            = GeoLocator()
    private val fridaTraceRunner      = FridaTraceRunner()
    private val tsharkRunner          = TsharkRunner()
    private val apkAnalyzer           = ApkStaticAnalyzer()
    private val decompiledScanner     = DecompiledSourceScanner()
    private val reportGenerator       = ReportGenerator()
    private val adbRunner             = AdbRunner()
    private val eventCounter          = java.util.concurrent.atomic.AtomicLong(0)
    private var dirty = false
    private val publishTimer = Timer(200) { flushPublish() }

    private var state = FridaLinkState(
        scripts = listOf(
            CustomScript(
                id = "starter-trace",
                name = "Starter Trace Script",
                description = "Edit and run your own script against the sidecar target.",
                content = "// Frida JavaScript placeholder\nsend({ type: 'log', message: 'starter script loaded' });",
            )
        )
    )

    private val sidecarSource: TelemetrySource = SidecarTelemetrySource()
    private var activeSource: TelemetrySource = sidecarSource

    fun start() {
        sidecarSource.start(this)
        publishTimer.start()
        // Detect host environment asynchronously so startup is not blocked
        Thread {
            val env = adbRunner.detectShellEnv()
            SwingUtilities.invokeLater {
                updateState { copy(hostShellEnv = env) }
                appendSidecarLog(buildString {
                    append("Host OS: ${if (env.isWindows) "Windows" else "Linux/macOS"}")
                    if (env.isWindows) {
                        if (env.hasBash) {
                            append(" | Git Bash: FOUND at ${env.gitBashPath}")
                            if (env.gitBashVersion.isNotBlank()) append(" (${env.gitBashVersion.take(40)})")
                        } else {
                            append(" | Git Bash: NOT FOUND — host-side bash pipe commands unavailable")
                            append(" | Install Git for Windows from https://git-scm.com to enable host-side bash tools")
                        }
                    } else {
                        append(" | bash: available")
                    }
                })
            }
        }.also { it.isDaemon = true }.start()
        markDirty()
    }

    fun addListener(listener: (FridaLinkState) -> Unit) {
        listeners += listener
        listener(state)
    }

    fun connectSidecar(host: String, port: Int) {
        activeSource = sidecarSource
        updateState { copy(mode = "sidecar", status = "Connecting to sidecar...", sessionStatus = "Connecting to FridaLink sidecar") }
        sidecarSource.connect(SidecarConfig(host, port))
    }

    fun disconnectSidecar() {
        activeSource.disconnect()
        updateState { copy(connected = false, mode = "idle", status = "Disconnected", sessionStatus = "No FridaLink session") }
    }

    fun clearEvents() {
        updateState { copy(events = emptyList()) }
    }

    fun refreshProcesses() {
        activeSource.refreshProcesses()
    }

    fun selectProcess(pid: Int) {
        updateState { copy(selectedPid = pid, processes = processes.map { it.copy(selected = it.pid == pid) }) }
    }

    fun attachSelectedProcess() {
        val pid = state.selectedPid ?: return
        activeSource.attachProcess(pid)
        updateState { copy(status = "Attaching to pid $pid...", sessionStatus = "Attaching FridaLink session to pid $pid") }
    }

    fun detachCurrentProcess() {
        activeSource.detachProcess()
        updateState {
            copy(
                status = "Detaching current session...",
                sessionStatus = "Detaching FridaLink session",
                // Reset enabled state — scripts are unloaded with the session
                libraryScripts = libraryScripts.map { it.copy(enabled = false) },
            )
        }
    }

    fun spawnProcess(identifier: String) {
        if (identifier.isBlank()) return
        // Collect all currently-enabled library scripts so the sidecar can load
        // them into the paused session before the user clicks Resume.
        val enabledScripts = state.libraryScripts
            .filter { it.enabled }
            .map { CustomScript(id = it.id, name = it.name, language = "javascript", content = it.content) }
        activeSource.spawnProcess(identifier, enabledScripts)
        val count = enabledScripts.size
        updateState {
            copy(
                status = "Spawning $identifier with $count script(s) pre-loaded...",
                sessionStatus = "Process spawned (paused) — click Resume to start app",
            )
        }
    }

    fun resumeProcess() {
        activeSource.resumeProcess()
        updateState { copy(status = "Resuming process...", sessionStatus = "Process running") }
    }

    fun addMatchReplaceRule(rule: MatchReplaceRule) {
        updateState { copy(matchReplaceRules = matchReplaceRules + rule) }
    }

    fun updateMatchReplaceRule(rule: MatchReplaceRule) {
        updateState {
            copy(matchReplaceRules = matchReplaceRules.map { if (it.id == rule.id) rule else it })
        }
    }

    fun removeMatchReplaceRule(id: String) {
        updateState { copy(matchReplaceRules = matchReplaceRules.filterNot { it.id == id }) }
    }

    fun pushMatchReplaceRules() {
        activeSource.updateRules(state.matchReplaceRules)
    }

    fun callRpc(method: String, args: List<Any> = emptyList()) {
        activeSource.callRpc(method, args)
    }

    fun evalRepl(code: String) {
        activeSource.evalRepl(code)
    }

    fun toggleBookmark(id: String) {
        updateState {
            val next = if (id in bookmarkedIds) bookmarkedIds - id else bookmarkedIds + id
            copy(bookmarkedIds = next)
        }
    }

    fun configureExport(dir: java.io.File, baseName: String) {
        exporter.configure(dir, baseName)
        appendSidecarLog("Export started: ${exporter.statusLine()}")
    }

    fun stopExport() {
        exporter.stop()
        appendSidecarLog("Export stopped")
    }

    fun exportStatusLine(): String = exporter.statusLine()

    fun saveScript(id: String?, name: String, language: String, description: String, content: String) {
        val normalized = CustomScript(
            id = id ?: UUID.randomUUID().toString(),
            name = name.ifBlank { "Untitled Script" },
            language = language.ifBlank { "javascript" },
            description = description,
            content = content,
        )
        updateState {
            val others = scripts.filterNot { script -> script.id == normalized.id }
            copy(
                scripts = (others + normalized).sortedBy { it.name.lowercase() },
                status = "Saved script: ${normalized.name}",
            )
        }
    }

    fun deleteScript(id: String) {
        updateState {
            copy(
                scripts = scripts.filterNot { it.id == id },
                status = "Deleted script",
            )
        }
    }

    fun runScript(script: CustomScript) {
        activeSource.runScript(script)
    }

    // --- Script library management ---

    fun loadScriptLibrary(path: String) {
        val dir = File(path)
        val scripts = scriptLibraryManager.loadFromDirectory(dir)
        updateState {
            copy(
                libraryScripts = scripts,
                status = if (scripts.isEmpty())
                    "No scripts found in $path"
                else
                    "Loaded ${scripts.size} library script(s) from $path",
            )
        }
        appendSidecarLog("Script library loaded from $path — ${scripts.size} script(s)")
    }

    fun enableLibraryScript(id: String) {
        val script = state.libraryScripts.firstOrNull { it.id == id } ?: return
        activeSource.runScript(
            CustomScript(
                id = script.id,
                name = script.name,
                language = "javascript",
                description = script.description,
                content = script.content,
            )
        )
        updateState {
            copy(
                libraryScripts = libraryScripts.map { if (it.id == id) it.copy(enabled = true) else it },
                status = "Enabled: ${script.name}",
            )
        }
    }

    fun disableLibraryScript(id: String) {
        // Marks disabled in state; actual unload requires detach/re-attach.
        val script = state.libraryScripts.firstOrNull { it.id == id } ?: return
        updateState {
            copy(
                libraryScripts = libraryScripts.map { if (it.id == id) it.copy(enabled = false) else it },
                status = "Disabled: ${script.name} (takes effect on next attach)",
            )
        }
    }

    fun launchSidecar(pythonExecutable: String, projectRoot: String) {
        sidecarProcessManager.start(
            pythonExecutable,
            File(projectRoot),
            onOutput = { line -> appendSidecarLog(line) },
            onExit = { exitCode -> appendSidecarLog("sidecar exited with code $exitCode") },
        )
        updateState { copy(status = "Launching sidecar process...", mode = "sidecar", sessionStatus = "Waiting for FridaLink sidecar") }
    }

    fun stopSidecar() {
        sidecarProcessManager.stop()
        updateState { copy(status = "Stopped sidecar process", sessionStatus = "No FridaLink session") }
    }

    fun isSidecarProcessRunning(): Boolean = sidecarProcessManager.isRunning()

    fun selectEvent(index: Int?) {
        updateState { copy(selectedEventIndex = index) }
    }

    fun selectIntercept(id: String?) {
        updateState { copy(selectedInterceptId = id) }
    }

    fun submitInterceptAction(id: String, action: String, payload: String) {
        activeSource.submitInterceptAction(id, action, payload)
        updateState {
            copy(
                intercepts = intercepts.filterNot { it.id == id },
                selectedInterceptId = if (selectedInterceptId == id) null else selectedInterceptId,
            )
        }
    }

    override fun onStatus(status: String) {
        updateState { copy(status = status) }
        appendSidecarLog(status)
    }

    override fun onConnected(sourceName: String) {
        updateState { copy(connected = true, mode = sourceName, status = "Connected via $sourceName", sessionStatus = "FridaLink sidecar connected") }
        api.logging().logToOutput("FridaLink connected via $sourceName")
    }

    override fun onDisconnected(sourceName: String) {
        updateState { copy(connected = false, status = "Disconnected from $sourceName", sessionStatus = "No FridaLink session") }
        api.logging().logToOutput("FridaLink disconnected from $sourceName")
    }

    override fun onSessionSummary(summary: Map<String, Any?>) {
        val hostFrida = summary["host_frida_available"].toBooleanFlag()
        val deviceVisible = summary["android_device_visible"].toBooleanFlag()
        val processCount = summary["android_process_count"]?.toString().orEmpty().ifBlank { "0" }
        val sessionActive = summary["session_active"].toBooleanFlag()
        val loadedScripts = summary["loaded_script_count"]?.toString().orEmpty().ifBlank { "0" }
        val attachedPidText = summary["attached_pid"]?.toString()?.takeIf { it.isNotBlank() && it != "null" }
        val attachedPid = attachedPidText?.toIntOrNull()
        val attachedName = summary["attached_name"]?.toString()?.takeIf { it.isNotBlank() && it != "null" }
        val error = summary["error"]?.toString()?.takeIf { it.isNotBlank() && it != "null" }
        val sessionText = buildString {
            append("Host Frida=")
            append(if (hostFrida) "yes" else "no")
            append(" | Android device=")
            append(if (deviceVisible) "yes" else "no")
            append(" | Processes=")
            append(processCount)
            append(" | Session=")
            append(if (sessionActive) "attached" else "idle")
            append(" | Scripts=")
            append(loadedScripts)
            if (attachedPidText != null) {
                append(" | Target=")
                append(attachedName ?: "pid:$attachedPidText")
                append(" (")
                append(attachedPidText)
                append(")")
            }
            if (error != null) {
                append(" | Error=")
                append(error)
            }
        }
        updateState {
            copy(
                attachedPid = attachedPid,
                sessionStatus = sessionText,
            )
        }
    }

    override fun onProcesses(processes: List<Map<String, Any?>>) {
        val mapped = processes.map {
            TargetProcess(
                pid = (it["pid"] as? Number)?.toInt() ?: -1,
                name = it["name"]?.toString().orEmpty(),
                platform = it["platform"]?.toString().orEmpty(),
                state = it["state"]?.toString().orEmpty(),
                selected = it["selected"] as? Boolean ?: false,
                attached = it["attached"] as? Boolean ?: false,
            )
        }.sortedBy { it.name.lowercase() }
        updateState {
            val selected = mapped.firstOrNull { it.selected }?.pid
                ?: selectedPid?.takeIf { pid -> mapped.any { it.pid == pid } }
                ?: mapped.firstOrNull()?.pid
            val attached = mapped.firstOrNull { it.attached }?.pid ?: attachedPid?.takeIf { pid -> mapped.any { it.pid == pid } }
            copy(
                processes = mapped.map { it.copy(selected = it.pid == selected, attached = it.pid == attached) },
                selectedPid = selected,
                attachedPid = attached,
            )
        }
    }

    override fun onEvent(event: Map<String, Any?>) {
        val details = event.mapValues { (_, value) -> value?.toString().orEmpty() }
        val severityRaw = event["severity"]?.toString()
        val rawJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(event)
        val mapped = RuntimeEvent(
            id = eventCounter.incrementAndGet().toString(),
            timestamp = event["timestamp"]?.toString().orEmpty(),
            process = event["process"]?.toString().orEmpty(),
            category = event["category"]?.toString().orEmpty(),
            module = event["module"]?.toString().orEmpty(),
            target = event["target"]?.toString().orEmpty(),
            summary = event["summary"]?.toString().orEmpty(),
            severity = if (severityRaw in setOf("info", "warn", "error")) severityRaw!! else "info",
            threadId = event["thread_id"]?.toString().orEmpty(),
            scriptSource = event["script_source"]?.toString().orEmpty(),
            correlationId = event["correlation_id"]?.toString().orEmpty(),
            args = event["args"]?.toString().orEmpty(),
            retval = event["retval"]?.toString().orEmpty(),
            backtrace = event["backtrace"]?.toString().orEmpty(),
            raw = rawJson,
            details = details,
        )
        exporter.writeEvent(rawJson)
        updateState {
            val nextEvents = (listOf(mapped) + events).take(20_000)
            copy(events = nextEvents, selectedEventIndex = 0)
        }
    }

    override fun onIntercept(intercept: Map<String, Any?>) {
        val id = intercept["id"]?.toString().orEmpty()
        if (id.isBlank()) {
            return
        }
        val mapped = InterceptItem(
            id = id,
            timestamp = intercept["timestamp"]?.toString().orEmpty(),
            process = intercept["process"]?.toString().orEmpty(),
            direction = intercept["direction"]?.toString().orEmpty(),
            channel = intercept["channel"]?.toString().orEmpty(),
            summary = intercept["summary"]?.toString().orEmpty(),
            payload = intercept["payload"]?.toString().orEmpty(),
            editable = intercept["editable"]?.toString()?.toBooleanStrictOrNull() ?: true,
        )
        updateState {
            val next = listOf(mapped) + intercepts.filterNot { it.id == id }
            copy(intercepts = next.take(100), selectedInterceptId = mapped.id)
        }
    }

    override fun onReplResult(entry: fridalink.model.ReplEntry) {
        updateState {
            copy(replHistory = (listOf(entry) + replHistory).take(500))
        }
    }

    override fun onScripts(scripts: List<Map<String, Any?>>) {
        val mapped = scripts.map {
            CustomScript(
                id = it["id"]?.toString().orEmpty(),
                name = it["name"]?.toString().orEmpty(),
                language = it["language"]?.toString() ?: "javascript",
                description = it["description"]?.toString().orEmpty(),
                content = it["content"]?.toString().orEmpty(),
            )
        }
        updateState { copy(scripts = mapped) }
    }

    private fun updateState(update: FridaLinkState.() -> FridaLinkState) {
        synchronized(stateLock) {
            state = state.update()
        }
        markDirty()
    }

    private fun markDirty() {
        dirty = true
    }

    private fun flushPublish() {
        if (!dirty) {
            return
        }
        dirty = false
        val snapshot = synchronized(stateLock) { state }
        SwingUtilities.invokeLater {
            listeners.forEach { it(snapshot) }
        }
    }

    // -----------------------------------------------------------------------
    // Traffic analysis
    // -----------------------------------------------------------------------

    fun loadBurpTraffic() {
        appendSidecarLog("Loading Burp proxy history...")
        val entries = trafficAnalyzer.loadProxyHistory()
        appendSidecarLog("Loaded ${entries.size} traffic entries from proxy history")
        updateState { copy(trafficEntries = entries, status = "Loaded ${entries.size} traffic entries") }
        // Auto-geolocate all unique IPs/hosts extracted from URLs
        val hosts = entries.map { extractHostIp(it.url) }.filter { it.isNotBlank() }.distinct()
        geolocateHosts(hosts)
    }

    fun sendEntryToRepeater(entry: TrafficEntry) {
        trafficAnalyzer.sendToRepeater(entry)
        appendSidecarLog("Sent to Repeater: ${entry.method} ${entry.url}")
    }

    fun sendEntryToIntruder(entry: TrafficEntry) {
        trafficAnalyzer.sendToIntruder(entry)
        appendSidecarLog("Sent to Intruder: ${entry.method} ${entry.url}")
    }

    fun exportTrafficCsv(file: File) {
        trafficAnalyzer.exportToCsv(state.trafficEntries, file)
        appendSidecarLog("Traffic exported to ${file.absolutePath}")
        updateState { copy(status = "Traffic exported: ${file.absolutePath}") }
    }

    // -----------------------------------------------------------------------
    // Geolocation
    // -----------------------------------------------------------------------

    fun geolocateHosts(hosts: List<String>) {
        geoLocator.lookupBatch(hosts) { ip, result ->
            SwingUtilities.invokeLater {
                updateState { copy(geoResults = geoResults + (ip to result)) }
            }
        }
    }

    fun geolocateCurrentTraffic() {
        val hosts = state.trafficEntries.map { extractHostIp(it.url) }.filter { it.isNotBlank() }.distinct()
        appendSidecarLog("Geolocating ${hosts.size} hosts from traffic table...")
        geolocateHosts(hosts)
    }

    /**
     * Builds a human-readable summary of requests observed in Burp proxy history
     * to servers outside the United States, cross-referenced with geo and threat data.
     * Only reads hostnames from proxy history — no request bodies loaded.
     */
    fun analyzeForeignTraffic(): String {
        val hosts = trafficAnalyzer.extractProxyHosts()
        val nonUsResults = state.geoResults.values.filter { !it.isUS && it.status == "success" }
        if (nonUsResults.isEmpty()) return "No non-US geolocation results yet — run 'Geolocate from Proxy History' first."

        val sb = StringBuilder()
        sb.appendLine("=== Foreign Server Traffic Analysis ===")
        sb.appendLine("Total unique hosts in proxy history : ${hosts.size}")
        sb.appendLine("Non-US hosts with geo data         : ${nonUsResults.size}")
        sb.appendLine()

        val byCountry = nonUsResults.groupBy { it.country }.entries
            .sortedByDescending { it.value.size }
        sb.appendLine("By country:")
        for ((country, results) in byCountry) {
            val threats = results.filter { it.threatLabel.isNotBlank() }
            sb.appendLine("  $country (${results.size} hosts, ${threats.size} threats)")
            for (r in results.sortedByDescending { it.threatLabel.isNotBlank() }) {
                val threat = if (r.threatLabel.isNotBlank()) "  ← ${r.threatLabel}" else ""
                sb.appendLine("    • ${r.host.ifBlank { r.ip }}  [${r.org}]$threat")
            }
        }

        val threats = nonUsResults.filter { it.threatLabel.isNotBlank() }
        if (threats.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("=== Threat / Tracker Summary ===")
            for (r in threats.sortedBy { it.threatLabel }) {
                sb.appendLine("  ${r.threatLabel.padEnd(35)} ${r.host.ifBlank { r.ip }}  (${r.country})")
            }
        }
        return sb.toString()
    }

    /**
     * Extract unique hostnames directly from Burp proxy history (no bodies loaded)
     * and geolocate them.  This avoids the OOM caused by loading full TrafficEntry objects.
     */
    fun geolocateFromBurpProxy() {
        Thread {
            appendSidecarLog("Extracting hosts from Burp proxy history...")
            updateState { copy(status = "Reading proxy history hosts...") }
            val hosts = trafficAnalyzer.extractProxyHosts()
            appendSidecarLog("Found ${hosts.size} unique hosts in proxy history — geolocating...")
            updateState { copy(status = "Geolocating ${hosts.size} hosts...") }
            geolocateHosts(hosts)
        }.start()
    }

    private fun extractHostIp(url: String): String {
        return try { java.net.URL(url).host } catch (_: Exception) {
            url.substringAfter("://").substringBefore("/").substringBefore(":")
        }
    }

    // -----------------------------------------------------------------------
    // Frida Trace
    // -----------------------------------------------------------------------

    fun startFridaTrace(config: FridaTraceConfig, workDir: File) {
        if (fridaTraceRunner.isRunning()) {
            appendSidecarLog("frida-trace already running — stop first")
            return
        }
        updateState { copy(fridaTraceOutput = emptyList(), status = "Starting frida-trace...") }
        fridaTraceRunner.start(config, workDir) { line ->
            SwingUtilities.invokeLater {
                updateState {
                    copy(
                        fridaTraceOutput = (fridaTraceOutput + line).takeLast(5000),
                        status = "frida-trace: $line".take(80),
                    )
                }
            }
        }
    }

    fun stopFridaTrace() {
        fridaTraceRunner.stop()
        updateState { copy(status = "frida-trace stopped") }
        appendSidecarLog("frida-trace stopped")
    }

    fun isFridaTraceRunning(): Boolean = fridaTraceRunner.isRunning()

    // -----------------------------------------------------------------------
    // Tshark / Wireshark
    // -----------------------------------------------------------------------

    fun startTshark(iface: String, outDir: File, filter: String = "") {
        if (tsharkRunner.isRunning()) return
        updateState { copy(tsharkCapturing = true, status = "tshark capturing on $iface") }
        tsharkRunner.start(iface, outDir, filter,
            onEntry = { entry ->
                SwingUtilities.invokeLater {
                    updateState { copy(tsharkEntries = (tsharkEntries + entry).takeLast(10000)) }
                }
            },
            onLine = { line -> appendSidecarLog("[tshark] $line") },
        )
    }

    fun stopTshark() {
        tsharkRunner.stop()
        updateState { copy(tsharkCapturing = false, status = "tshark stopped") }
        appendSidecarLog("tshark stopped — captured ${tsharkRunner.capturedEntries.size} HTTP entries")
    }

    fun exportTsharkCsv(file: File) {
        tsharkRunner.exportCsv(file)
        appendSidecarLog("tshark data exported to ${file.absolutePath}")
    }

    fun listTsharkInterfaces(): List<String> = tsharkRunner.listInterfaces()

    // -----------------------------------------------------------------------
    // APK static analysis
    // -----------------------------------------------------------------------

    fun analyzeApk(apkPath: String) {
        if (apkPath.isBlank()) { appendSidecarLog("APK path is empty"); return }
        appendSidecarLog("Starting APK analysis: $apkPath")
        updateState { copy(apkPath = apkPath, status = "Analyzing APK...", apkFindings = emptyList()) }
        Thread {
            val result = apkAnalyzer.analyze(apkPath) { msg -> appendSidecarLog("[APK] $msg") }

            // Merge decompiled source findings if a path is already set
            val srcPath = state.decompSrcPath
            val srcFindings = if (srcPath.isNotBlank()) {
                appendSidecarLog("[APK] Also scanning decompiled source at $srcPath...")
                decompiledScanner.scan(srcPath) { msg -> appendSidecarLog("[SRC] $msg") }
            } else emptyList()

            val allFindings = (result.findings + srcFindings)
                .distinctBy { it.title }
                .sortedByDescending { it.severity.ordinal }

            // Log critical/high findings to Burp output tab
            val highPlusFindings = allFindings.filter {
                it.severity == fridalink.model.FindingSeverity.CRITICAL ||
                it.severity == fridalink.model.FindingSeverity.HIGH
            }
            if (highPlusFindings.isNotEmpty()) {
                api.logging().logToOutput("=== FridaLink APK Analysis — ${java.io.File(apkPath).name} ===")
                api.logging().logToOutput("${allFindings.size} total findings | ${highPlusFindings.size} HIGH+")
                highPlusFindings.forEach { f ->
                    api.logging().logToOutput("[${f.severity}] ${f.title}")
                    api.logging().logToOutput("  ${f.description.lines().first()}")
                    api.logging().logToOutput("  MASVS: ${f.masvsRef.ifBlank{"N/A"}}  CWE: ${f.cweRef.ifBlank{"N/A"}}  CVSS: ${f.cvssScore}")
                }
                api.logging().logToOutput("==========================================")
            }

            SwingUtilities.invokeLater {
                updateState {
                    copy(
                        apkFindings             = allFindings,
                        decompSrcFindings       = srcFindings,
                        analysisUrlRefs         = result.urlRefs,
                        analysisLibraries       = result.libraries,
                        analysisCertInfo        = result.certInfo,
                        analysisBehaviorProfile = result.behaviorProfile,
                        status = "APK analysis complete — ${allFindings.size} findings",
                        masvsItems = if (masvsItems.isNotEmpty())
                            MasvsChecker.autoEvaluate(masvsItems, allFindings, events, adbResults)
                        else
                            MasvsChecker.autoEvaluate(MasvsChecker.buildChecklist(), allFindings, events, adbResults),
                    )
                }
                appendSidecarLog("APK analysis done: ${allFindings.size} findings (${srcFindings.size} from source), ${result.permissions.size} permissions, ${result.urlRefs.size} URLs, ${result.libraries.size} libraries")
            }
        }.start()
    }

    fun analyzeDecompiledSource(srcPath: String) {
        if (srcPath.isBlank()) { appendSidecarLog("Decompiled source path is empty"); return }
        appendSidecarLog("Scanning decompiled source: $srcPath")
        updateState { copy(decompSrcPath = srcPath, status = "Scanning decompiled source...") }
        Thread {
            val srcFindings = decompiledScanner.scan(srcPath) { msg -> appendSidecarLog("[SRC] $msg") }
            val allFindings = (state.apkFindings.filter { f ->
                srcFindings.none { it.title == f.title }
            } + srcFindings).sortedByDescending { it.severity.ordinal }

            val highPlusFindings = srcFindings.filter {
                it.severity == fridalink.model.FindingSeverity.CRITICAL ||
                it.severity == fridalink.model.FindingSeverity.HIGH
            }
            if (highPlusFindings.isNotEmpty()) {
                api.logging().logToOutput("=== FridaLink Source Analysis — ${java.io.File(srcPath).name} ===")
                api.logging().logToOutput("${srcFindings.size} findings from decompiled source | ${highPlusFindings.size} HIGH+")
                highPlusFindings.forEach { f ->
                    api.logging().logToOutput("[${f.severity}] ${f.title}")
                    api.logging().logToOutput("  MASVS: ${f.masvsRef.ifBlank{"N/A"}}  CWE: ${f.cweRef.ifBlank{"N/A"}}")
                }
                api.logging().logToOutput("==========================================")
            }

            SwingUtilities.invokeLater {
                updateState {
                    copy(
                        apkFindings       = allFindings,
                        decompSrcFindings = srcFindings,
                        status = "Source scan done — ${srcFindings.size} findings from source",
                        masvsItems = if (masvsItems.isNotEmpty())
                            MasvsChecker.autoEvaluate(masvsItems, allFindings, events, adbResults)
                        else
                            MasvsChecker.autoEvaluate(MasvsChecker.buildChecklist(), allFindings, events, adbResults),
                    )
                }
                appendSidecarLog("Source scan done: ${srcFindings.size} findings")
            }
        }.start()
    }

    // -----------------------------------------------------------------------
    // MASVS checklist
    // -----------------------------------------------------------------------

    fun initMasvsChecklist() {
        if (state.masvsItems.isEmpty()) {
            val items = MasvsChecker.autoEvaluate(MasvsChecker.buildChecklist(), state.apkFindings, state.events, state.adbResults)
            updateState { copy(masvsItems = items, status = "MASVS checklist loaded — ${items.size} controls") }
        }
    }

    fun updateMasvsItem(id: String, status: MasvsStatus, notes: String) {
        updateState {
            copy(masvsItems = masvsItems.map {
                if (it.id == id) it.copy(status = status, notes = notes) else it
            })
        }
    }

    fun reevaluateMasvs() {
        val items = MasvsChecker.autoEvaluate(
            state.masvsItems.ifEmpty { MasvsChecker.buildChecklist() },
            state.apkFindings,
            state.events,
            state.adbResults,
        )
        updateState { copy(masvsItems = items, status = "MASVS re-evaluated") }
    }

    // -----------------------------------------------------------------------
    // Report generation
    // -----------------------------------------------------------------------

    fun generateReport(outputFile: File, targetApp: String, assessor: String, engagementId: String) {
        updateState { copy(reportStatus = "Generating report...", status = "Generating PDF report...") }
        Thread {
            try {
                val cfg = ReportGenerator.ReportConfig(
                    targetApp      = targetApp,
                    assessor       = assessor,
                    engagementId   = engagementId,
                    outputFile     = outputFile,
                )
                reportGenerator.generate(
                    config         = cfg,
                    apkFindings    = state.apkFindings,
                    masvsItems     = state.masvsItems.ifEmpty { MasvsChecker.buildChecklist() },
                    trafficEntries = state.trafficEntries + state.tsharkEntries,
                    geoResults     = geoLocator.allResults(),
                ) { msg -> appendSidecarLog("[Report] $msg") }
                SwingUtilities.invokeLater {
                    updateState { copy(reportStatus = "Report saved: ${outputFile.absolutePath}", status = "PDF report generated") }
                }
            } catch (e: Exception) {
                SwingUtilities.invokeLater {
                    updateState { copy(reportStatus = "Report ERROR: ${e.message}", status = "Report generation failed") }
                }
                appendSidecarLog("[Report] ERROR: ${e.message}")
            }
        }.start()
    }

    // -----------------------------------------------------------------------
    // ADB device integration
    // -----------------------------------------------------------------------

    /** Returns a one-line human-readable summary of the detected host shell environment. */
    fun hostEnvSummary(): String {
        val env = state.hostShellEnv ?: return "Host environment not yet detected"
        return if (!env.isWindows) {
            "Host: Linux/macOS — bash available"
        } else if (env.hasBash) {
            "Host: Windows — Git Bash found at ${env.gitBashPath}"
        } else {
            "Host: Windows — Git Bash NOT FOUND (install from git-scm.com, choose 'Add to PATH')"
        }
    }

    fun checkAdbAvailability() {
        Thread {
            val available = adbRunner.isAvailable()
            val devices   = if (available) adbRunner.getDevices() else emptyList()
            appendSidecarLog(if (available) "ADB available — ${devices.size} device(s): ${devices.joinToString()}" else "ADB not found — install Android SDK Platform-Tools and ensure adb is on PATH")
            SwingUtilities.invokeLater {
                updateState {
                    copy(
                        adbAvailable = available,
                        adbDevices   = devices,
                        adbStatus    = if (available) "${devices.size} device(s): ${devices.joinToString().ifBlank { "none connected" }}" else "adb not found on PATH",
                    )
                }
            }
        }.start()
    }

    /**
     * Run all MASVS-relevant ADB checks for [pkg] on the first connected device
     * (or [serial] if specified).  Results are fed into MASVS autoEvaluate.
     */
    fun runAdbMasvsChecks(pkg: String, serial: String? = null) {
        if (!state.adbAvailable) {
            appendSidecarLog("ADB not available — run 'Check ADB' first")
            return
        }
        if (state.adbDevices.isEmpty()) {
            appendSidecarLog("No ADB devices connected")
            return
        }
        val targetSerial = serial ?: adbRunner.preferredSerial(state.adbDevices)
        val connType = if (targetSerial != null && adbRunner.isTcpSerial(targetSerial)) "TCP" else "USB"
        appendSidecarLog("Running ADB MASVS checks for '$pkg' on device ${targetSerial ?: "default"} ($connType)...")
        updateState { copy(adbStatus = "Running checks on ${targetSerial ?: "default"}...") }
        Thread {
            val results = adbRunner.runMasvsChecks(pkg, targetSerial)
            val checklist = state.masvsItems.ifEmpty { MasvsChecker.buildChecklist() }
            val evaluated = MasvsChecker.autoEvaluate(checklist, state.apkFindings, state.events, results)

            // Build a human-readable display block for the raw results
            val rawDisplay = buildString {
                appendLine("ADB Check Results — $pkg")
                appendLine("Device : ${targetSerial ?: "first connected"}")
                appendLine("Time   : ${java.time.LocalTime.now().withNano(0)}")
                appendLine("Checks : ${results.size}")
                appendLine("")
                appendLine("═".repeat(60))
                for ((key, value) in results.entries.sortedBy { it.key }) {
                    val masvsTag = when {
                        key.startsWith("ro.debuggable") || key.startsWith("app.debuggable") || key.startsWith("app.flags") || key.startsWith("ro.build") -> "MASVS-CODE-1"
                        key.startsWith("app.allowBackup") -> "MASVS-STORAGE-6"
                        key.startsWith("app.sharedPrefs") -> "MASVS-STORAGE-1"
                        key.startsWith("app.external")    -> "MASVS-STORAGE-1"
                        key.startsWith("root.")           -> "MASVS-RESILIENCE-1"
                        key.startsWith("device.")         -> "MASVS-RESILIENCE-4"
                        key.startsWith("frida.")          -> "MASVS-RESILIENCE-6"
                        key.startsWith("network.")        -> "MASVS-NETWORK-1"
                        key.startsWith("ssl.")            -> "MASVS-NETWORK-3"
                        else                              -> ""
                    }
                    val tag = if (masvsTag.isNotBlank()) "[$masvsTag]" else ""
                    appendLine("┌ $key  $tag")
                    value.lines().forEach { appendLine("│  $it") }
                    appendLine("")
                }
                appendLine("═".repeat(60))
                appendLine("")
                appendLine("MASVS Items Updated:")
                evaluated.filter { it.evidence.contains("[ADB]") }.forEach { item ->
                    appendLine("  ${item.id} — ${item.status}  ${item.control}")
                    item.evidence.lines().filter { it.startsWith("[ADB]") }.forEach { ev ->
                        appendLine("    $ev")
                    }
                }
            }

            // Log to Burp output tab
            api.logging().logToOutput("=== FridaLink ADB MASVS Checks — $pkg ===")
            results.entries.sortedBy { it.key }.forEach { (key, value) ->
                api.logging().logToOutput("  $key = ${value.take(120)}")
            }
            val failedItems = evaluated.filter { it.evidence.contains("[ADB]") && it.status == fridalink.model.MasvsStatus.FAIL }
            if (failedItems.isNotEmpty()) {
                api.logging().logToOutput("MASVS FAILURES from ADB:")
                failedItems.forEach { api.logging().logToOutput("  [FAIL] ${it.id} — ${it.control}") }
            }
            api.logging().logToOutput("==========================================")

            appendSidecarLog("ADB checks complete — ${results.size} checks, ${failedItems.size} MASVS failures")
            SwingUtilities.invokeLater {
                updateState {
                    copy(
                        adbResults     = results,
                        adbRawDisplay  = rawDisplay,
                        masvsItems     = evaluated,
                        adbStatus      = "Last checked: ${java.time.LocalTime.now().withNano(0)} — ${results.size} checks",
                        status         = "ADB MASVS checks done — ${results.size} results",
                    )
                }
            }
        }.start()
    }

    // -----------------------------------------------------------------------
    // False positive management
    // -----------------------------------------------------------------------

    /**
     * Marks a finding as a false positive by matching title + category.
     * The FindingsTableModel filters out false-positive items on next render.
     */
    fun markFindingFalsePositive(findingTitle: String, findingCategory: String) {
        updateState {
            copy(apkFindings = apkFindings.map {
                if (it.title == findingTitle && it.category == findingCategory)
                    it.copy(isFalsePositive = true)
                else it
            })
        }
        appendSidecarLog("Finding marked as false positive: $findingTitle")
    }

    // -----------------------------------------------------------------------
    // Certificate pull via ADB
    // -----------------------------------------------------------------------

    /**
     * Pulls the app APK from the device via `adb pull`, then re-runs the
     * static analyser's cert-extraction step and updates [analysisCertInfo].
     */
    fun pullCertViaAdb(pkg: String = "com.crunchyroll.bleachsoulres", serial: String? = null) {
        if (!state.adbAvailable) {
            appendSidecarLog("pullCertViaAdb: ADB not available — run 'Check ADB' first")
            return
        }
        appendSidecarLog("Pulling certificate for $pkg via ADB...")
        updateState { copy(status = "Pulling APK from device for cert extraction...") }
        Thread {
            try {
                // Step 1: resolve on-device APK path
                val pmOut = adbRunner.shell("pm path $pkg 2>/dev/null", serial).trim()
                val apkOnDevice = pmOut.substringAfter("package:").trim()
                if (apkOnDevice.isBlank()) {
                    appendSidecarLog("pullCertViaAdb: 'pm path' returned no path for $pkg")
                    SwingUtilities.invokeLater { updateState { copy(status = "Cert pull failed — package not found on device") } }
                    return@Thread
                }
                appendSidecarLog("APK on device: $apkOnDevice")

                // Step 2: pull APK to temp file
                val tmpFile = java.io.File(System.getProperty("java.io.tmpdir"), "fridalink_cert_pull.apk")
                adbRunner.run(listOf("pull", apkOnDevice, tmpFile.absolutePath), serial)
                if (!tmpFile.exists() || tmpFile.length() == 0L) {
                    appendSidecarLog("pullCertViaAdb: adb pull failed — file missing or empty")
                    SwingUtilities.invokeLater { updateState { copy(status = "Cert pull failed — adb pull error") } }
                    return@Thread
                }
                appendSidecarLog("APK pulled to ${tmpFile.absolutePath} (${tmpFile.length() / 1024} KB)")

                // Step 3: run static analyser for cert only
                val result = apkAnalyzer.analyze(tmpFile.absolutePath) { msg -> appendSidecarLog("[Cert] $msg") }
                tmpFile.delete()

                if (result.certInfo != null) {
                    appendSidecarLog("Certificate subject: ${result.certInfo.subject}")
                    SwingUtilities.invokeLater {
                        updateState {
                            copy(
                                analysisCertInfo = result.certInfo,
                                status = "Certificate extracted via ADB",
                            )
                        }
                    }
                } else {
                    appendSidecarLog("pullCertViaAdb: analyser returned no cert info")
                    SwingUtilities.invokeLater { updateState { copy(status = "Cert pull: APK pulled but no cert extracted") } }
                }
            } catch (e: Exception) {
                appendSidecarLog("pullCertViaAdb error: ${e.message}")
                SwingUtilities.invokeLater { updateState { copy(status = "Cert pull failed: ${e.message}") } }
            }
        }.also { it.isDaemon = true }.start()
    }

    // -----------------------------------------------------------------------
    // Geo from live event stream
    // -----------------------------------------------------------------------

    /**
     * Extracts unique IPs / hostnames from the live Frida event stream
     * (dns, caller_net, http, native categories) and geolocates them.
     */
    fun geolocateFromEventStream() {
        val ipPattern = Regex("""(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)""")
        val hosts = state.events
            .filter { it.category in setOf("dns", "caller_net", "http", "native", "socket", "udp") }
            .flatMap { e ->
                buildList {
                    if (e.target.isNotBlank()) add(extractHostIp(e.target))
                    ipPattern.findAll(e.summary).map { it.value }.forEach { add(it) }
                    ipPattern.findAll(e.target).map { it.value }.forEach { add(it) }
                }
            }
            .filter { it.isNotBlank() && !it.startsWith("0.") && it != "127.0.0.1" && it != "localhost" }
            .distinct()

        if (hosts.isEmpty()) {
            appendSidecarLog("geolocateFromEventStream: no IPs/hosts found in ${state.events.size} events")
            return
        }
        appendSidecarLog("Geolocating ${hosts.size} host(s) from live event stream...")
        updateState { copy(status = "Geolocating ${hosts.size} hosts from event stream...") }
        geolocateHosts(hosts)
    }

    private fun appendSidecarLog(line: String) {
        val timestamped = "[${java.time.LocalTime.now().withNano(0)}] $line"
        synchronized(stateLock) {
            state = state.copy(sidecarLogs = (state.sidecarLogs + timestamped).takeLast(1000))
        }
        markDirty()
    }

    private fun Any?.toBooleanFlag(): Boolean =
        when (this) {
            is Boolean -> this
            is String -> equals("true", ignoreCase = true)
            is Number -> toInt() != 0
            else -> false
        }
}
