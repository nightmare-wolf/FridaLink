package fridalink.service

import fridalink.model.CustomScript
import fridalink.model.SidecarConfig
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import kotlin.random.Random

class DemoTelemetrySource : TelemetrySource {
    override val name: String = "demo"

    private var listener: TelemetryListener? = null
    private var executor: ScheduledExecutorService? = null
    private var tick: Int = 0
    private var selectedPid: Int = 1010
    private var attachedPid: Int? = null

    override fun start(listener: TelemetryListener) {
        this.listener = listener
    }

    override fun stop() {
        executor?.shutdownNow()
        executor = null
    }

    override fun connect(config: SidecarConfig) {
        stop()
        listener?.onStatus("Connected to demo feed")
        listener?.onConnected(name)
        listener?.onScripts(
            listOf(
                mapOf(
                    "id" to "demo-logcat",
                    "name" to "Demo call tracer",
                    "language" to "javascript",
                    "description" to "Synthetic Frida script placeholder",
                    "content" to "Interceptor.attach(ptr('0x0'), { onEnter(args) { send({type:'demo'}); } });",
                )
            )
        )
        executor = Executors.newSingleThreadScheduledExecutor()
        executor?.scheduleAtFixedRate(::emitDemoState, 0, 2, TimeUnit.SECONDS)
    }

    override fun disconnect() {
        stop()
        attachedPid = null
        listener?.onDisconnected(name)
        listener?.onStatus("Disconnected from demo feed")
    }

    override fun refreshProcesses() {
        emitDemoState()
        listener?.onStatus("Demo process list refreshed")
    }

    override fun attachProcess(pid: Int) {
        selectedPid = pid
        attachedPid = pid
        emitDemoState()
        listener?.onStatus("Demo attached to pid $pid")
        listener?.onEvent(
            mapOf(
                "timestamp" to Instant.now().toString(),
                "process" to processNameFor(pid),
                "category" to "attach",
                "module" to "session",
                "target" to pid.toString(),
                "summary" to "Attached to demo process",
            )
        )
    }

    override fun detachProcess() {
        val previous = attachedPid
        attachedPid = null
        emitDemoState()
        listener?.onStatus("Demo detached")
        if (previous != null) {
            listener?.onEvent(
                mapOf(
                    "timestamp" to Instant.now().toString(),
                    "process" to processNameFor(previous),
                    "category" to "detach",
                    "module" to "session",
                    "target" to previous.toString(),
                    "summary" to "Detached from demo process",
                )
            )
        }
    }

    override fun runScript(script: CustomScript) {
        val pid = attachedPid ?: selectedPid
        listener?.onStatus("Demo script run requested: ${script.name}")
        listener?.onEvent(
            mapOf(
                "timestamp" to Instant.now().toString(),
                "process" to processNameFor(pid),
                "category" to "script",
                "module" to "custom",
                "target" to script.name,
                "summary" to "Executed custom script request in demo mode",
            )
        )
    }

    override fun submitInterceptAction(id: String, action: String, payload: String) {
        listener?.onStatus("Demo intercept action '$action' for $id")
        listener?.onEvent(
            mapOf(
                "timestamp" to Instant.now().toString(),
                "process" to processNameFor(attachedPid ?: selectedPid),
                "category" to "intercept",
                "module" to "queue",
                "target" to id,
                "summary" to "Demo intercept action: $action",
                "action" to action,
                "payload" to payload,
            )
        )
    }

    override fun spawnProcess(identifier: String, scripts: List<fridalink.model.CustomScript>) {
        listener?.onStatus("Demo spawn: $identifier (${scripts.size} script(s))")
    }

    override fun resumeProcess() {
        listener?.onStatus("Demo resume")
    }

    override fun updateRules(rules: List<fridalink.model.MatchReplaceRule>) {
        listener?.onStatus("Demo: ${rules.size} rule(s) updated")
    }

    override fun callRpc(method: String, args: List<Any>) {
        listener?.onStatus("Demo RPC: $method(${args.joinToString()})")
        listener?.onEvent(
            mapOf(
                "timestamp"  to Instant.now().toString(),
                "process"    to processNameFor(attachedPid ?: selectedPid),
                "category"   to "rpc_result",
                "module"     to "lua_il2cpp_inspector",
                "target"     to method,
                "summary"    to "[DEMO] $method() → demo result",
                "severity"   to "info",
                "args"       to """{"method":"$method","callArgs":${args},"result":"demo-mode"}""",
            )
        )
    }

    override fun evalRepl(code: String) {
        listener?.onStatus("Demo REPL: $code")
        listener?.onReplResult(
            fridalink.model.ReplEntry(
                code      = code,
                result    = "[DEMO] ${code.take(60)} → \"demo-result\"",
                error     = null,
                timestamp = Instant.now().toString(),
            )
        )
    }

    private fun emitDemoState() {
        tick += 1
        val processBase = listOf(
            mapOf(
                "pid" to 1010,
                "name" to "BleachSoulRes",
                "platform" to "android",
                "state" to if (tick % 3 == 0) "foreground" else "running",
                "selected" to (selectedPid == 1010),
                "attached" to (attachedPid == 1010),
            ),
            mapOf(
                "pid" to 1011,
                "name" to "com.android.systemui",
                "platform" to "android",
                "state" to "running",
                "selected" to (selectedPid == 1011),
                "attached" to (attachedPid == 1011),
            ),
        )
        val maybeExtra = if (tick % 4 == 0) {
            listOf(
                mapOf(
                    "pid" to 1020,
                    "name" to "zygote64",
                    "platform" to "android",
                    "state" to "background",
                    "selected" to (selectedPid == 1020),
                    "attached" to (attachedPid == 1020),
                )
            )
        } else {
            emptyList()
        }
        listener?.onProcesses(processBase + maybeExtra)
        listener?.onEvent(
            mapOf(
                "timestamp" to Instant.now().toString(),
                "process" to "BleachSoulRes",
                "category" to listOf("call", "network", "jni", "message")[Random.nextInt(4)],
                "module" to listOf("libil2cpp.so", "UnityPlayer", "libart.so", "custom.js")[Random.nextInt(4)],
                "target" to listOf(
                    "UnitySendMessage",
                    "ssl_write",
                    "BattleEndClient",
                    "InventorySync",
                    "CustomHook",
                )[Random.nextInt(5)],
                "summary" to listOf(
                    "Runtime call observed",
                    "Socket payload emitted",
                    "IL2CPP method traced",
                    "Custom script message received",
                )[Random.nextInt(4)],
            )
        )
    }

    private fun processNameFor(pid: Int): String = when (pid) {
        1010 -> "BleachSoulRes"
        1011 -> "com.android.systemui"
        1020 -> "zygote64"
        else -> "pid:$pid"
    }
}
