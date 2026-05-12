package fridalink.service

import fridalink.model.CustomScript
import fridalink.model.ReplEntry
import fridalink.model.SidecarConfig

interface TelemetrySource {
    val name: String

    fun start(listener: TelemetryListener)

    fun stop()

    fun connect(config: SidecarConfig)

    fun disconnect()

    fun refreshProcesses()

    fun attachProcess(pid: Int)

    fun detachProcess()

    fun runScript(script: CustomScript)

    fun submitInterceptAction(id: String, action: String, payload: String)

    /** Spawn [identifier] (paused), load [scripts] into the session, then wait for resumeProcess(). */
    fun spawnProcess(identifier: String, scripts: List<fridalink.model.CustomScript>)

    fun resumeProcess()

    /** Push match-and-replace rules to all loaded scripts in the active session. */
    fun updateRules(rules: List<fridalink.model.MatchReplaceRule>)

    /**
     * Dispatch an RPC-style call to all loaded scripts by posting a
     * {type:"rpc_call", method, args} message.  Results arrive back as
     * fridalink_event events with category="rpc_result".
     */
    fun callRpc(method: String, args: List<Any> = emptyList())

    /**
     * Evaluate [code] as JavaScript in the Frida script context via the
     * auto-loaded REPL helper script.  Result arrives via onReplResult().
     */
    fun evalRepl(code: String)
}

interface TelemetryListener {
    fun onStatus(status: String)

    fun onConnected(sourceName: String)

    fun onDisconnected(sourceName: String)

    fun onSessionSummary(summary: Map<String, Any?>)

    fun onProcesses(processes: List<Map<String, Any?>>)

    fun onEvent(event: Map<String, Any?>)

    fun onIntercept(intercept: Map<String, Any?>)

    fun onScripts(scripts: List<Map<String, Any?>>)

    /** Called when the sidecar returns a REPL evaluation result. */
    fun onReplResult(entry: ReplEntry)
}
