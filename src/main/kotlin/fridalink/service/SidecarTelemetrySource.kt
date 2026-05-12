package fridalink.service

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import fridalink.model.CustomScript
import fridalink.model.ReplEntry
import fridalink.model.SidecarConfig
import java.net.URI
import java.net.http.HttpClient
import java.net.http.WebSocket
import java.nio.ByteBuffer
import java.util.concurrent.CompletionStage

class SidecarTelemetrySource : TelemetrySource {
    override val name: String = "sidecar"

    private val mapper: ObjectMapper = jacksonObjectMapper()
    private val httpClient = HttpClient.newHttpClient()
    private var listener: TelemetryListener? = null
    private var webSocket: WebSocket? = null

    override fun start(listener: TelemetryListener) {
        this.listener = listener
    }

    override fun stop() {
        disconnect()
    }

    override fun connect(config: SidecarConfig) {
        val uri = URI("ws://${config.host}:${config.port}/ws")
        listener?.onStatus("Connecting to $uri")
        httpClient.newWebSocketBuilder().buildAsync(uri, SocketListener()).whenComplete { socket, error ->
            if (error != null) {
                listener?.onStatus("Sidecar connect failed: ${error.message}")
                return@whenComplete
            }
            webSocket = socket
            listener?.onConnected(name)
            listener?.onStatus("Connected to sidecar")
            sendJson(
                mapOf(
                    "type" to "hello",
                    "client" to "fridalink-burp",
                    "version" to "0.1.0",
                )
            )
        }
    }

    override fun disconnect() {
        webSocket?.sendClose(WebSocket.NORMAL_CLOSURE, "bye")
        webSocket = null
        listener?.onDisconnected(name)
    }

    override fun refreshProcesses() {
        sendJson(mapOf("type" to "process_refresh"))
    }

    override fun attachProcess(pid: Int) {
        sendJson(mapOf("type" to "attach", "pid" to pid))
    }

    override fun detachProcess() {
        sendJson(mapOf("type" to "detach"))
    }

    override fun runScript(script: CustomScript) {
        sendJson(
            mapOf(
                "type" to "script_run",
                "script" to mapOf(
                    "id" to script.id,
                    "name" to script.name,
                    "language" to script.language,
                    "description" to script.description,
                    "content" to script.content,
                ),
            )
        )
        listener?.onStatus("Sent script run request: ${script.name}")
    }

    override fun submitInterceptAction(id: String, action: String, payload: String) {
        sendJson(
            mapOf(
                "type" to "intercept_action",
                "id" to id,
                "action" to action,
                "payload" to payload,
            )
        )
        listener?.onStatus("Sent intercept action '$action' for $id")
    }

    override fun spawnProcess(identifier: String, scripts: List<fridalink.model.CustomScript>) {
        sendJson(
            mapOf(
                "type" to "spawn",
                "identifier" to identifier,
                "scripts" to scripts.map {
                    mapOf("name" to it.name, "content" to it.content)
                },
            )
        )
        val count = scripts.size
        listener?.onStatus("Sent spawn request: $identifier (${count} script(s) to auto-load)")
    }

    override fun resumeProcess() {
        sendJson(mapOf("type" to "resume"))
        listener?.onStatus("Sent resume request")
    }

    override fun updateRules(rules: List<fridalink.model.MatchReplaceRule>) {
        sendJson(
            mapOf(
                "type" to "update_rules",
                "rules" to rules.map {
                    mapOf(
                        "id" to it.id,
                        "enabled" to it.enabled,
                        "urlPattern" to it.urlPattern,
                        "matchText" to it.matchText,
                        "replaceText" to it.replaceText,
                        "isRegex" to it.isRegex,
                        "comment" to it.comment,
                    )
                },
            )
        )
        listener?.onStatus("Pushed ${rules.count { it.enabled }} active rule(s) to session")
    }

    override fun callRpc(method: String, args: List<Any>) {
        sendJson(mapOf("type" to "rpc_call", "method" to method, "args" to args))
        listener?.onStatus("RPC dispatched: $method(${args.joinToString()}) — result incoming as rpc_result event")
    }

    override fun evalRepl(code: String) {
        sendJson(mapOf("type" to "repl_eval", "code" to code))
    }

    private fun sendJson(payload: Any) {
        val socket = webSocket ?: return
        socket.sendText(mapper.writeValueAsString(payload), true)
    }

    private fun handleMessage(text: String) {
        val message = mapper.readTree(text)
        when (message["type"]?.asText()) {
            "process_list" -> listener?.onProcesses(message["processes"]?.toMaps().orEmpty())
            "session_summary" -> listener?.onSessionSummary(message["summary"]?.toMap().orEmpty())
            "event" -> listener?.onEvent(message.toMap())
            "event_batch" -> message["events"]?.toMaps().orEmpty().forEach { listener?.onEvent(it) }
            "intercept" -> listener?.onIntercept(message.toMap())
            "intercept_batch" -> message["items"]?.toMaps().orEmpty().forEach { listener?.onIntercept(it) }
            "scripts" -> listener?.onScripts(message["scripts"]?.toMaps().orEmpty())
            "status" -> listener?.onStatus(message["message"]?.asText() ?: "status")
            "repl_result" -> {
                val resultNode = message["result"]
                val errorNode  = message["error"]
                listener?.onReplResult(
                    ReplEntry(
                        code      = message["code"]?.asText().orEmpty(),
                        result    = if (resultNode != null && !resultNode.isNull) resultNode.asText() else null,
                        error     = if (errorNode  != null && !errorNode.isNull)  errorNode.asText()  else null,
                        timestamp = java.time.Instant.now().toString(),
                    )
                )
            }
        }
    }

    private fun JsonNode.toMaps(): List<Map<String, Any?>> =
        if (!isArray) emptyList() else map { node ->
            node.fields().asSequence().associate { entry ->
                entry.key to when {
                    entry.value.isTextual -> entry.value.asText()
                    entry.value.isInt -> entry.value.asInt()
                    entry.value.isBoolean -> entry.value.asBoolean()
                    entry.value.isLong -> entry.value.asLong()
                    else -> entry.value.toString()
                }
            }
        }.toList()

    private fun JsonNode.toMap(): Map<String, Any?> =
        fields().asSequence().associate { entry ->
            entry.key to when {
                entry.value.isTextual -> entry.value.asText()
                entry.value.isInt -> entry.value.asInt()
                entry.value.isBoolean -> entry.value.asBoolean()
                entry.value.isLong -> entry.value.asLong()
                else -> entry.value.toString()
            }
        }

    private inner class SocketListener : WebSocket.Listener {
        private val buffer = StringBuilder()

        override fun onOpen(webSocket: WebSocket) {
            webSocket.request(1)
        }

        override fun onText(webSocket: WebSocket, data: CharSequence, last: Boolean): CompletionStage<*>? {
            buffer.append(data)
            if (last) {
                val text = buffer.toString()
                buffer.setLength(0)
                handleMessage(text)
            }
            webSocket.request(1)
            return null
        }

        override fun onBinary(webSocket: WebSocket, data: ByteBuffer, last: Boolean): CompletionStage<*>? {
            webSocket.request(1)
            return null
        }

        override fun onError(webSocket: WebSocket, error: Throwable) {
            listener?.onStatus("Sidecar socket error: ${error.message}")
        }
    }
}
