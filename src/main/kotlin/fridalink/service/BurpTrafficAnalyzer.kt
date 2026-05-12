package fridalink.service

import burp.api.montoya.MontoyaApi
import fridalink.model.TrafficEntry
import java.util.UUID

/**
 * Reads the Burp proxy history and extracts structured TrafficEntry objects.
 * Also provides helpers to send entries to Repeater and Intruder.
 */
class BurpTrafficAnalyzer(private val api: MontoyaApi) {

    /**
     * Extracts only unique hostnames from Burp proxy history without loading
     * request/response bodies.  Use this for geolocation to avoid OOM.
     */
    fun extractProxyHosts(): List<String> {
        return try {
            api.proxy().history().mapNotNull { item ->
                try {
                    val url = item.request()?.url() ?: return@mapNotNull null
                    extractHost(url).takeIf { it.isNotBlank() }
                } catch (_: Exception) { null }
            }.distinct()
        } catch (e: Exception) {
            api.logging().logToError("BurpTrafficAnalyzer.extractProxyHosts: ${e.message}")
            emptyList()
        }
    }

    fun loadProxyHistory(): List<TrafficEntry> {
        return try {
            api.proxy().history().mapIndexedNotNull { idx, item ->
                try {
                    val req = item.request() ?: return@mapIndexedNotNull null
                    val resp = try { item.response() } catch (_: Exception) { null }

                    val url    = req.url() ?: ""
                    val method = req.method() ?: "?"
                    val host   = extractHost(url)
                    val path   = extractPath(url)
                    val params = extractParamNames(url, req.bodyToString() ?: "", method)

                    val reqHeaders  = req.headers()?.joinToString("\n") { "${it.name()}: ${it.value()}" } ?: ""
                    val reqBody     = req.bodyToString() ?: ""
                    val respHeaders = resp?.headers()?.joinToString("\n") { "${it.name()}: ${it.value()}" } ?: ""
                    val respBody    = try { resp?.bodyToString()?.take(8192) ?: "" } catch (_: Exception) { "" }
                    val statusCode  = try { resp?.statusCode()?.toInt() ?: 0 } catch (_: Exception) { 0 }
                    val mimeType    = try { resp?.mimeType()?.toString() ?: "" } catch (_: Exception) { "" }
                    val reqLen      = try { req.body()?.length() ?: 0 } catch (_: Exception) { 0 }
                    val respLen     = try { resp?.body()?.length() ?: 0 } catch (_: Exception) { 0 }

                    TrafficEntry(
                        id             = "${idx}_${UUID.randomUUID()}",
                        method         = method,
                        host           = host,
                        url            = url,
                        path           = path,
                        statusCode     = statusCode,
                        mimeType       = mimeType,
                        requestLength  = reqLen.toInt(),
                        responseLength = respLen.toInt(),
                        params         = params,
                        requestHeaders = reqHeaders,
                        requestBody    = reqBody,
                        responseHeaders = respHeaders,
                        responseBody   = respBody,
                    )
                } catch (e: Exception) {
                    api.logging().logToError("BurpTrafficAnalyzer: error parsing item $idx: ${e.message}")
                    null
                }
            }
        } catch (e: Exception) {
            api.logging().logToError("BurpTrafficAnalyzer: failed to load history: ${e.message}")
            emptyList()
        }
    }

    fun sendToRepeater(entry: TrafficEntry) {
        try {
            val items = api.proxy().history()
            // Find the matching item by URL + method
            val match = items.firstOrNull { item ->
                try {
                    item.request()?.url() == entry.url && item.request()?.method() == entry.method
                } catch (_: Exception) { false }
            }
            if (match != null) {
                api.repeater().sendToRepeater(match.request())
            } else {
                api.logging().logToOutput("Repeater: no matching request found for ${entry.url}")
            }
        } catch (e: Exception) {
            api.logging().logToError("sendToRepeater: ${e.message}")
        }
    }

    fun sendToIntruder(entry: TrafficEntry) {
        try {
            val items = api.proxy().history()
            val match = items.firstOrNull { item ->
                try {
                    item.request()?.url() == entry.url && item.request()?.method() == entry.method
                } catch (_: Exception) { false }
            }
            if (match != null) {
                api.intruder().sendToIntruder(match.request())
            } else {
                api.logging().logToOutput("Intruder: no matching request found for ${entry.url}")
            }
        } catch (e: Exception) {
            api.logging().logToError("sendToIntruder: ${e.message}")
        }
    }

    fun exportToCsv(entries: List<TrafficEntry>, file: java.io.File) {
        file.bufferedWriter(Charsets.UTF_8).use { out ->
            out.write("ID,Method,Host,Path,URL,Status,MIME,ReqLen,RespLen,Params,IP\n")
            for (e in entries) {
                out.write(csvRow(
                    e.id, e.method, e.host, e.path, e.url,
                    e.statusCode.toString(), e.mimeType,
                    e.requestLength.toString(), e.responseLength.toString(),
                    e.params.joinToString(";"),
                    e.ip,
                ))
                out.write("\n")
            }
        }
    }

    private fun csvRow(vararg fields: String): String =
        fields.joinToString(",") { "\"${it.replace("\"", "\"\"")}\"" }

    private fun extractHost(url: String): String {
        return try {
            java.net.URL(url).host
        } catch (_: Exception) {
            url.substringAfter("://").substringBefore("/").substringBefore(":")
        }
    }

    private fun extractPath(url: String): String {
        return try {
            val u = java.net.URL(url)
            val q = if (u.query != null) "?${u.query}" else ""
            u.path + q
        } catch (_: Exception) {
            url.substringAfter("://").substringAfter("/").let { "/$it" }
        }
    }

    private fun extractParamNames(url: String, body: String, method: String): List<String> {
        val params = mutableListOf<String>()
        // Query params
        try {
            val query = java.net.URL(url).query ?: ""
            query.split("&").forEach { kv ->
                val k = kv.substringBefore("=").trim()
                if (k.isNotBlank()) params.add(k)
            }
        } catch (_: Exception) {}
        // Body params (form or JSON keys)
        if (method in listOf("POST", "PUT", "PATCH") && body.isNotBlank()) {
            if (body.trimStart().startsWith("{")) {
                // JSON — extract top-level keys
                val keyRe = Regex("\"(\\w+)\"\\s*:")
                keyRe.findAll(body).forEach { params.add(it.groupValues[1]) }
            } else {
                // URL-encoded form
                body.split("&").forEach { kv ->
                    val k = kv.substringBefore("=").trim()
                    if (k.isNotBlank()) params.add(k)
                }
            }
        }
        return params.distinct()
    }
}
