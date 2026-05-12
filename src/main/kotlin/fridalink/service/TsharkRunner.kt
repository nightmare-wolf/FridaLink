package fridalink.service

import fridalink.model.TrafficEntry
import java.io.File
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Launches tshark (Wireshark CLI) to capture packets in real-time.
 * Extracts HTTP hosts, methods, URIs and builds TrafficEntry objects.
 *
 * On Windows, tshark is typically at:
 *   C:\Program Files\Wireshark\tshark.exe
 *
 * The capture is written to a pcap file and can also be exported as CSV.
 *
 * tshark fields captured:
 *   frame.time_epoch, ip.src, ip.dst, tcp.srcport, tcp.dstport,
 *   http.host, http.request.method, http.request.uri,
 *   http.response.code, http.content_type, http.content_length
 */
class TsharkRunner {

    private var process: Process? = null
    private val running = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()
    val capturedEntries = CopyOnWriteArrayList<TrafficEntry>()
    var pcapFile: File? = null

    fun isRunning(): Boolean = running.get()

    fun listInterfaces(tsharkPath: String = detectTsharkPath()): List<String> {
        return try {
            val proc = ProcessBuilder(tsharkPath, "-D")
                .redirectErrorStream(true)
                .start()
            proc.inputStream.bufferedReader().readLines()
                .map { it.trim() }
                .filter { it.isNotBlank() }
        } catch (e: Exception) {
            listOf("ERROR: ${e.message}")
        }
    }

    /**
     * Start tshark capture.
     * @param iface     network interface name or index (e.g. "Wi-Fi" or "1")
     * @param outDir    directory to write pcap and CSV
     * @param filter    capture filter (e.g. "host 192.168.86.14")
     * @param onEntry   called when a new HTTP entry is extracted
     * @param onLine    called for raw tshark output lines
     */
    fun start(
        iface: String,
        outDir: File,
        filter: String = "",
        tsharkPath: String = detectTsharkPath(),
        onEntry: (TrafficEntry) -> Unit = {},
        onLine: (String) -> Unit = {},
    ) {
        if (running.get()) return
        running.set(true)
        capturedEntries.clear()
        outDir.mkdirs()

        val timestamp = System.currentTimeMillis()
        pcapFile = File(outDir, "fridalink_capture_$timestamp.pcap")

        // tshark command: capture to pcap AND print HTTP fields in parallel
        // We use two separate tshark instances: one for pcap, one for field extraction
        val args = mutableListOf(
            tsharkPath,
            "-i", iface,
            "-w", pcapFile!!.absolutePath,   // write pcap
            "-P",                            // print packets while writing
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=y",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "http.host",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.response.code",
            "-e", "http.content_type",
            "-e", "http.request.full_uri",
            "-e", "http.file_data",
        )
        if (filter.isNotBlank()) {
            args += listOf("-f", filter)
        }

        onLine("[tshark] Starting capture on interface '$iface'")
        onLine("[tshark] Writing to: ${pcapFile!!.absolutePath}")
        onLine("[tshark] Command: ${args.joinToString(" ")}")

        try {
            val pb = ProcessBuilder(args)
            pb.redirectErrorStream(true)
            process = pb.start()

            executor.submit {
                var headerParsed = false
                try {
                    process!!.inputStream.bufferedReader().use { reader ->
                        reader.lines().forEach { line ->
                            onLine(line)
                            if (!headerParsed) {
                                headerParsed = true  // skip header row
                                return@forEach
                            }
                            parseFieldLine(line)?.let { entry ->
                                capturedEntries.add(entry)
                                onEntry(entry)
                            }
                        }
                    }
                } catch (_: Exception) {}
                running.set(false)
                onLine("[tshark] Capture stopped. Total HTTP entries: ${capturedEntries.size}")
            }
        } catch (e: Exception) {
            running.set(false)
            onLine("[tshark] ERROR: ${e.message}")
            onLine("[tshark] Make sure Wireshark/tshark is installed and on PATH")
            onLine("[tshark] Detected path: $tsharkPath")
        }
    }

    fun stop() {
        running.set(false)
        try { process?.destroyForcibly() } catch (_: Exception) {}
        process = null
    }

    fun exportCsv(file: File) {
        file.bufferedWriter(Charsets.UTF_8).use { out ->
            out.write("Method,Host,Path,URL,StatusCode,IP,MimeType\n")
            for (e in capturedEntries) {
                out.write("\"${e.method}\",\"${e.host}\",\"${e.path}\",\"${e.url}\",\"${e.statusCode}\",\"${e.ip}\",\"${e.mimeType}\"\n")
            }
        }
    }

    private fun parseFieldLine(line: String): TrafficEntry? {
        val parts = line.split("|")
        if (parts.size < 7) return null
        val ipSrc     = parts.getOrElse(1) { "" }.trim()
        val ipDst     = parts.getOrElse(2) { "" }.trim()
        val host      = parts.getOrElse(4) { "" }.trim()
        val method    = parts.getOrElse(5) { "" }.trim()
        val uri       = parts.getOrElse(6) { "" }.trim()
        val respCode  = parts.getOrElse(7) { "" }.trim().toIntOrNull() ?: 0
        val mime      = parts.getOrElse(8) { "" }.trim()
        val fullUri   = parts.getOrElse(9) { "" }.trim()

        // Only build entries for HTTP requests (have method and host)
        if (method.isBlank() && host.isBlank() && respCode == 0) return null

        val url = if (fullUri.isNotBlank()) fullUri
                  else if (host.isNotBlank() && uri.isNotBlank()) "http://$host$uri"
                  else return null

        return TrafficEntry(
            id             = UUID.randomUUID().toString(),
            method         = method.ifBlank { if (respCode > 0) "RESPONSE" else "?" },
            host           = host.ifBlank { ipDst },
            url            = url,
            path           = uri.ifBlank { "/" },
            statusCode     = respCode,
            mimeType       = mime,
            requestLength  = 0,
            responseLength = 0,
            params         = emptyList(),
            requestHeaders = "",
            requestBody    = "",
            responseHeaders = "",
            responseBody   = "",
            ip             = ipSrc,
        )
    }

    fun detectTsharkPath(): String {
        // Windows
        val winPaths = listOf(
            """C:\Program Files\Wireshark\tshark.exe""",
            """C:\Program Files (x86)\Wireshark\tshark.exe""",
        )
        for (p in winPaths) {
            if (File(p).exists()) return p
        }
        // Linux/Mac
        return "tshark"
    }
}
