package fridalink.service

import java.io.File
import java.io.FileWriter
import java.io.PrintWriter

/**
 * Writes incoming events as JSON Lines (one object per line) to a rolling file.
 * Events are buffered in memory and flushed to disk every [BATCH_SIZE] events,
 * preventing excessive I/O on high-volume Frida sessions.  Remaining buffered
 * events are flushed immediately when [stop] is called.
 *
 * Rotates to a new file when the current one reaches [maxBytes] (default 1 GB).
 * File naming: baseName.jsonl, baseName_1.jsonl, baseName_2.jsonl, ...
 *
 * Thread-safe: all methods are synchronized.
 */
class EventExporter {
    var enabled: Boolean = false
        private set

    private val lock = Any()
    private val maxBytes: Long = 1_000_000_000L   // 1 GB
    private val BATCH_SIZE = 10_000

    private var dir: File? = null
    private var baseName: String = "fridalink_events"
    private var rotationIndex: Int = 0
    private var writer: PrintWriter? = null
    private var currentFile: File? = null
    private var currentSize: Long = 0L
    private var totalEvents: Long = 0L
    private val buffer = ArrayList<String>(BATCH_SIZE + 1)

    /** Start exporting to [dir]/[baseName].jsonl.  Closes any previous session. */
    fun configure(dir: File, baseName: String) {
        synchronized(lock) {
            flushBuffer()
            closeWriter()
            this.dir = dir
            this.baseName = baseName.ifBlank { "fridalink_events" }
            this.rotationIndex = 0
            this.totalEvents = 0L
            buffer.clear()
            openNext()
            enabled = true
        }
    }

    /** Flush any buffered events to disk and close the file. */
    fun stop() {
        synchronized(lock) {
            enabled = false
            flushBuffer()
            closeWriter()
        }
    }

    /**
     * Buffer a single JSON event.  Every [BATCH_SIZE] events the buffer is
     * flushed to disk in one batch.  No-op if export is not enabled.
     */
    fun writeEvent(json: String) {
        if (!enabled) return
        synchronized(lock) {
            buffer.add(json)
            if (buffer.size >= BATCH_SIZE) flushBuffer()
        }
    }

    fun statusLine(): String {
        synchronized(lock) {
            if (!enabled) return "Export disabled"
            val mb = currentSize / (1024 * 1024)
            val buffered = buffer.size
            return "→ ${currentFile?.name ?: "?"} | ${mb} MB | $totalEvents written | $buffered buffered"
        }
    }

    private fun flushBuffer() {
        if (buffer.isEmpty()) return
        try {
            for (json in buffer) {
                if (currentSize >= maxBytes) {
                    writer?.flush()
                    closeWriter()
                    rotationIndex++
                    openNext()
                }
                writer?.println(json)
                currentSize += json.length.toLong() + 1
                totalEvents++
            }
            writer?.flush()
        } catch (_: Exception) { }
        buffer.clear()
    }

    private fun openNext() {
        val d = dir ?: return
        if (!d.exists()) d.mkdirs()
        val name = if (rotationIndex == 0) "$baseName.jsonl" else "${baseName}_$rotationIndex.jsonl"
        val f = File(d, name)
        currentFile = f
        writer = PrintWriter(FileWriter(f, /* append= */ true))
        currentSize = f.length()
    }

    private fun closeWriter() {
        try { writer?.flush(); writer?.close() } catch (_: Exception) { }
        writer = null
    }
}
