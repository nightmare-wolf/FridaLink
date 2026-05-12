package fridalink.service

import java.io.File
import java.util.concurrent.Executors

class SidecarProcessManager {
    private var process: Process? = null
    private val executor = Executors.newSingleThreadExecutor()

    fun isRunning(): Boolean = process?.isAlive == true

    fun start(pythonExecutable: String, projectRoot: File, onOutput: (String) -> Unit, onExit: (Int) -> Unit) {
        stop()
        val pythonDir = File(projectRoot, "python")
        val modulePath = File(pythonDir, "src")
        val command = mutableListOf(
            pythonExecutable,
            "-m",
            "fridalink_sidecar.app",
        )
        val builder = ProcessBuilder(command)
            .directory(pythonDir)
            .redirectErrorStream(true)
        builder.environment()["PYTHONPATH"] = modulePath.absolutePath
        process = builder.start()
        val running = process ?: return
        executor.submit {
            running.inputStream.bufferedReader().useLines { lines ->
                lines.forEach(onOutput)
            }
            val exitCode = running.waitFor()
            onExit(exitCode)
        }
    }

    fun stop() {
        process?.destroy()
        process = null
    }
}
