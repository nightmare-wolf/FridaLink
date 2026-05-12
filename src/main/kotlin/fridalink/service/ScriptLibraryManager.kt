package fridalink.service

import fridalink.model.LibraryScript
import java.io.File

/**
 * Scans a directory tree for .js files and returns them as [LibraryScript] entries.
 *
 * Script metadata is read from leading comment annotations:
 *   // @name    Human-readable name
 *   // @category  http | java | webview | native | helper | ...
 *   // @description Short description
 *   // @version  1.0
 *
 * If a tag is absent the value is derived from the filename or parent directory.
 */
class ScriptLibraryManager {

    fun loadFromDirectory(dir: File): List<LibraryScript> {
        if (!dir.exists() || !dir.isDirectory) return emptyList()
        return dir.walkTopDown()
            .filter { it.isFile && it.extension == "js" }
            .map { file -> parseScriptFile(file) }
            .sortedWith(compareBy({ it.category.lowercase() }, { it.name.lowercase() }))
            .toList()
    }

    private fun parseScriptFile(file: File): LibraryScript {
        val content = try {
            file.readText(Charsets.UTF_8)
        } catch (e: Exception) {
            "// failed to read: ${e.message}"
        }
        val meta = parseMetadata(content)
        val category = meta["category"]
            ?: file.parentFile?.name?.takeIf { it != "scripts" }
            ?: "general"
        return LibraryScript(
            id = "lib:${file.nameWithoutExtension}:${file.absolutePath.hashCode()}",
            name = meta["name"] ?: file.nameWithoutExtension,
            category = category,
            description = meta["description"] ?: "",
            version = meta["version"] ?: "1.0",
            path = file.absolutePath,
            content = content,
        )
    }

    private fun parseMetadata(content: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val pattern = Regex("""^//\s*@(\w+)\s+(.+)$""", RegexOption.MULTILINE)
        pattern.findAll(content).forEach { match ->
            result[match.groupValues[1]] = match.groupValues[2].trim()
        }
        return result
    }
}
