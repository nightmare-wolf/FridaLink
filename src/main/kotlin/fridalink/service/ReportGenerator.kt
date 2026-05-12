package fridalink.service

import fridalink.model.ApkFinding
import fridalink.model.FindingSeverity
import fridalink.model.GeoResult
import fridalink.model.MasvsItem
import fridalink.model.MasvsStatus
import fridalink.model.TrafficEntry
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.pdmodel.PDPage
import org.apache.pdfbox.pdmodel.PDPageContentStream
import org.apache.pdfbox.pdmodel.common.PDRectangle
import org.apache.pdfbox.pdmodel.font.PDType1Font
import org.apache.pdfbox.pdmodel.font.Standard14Fonts
import java.awt.Color
import java.io.File
import java.time.LocalDate
import java.time.format.DateTimeFormatter

/**
 * Generates a professional penetration test report in PDF format.
 *
 * Report sections:
 *  1. Cover page
 *  2. Engagement overview
 *  3. Executive summary
 *  4. Methodology
 *  5. Findings (Critical → Info with descriptions and mitigations)
 *  6. OWASP MASVS v2 checklist results
 *  7. Network traffic analysis
 *  8. Server geolocation analysis (non-US servers flagged in RED)
 *  9. Appendix
 */
class ReportGenerator {

    // ----------------------------------------------------------------
    // Layout constants
    // ----------------------------------------------------------------
    private val MARGIN      = 60f
    private val LINE_HEIGHT = 14f
    private val PAGE_WIDTH  = PDRectangle.LETTER.width
    private val PAGE_HEIGHT = PDRectangle.LETTER.height
    private val BODY_WIDTH  = PAGE_WIDTH - MARGIN * 2

    // Colors
    private val COLOR_COVER_BG    = Color(20,  30,  55)   // dark navy
    private val COLOR_HEADING     = Color(20,  30,  55)
    private val COLOR_CRITICAL    = Color(180, 0,   0)
    private val COLOR_HIGH        = Color(220, 50,  0)
    private val COLOR_MEDIUM      = Color(200, 120, 0)
    private val COLOR_LOW         = Color(50,  100, 160)
    private val COLOR_INFO        = Color(80,  80,  80)
    private val COLOR_FAIL_RED    = Color(200, 0,   0)
    private val COLOR_PASS_GREEN  = Color(0,   140, 60)
    private val COLOR_TABLE_HEAD  = Color(235, 238, 245)
    private val COLOR_WARN_RED    = Color(210, 0,   0)

    data class ReportConfig(
        val targetApp: String   = "Bleach: Brave Souls (com.crunchyroll.bleachsoulres)",
        val assessor: String    = "Luis Del Rio",
        val organization: String = "ISI (Internal Security Initiative)",
        val engagementId: String = "ISI-O-0196",
        val reportDate: String  = LocalDate.now().format(DateTimeFormatter.ofPattern("MMMM d, yyyy")),
        val classification: String = "CONFIDENTIAL — For Authorized Personnel Only",
        val scopeDescription: String = "Android mobile application — Bleach: Brave Souls (JP/Global), APK version captured April 2026.",
        val outputFile: File    = File(System.getProperty("user.home"), "FridaLink_Report_${System.currentTimeMillis()}.pdf"),
    )

    fun generate(
        config: ReportConfig,
        apkFindings: List<ApkFinding>,
        masvsItems: List<MasvsItem>,
        trafficEntries: List<TrafficEntry>,
        geoResults: Map<String, GeoResult>,
        onProgress: (String) -> Unit = {},
    ): File {
        val doc = PDDocument()

        onProgress("Generating cover page...")
        addCoverPage(doc, config)

        onProgress("Adding engagement overview...")
        addEngagementPage(doc, config)

        onProgress("Writing executive summary...")
        addExecutiveSummary(doc, config, apkFindings, masvsItems, geoResults)

        onProgress("Writing findings (${apkFindings.size})...")
        addFindingsSection(doc, apkFindings)

        onProgress("Writing MASVS checklist...")
        addMasvsSection(doc, masvsItems)

        onProgress("Writing network analysis...")
        addNetworkSection(doc, trafficEntries, geoResults)

        onProgress("Writing geolocation section...")
        addGeoSection(doc, geoResults)

        onProgress("Writing appendix...")
        addAppendix(doc, config, trafficEntries)

        onProgress("Saving PDF to ${config.outputFile.absolutePath}...")
        doc.save(config.outputFile)
        doc.close()
        onProgress("Report saved: ${config.outputFile.absolutePath}")
        return config.outputFile
    }

    // ----------------------------------------------------------------
    // Cover Page
    // ----------------------------------------------------------------
    private fun addCoverPage(doc: PDDocument, config: ReportConfig) {
        val page = PDPage(PDRectangle.LETTER)
        doc.addPage(page)
        PDPageContentStream(doc, page).use { cs ->
            // Background
            cs.setNonStrokingColor(COLOR_COVER_BG)
            cs.addRect(0f, 0f, PAGE_WIDTH, PAGE_HEIGHT)
            cs.fill()

            // Top accent bar
            cs.setNonStrokingColor(Color(200, 30, 30))
            cs.addRect(0f, PAGE_HEIGHT - 12f, PAGE_WIDTH, 12f)
            cs.fill()

            // Bottom accent bar
            cs.addRect(0f, 0f, PAGE_WIDTH, 12f)
            cs.fill()

            // Report type label
            cs.setNonStrokingColor(Color(200, 30, 30))
            drawText(cs, "MOBILE APPLICATION SECURITY ASSESSMENT", MARGIN, PAGE_HEIGHT - 80f,
                Standard14Fonts.FontName.HELVETICA_BOLD, 13f)

            // Title
            cs.setNonStrokingColor(Color.WHITE)
            drawText(cs, "Penetration Test Report", MARGIN, PAGE_HEIGHT - 130f,
                Standard14Fonts.FontName.HELVETICA_BOLD, 28f)
            drawText(cs, config.targetApp, MARGIN, PAGE_HEIGHT - 165f,
                Standard14Fonts.FontName.HELVETICA, 14f)

            // Divider
            cs.setStrokingColor(Color(200, 30, 30))
            cs.setLineWidth(2f)
            cs.moveTo(MARGIN, PAGE_HEIGHT - 185f)
            cs.lineTo(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 185f)
            cs.stroke()

            // Metadata block
            cs.setNonStrokingColor(Color(180, 200, 220))
            var y = PAGE_HEIGHT - 220f
            val metaItems = listOf(
                "Engagement ID" to config.engagementId,
                "Assessor"      to config.assessor,
                "Organization"  to config.organization,
                "Report Date"   to config.reportDate,
                "Classification" to config.classification,
            )
            for ((label, value) in metaItems) {
                drawText(cs, "$label:", MARGIN, y, Standard14Fonts.FontName.HELVETICA_BOLD, 11f)
                cs.setNonStrokingColor(Color.WHITE)
                drawText(cs, value, MARGIN + 130f, y, Standard14Fonts.FontName.HELVETICA, 11f)
                cs.setNonStrokingColor(Color(180, 200, 220))
                y -= LINE_HEIGHT + 4f
            }

            // Scope
            y -= 20f
            cs.setNonStrokingColor(Color(180, 200, 220))
            drawText(cs, "Scope:", MARGIN, y, Standard14Fonts.FontName.HELVETICA_BOLD, 11f)
            cs.setNonStrokingColor(Color.WHITE)
            y -= LINE_HEIGHT + 2f
            drawWrappedText(cs, config.scopeDescription, MARGIN, y,
                Standard14Fonts.FontName.HELVETICA, 10f, BODY_WIDTH)

            // Footer
            cs.setNonStrokingColor(Color(120, 140, 170))
            drawText(cs, "CONFIDENTIAL — Distribution limited to authorized personnel",
                MARGIN, 30f, Standard14Fonts.FontName.HELVETICA_OBLIQUE, 8f)
            drawText(cs, "FridaLink Assessment Platform — fridalink/1.0",
                PAGE_WIDTH - MARGIN - 180f, 30f, Standard14Fonts.FontName.HELVETICA_OBLIQUE, 8f)
        }
    }

    // ----------------------------------------------------------------
    // Engagement Overview
    // ----------------------------------------------------------------
    private fun addEngagementPage(doc: PDDocument, config: ReportConfig) {
        val writer = PageWriter(doc)
        writer.addHeading1("1. Engagement Overview")
        writer.addHeading2("1.1 Scope & Objectives")
        writer.addBody("""
This assessment was conducted against the mobile application: ${config.targetApp}.

Objectives:
  • Identify vulnerabilities that could allow unauthorized modification of game state
  • Map all network communication endpoints and assess data exposure
  • Evaluate adherence to OWASP MASVS v2 security controls
  • Assess resistance to dynamic instrumentation and code tampering
  • Document all findings with CVSS scores, OWASP references, and mitigations

Assessment Type:  Gray-Box Dynamic + Static Analysis
Platform:         Android
Tools Used:       Frida, Burp Suite Pro, FridaLink, tshark/Wireshark, MobSF, ADB
Engagement ID:    ${config.engagementId}
        """.trimIndent())

        writer.addHeading2("1.2 Methodology")
        writer.addBody("""
Phase 1 — Static Analysis
  APK decompilation and manifest review, permission analysis, string scanning for
  hardcoded secrets, URL extraction, native library identification.

Phase 2 — Dynamic Instrumentation
  Frida-based hooking of native libraries (libgame.so, libunity.so, libhades.so).
  SSL traffic interception at the TLS boundary. KCP protocol analysis. JNI tracing.

Phase 3 — Network Analysis
  Burp Suite proxy to capture all HTTP/HTTPS traffic. tshark packet capture.
  Server geolocation and jurisdiction analysis. CONNECT tunnel analysis.

Phase 4 — MASVS Evaluation
  Manual and automated evaluation of all applicable OWASP MASVS v2 controls.
        """.trimIndent())

        writer.addHeading2("1.3 Risk Rating")
        writer.addBody("""
Risk ratings follow the OWASP Risk Rating Methodology with CVSS v3.1 scores:

  CRITICAL  CVSS 9.0–10.0  Immediate risk of compromise
  HIGH      CVSS 7.0–8.9   Significant risk requiring prompt remediation
  MEDIUM    CVSS 4.0–6.9   Moderate risk; remediate in next release cycle
  LOW       CVSS 0.1–3.9   Minor risk; remediate in normal development cycle
  INFO      N/A            Informational; no direct security impact
        """.trimIndent())
        writer.save()
    }

    // ----------------------------------------------------------------
    // Executive Summary
    // ----------------------------------------------------------------
    private fun addExecutiveSummary(
        doc: PDDocument,
        config: ReportConfig,
        findings: List<ApkFinding>,
        masvsItems: List<MasvsItem>,
        geoResults: Map<String, GeoResult>,
    ) {
        val writer = PageWriter(doc)
        writer.addHeading1("2. Executive Summary")

        val critical = findings.count { it.severity == FindingSeverity.CRITICAL }
        val high     = findings.count { it.severity == FindingSeverity.HIGH }
        val medium   = findings.count { it.severity == FindingSeverity.MEDIUM }
        val low      = findings.count { it.severity == FindingSeverity.LOW }
        val info     = findings.count { it.severity == FindingSeverity.INFO }

        val failCount = masvsItems.count { it.status == MasvsStatus.FAIL }
        val passCount = masvsItems.count { it.status == MasvsStatus.PASS }

        val nonUsServers = geoResults.values.filter { !it.isUS && it.status == "success" && it.countryCode != "LO" }

        writer.addBody("""
Assessment of ${config.targetApp} identified ${findings.size} findings across ${findings.map { it.category }.distinct().size} categories.
The application presents significant security risks, particularly in network communication,
resilience, and server geography.

Finding Summary:
  CRITICAL : $critical
  HIGH     : $high
  MEDIUM   : $medium
  LOW      : $low
  INFO     : $info
  TOTAL    : ${findings.size}

OWASP MASVS v2 Results: $failCount controls FAIL, $passCount PASS, ${masvsItems.size - failCount - passCount} Not Tested
        """.trimIndent())

        if (nonUsServers.isNotEmpty()) {
            writer.addColoredBody("""
⚠ SERVER JURISDICTION ALERT ⚠
${nonUsServers.size} server(s) are hosted OUTSIDE the United States.
All data transmitted to these servers is subject to foreign jurisdiction laws and may
not be protected under US privacy frameworks (CCPA, etc.).

Non-US Servers:
${nonUsServers.joinToString("\n") { "  ${it.ip}  ${it.country} (${it.countryCode})  ${it.org}" }}
        """.trimIndent(), COLOR_WARN_RED)
        }

        writer.addBody("""
Key Findings:

1. Frida dynamic instrumentation succeeded without triggering any detection.
   The anti-tamper and anti-debug controls are ineffective.

2. All TLS connections are established by libunity.so using embedded BoringSSL/OpenSSL.
   SSL pinning, if implemented, can be bypassed via native hook injection.

3. Game protocol uses KCP (reliable UDP) over raw sockets for battle traffic.
   KCP payloads are not independently encrypted beyond TLS tunneling.

4. Multiple servers located in Japan (APJ Game infrastructure) and Singapore (CDN).
   These are outside US jurisdiction.

5. The Hades SDK (Alibaba) performs hot-patching via libhades.so, downloading and
   applying binary patches at runtime. This represents a code execution vector.
        """.trimIndent())
        writer.save()
    }

    // ----------------------------------------------------------------
    // Findings Section
    // ----------------------------------------------------------------
    private fun addFindingsSection(doc: PDDocument, findings: List<ApkFinding>) {
        val writer = PageWriter(doc)
        writer.addHeading1("3. Detailed Findings")

        val grouped = findings.groupBy { it.severity }
        var findingNum = 1

        for (severity in FindingSeverity.entries) {
            val group = grouped[severity] ?: continue
            for (f in group) {
                val color = severityColor(f.severity)
                val label = f.severity.name

                writer.addHeading2("Finding #${findingNum}: ${f.title}")
                writer.addColoredBody("Severity: $label   Category: ${f.category}   CVSS: ${f.cvssScore}", color)

                if (f.masvsRef.isNotBlank()) {
                    writer.addBody("MASVS Reference: ${f.masvsRef}   CWE: ${f.cweRef.ifBlank { "N/A" }}")
                }
                writer.addBody("")
                writer.addBody("Description:")
                writer.addBody(f.description)
                writer.addBody("")
                writer.addBody("Evidence:")
                writer.addBody(f.evidence.take(1000))
                writer.addBody("")
                writer.addColoredBody("Mitigation:", COLOR_HEADING)
                writer.addBody(f.mitigation)
                writer.addBody("─".repeat(60))
                findingNum++
            }
        }
        writer.save()
    }

    // ----------------------------------------------------------------
    // MASVS Section
    // ----------------------------------------------------------------
    private fun addMasvsSection(doc: PDDocument, items: List<MasvsItem>) {
        val writer = PageWriter(doc)
        writer.addHeading1("4. OWASP MASVS v2 Checklist")
        writer.addBody("Assessment results for all applicable OWASP MASVS v2 controls.\n")

        val grouped = items.groupBy { it.category }
        for ((category, controls) in grouped) {
            writer.addHeading2(category)
            for (item in controls) {
                val statusStr = item.status.name.replace("_", " ")
                val statusColor = when (item.status) {
                    MasvsStatus.PASS           -> COLOR_PASS_GREEN
                    MasvsStatus.FAIL           -> COLOR_FAIL_RED
                    MasvsStatus.NOT_APPLICABLE -> COLOR_INFO
                    MasvsStatus.NOT_TESTED     -> Color(100, 100, 100)
                }
                writer.addColoredBody("[${item.id}] ${item.control} — $statusStr  [${item.level}]", statusColor)
                if (item.evidence.isNotBlank()) {
                    writer.addBody("  Evidence: ${item.evidence.take(200)}")
                }
                if (item.notes.isNotBlank()) {
                    writer.addBody("  Notes: ${item.notes.take(200)}")
                }
            }
            writer.addBody("")
        }
        writer.save()
    }

    // ----------------------------------------------------------------
    // Network Analysis Section
    // ----------------------------------------------------------------
    private fun addNetworkSection(
        doc: PDDocument,
        entries: List<TrafficEntry>,
        geoResults: Map<String, GeoResult>,
    ) {
        val writer = PageWriter(doc)
        writer.addHeading1("5. Network Traffic Analysis")

        val hosts = entries.map { it.host }.distinct().sorted()
        writer.addBody("Unique hosts observed: ${hosts.size}")
        writer.addBody("Total requests captured: ${entries.size}\n")
        writer.addBody("Observed Hosts:")
        for (host in hosts.take(50)) {
            val geo = geoResults.values.firstOrNull { it.ip.contains(host) || host.contains(it.ip) }
            val geoNote = if (geo != null) "  [${geo.country}, ${geo.countryCode}]" else ""
            writer.addBody("  $host$geoNote")
        }

        writer.addBody("")
        writer.addHeading2("Notable Endpoints")

        val interesting = entries.filter { e ->
            e.path.contains("api", ignoreCase = true) ||
            e.path.contains("battle") ||
            e.path.contains("reward") ||
            e.path.contains("auth") ||
            e.path.contains("login") ||
            e.statusCode in 400..599
        }.take(30)

        for (e in interesting) {
            writer.addBody("${e.method} ${e.url.take(120)}")
            if (e.statusCode > 0) writer.addBody("  → HTTP ${e.statusCode}  ${e.mimeType}")
            if (e.params.isNotEmpty()) writer.addBody("  Parameters: ${e.params.joinToString(", ")}")
        }

        writer.save()
    }

    // ----------------------------------------------------------------
    // Geolocation Section
    // ----------------------------------------------------------------
    private fun addGeoSection(doc: PDDocument, geoResults: Map<String, GeoResult>) {
        val writer = PageWriter(doc)
        writer.addHeading1("6. Server Geolocation Analysis")

        val results = geoResults.values.filter { it.status == "success" }
        val nonUs   = results.filter { !it.isUS && it.countryCode != "LO" }
        val usOnly  = results.filter { it.isUS }

        if (nonUs.isNotEmpty()) {
            writer.addColoredBody("⚠ WARNING: ${nonUs.size} SERVER(S) HOSTED OUTSIDE THE UNITED STATES ⚠", COLOR_WARN_RED)
            writer.addColoredBody("""
The following servers are located in foreign jurisdictions. Any data processed by or
transmitted to these servers may be subject to laws of those countries, including
potential government access requirements, data retention mandates, and privacy regulations
that differ from US standards.

This should be disclosed in the application's privacy policy. Depending on the data types
involved, this may trigger CCPA, GDPR, or other compliance obligations.
            """.trimIndent(), COLOR_WARN_RED)
            writer.addBody("")
            writer.addBody("Non-US Servers:")
            for (r in nonUs) {
                writer.addColoredBody(
                    "  IP: ${r.ip.padEnd(16)} Country: ${r.country.padEnd(25)} (${r.countryCode})  City: ${r.city}  ISP/Org: ${r.org.take(40)}",
                    COLOR_WARN_RED
                )
            }
        }

        if (usOnly.isNotEmpty()) {
            writer.addBody("")
            writer.addBody("US-Based Servers (${usOnly.size}):")
            for (r in usOnly) {
                writer.addBody("  IP: ${r.ip.padEnd(16)} City: ${r.city}, ${r.regionName}  ISP: ${r.isp.take(40)}")
            }
        }

        writer.addBody("")
        writer.addHeading2("Recommendations")
        writer.addBody("""
1. Disclose in the app's privacy policy that user data is processed on servers in:
   ${(nonUs.map { it.country }.distinct().joinToString(", ").ifBlank { "N/A" })}

2. Evaluate whether the data transmitted to non-US servers is subject to CCPA/GDPR.

3. Consider requiring data residency agreements with the hosting providers in those
   countries if handling EU or California users' personal data.

4. Audit what specific data is transmitted to each foreign-hosted endpoint.
        """.trimIndent())
        writer.save()
    }

    // ----------------------------------------------------------------
    // Appendix
    // ----------------------------------------------------------------
    private fun addAppendix(doc: PDDocument, config: ReportConfig, entries: List<TrafficEntry>) {
        val writer = PageWriter(doc)
        writer.addHeading1("Appendix A — Captured URLs")
        writer.addBody("All unique URLs captured during the assessment session:\n")

        val urls = entries.map { "${it.method} ${it.url}" }.distinct().sorted()
        for (url in urls.take(200)) {
            writer.addBody(url.take(120))
        }
        if (urls.size > 200) writer.addBody("... and ${urls.size - 200} more (see exported CSV)")

        writer.addBody("")
        writer.addHeading1("Appendix B — References")
        writer.addBody("""
OWASP Mobile Application Security Verification Standard (MASVS) v2
https://mas.owasp.org/MASVS/

OWASP Mobile Application Security Testing Guide (MASTG)
https://mas.owasp.org/MASTG/

NIST Mobile Device Security — SP 800-124r2
Android Security Architecture
https://source.android.com/security

Frida Dynamic Instrumentation Framework
https://frida.re

This report was generated by FridaLink v1.0 — ${config.reportDate}
Engagement: ${config.engagementId}
        """.trimIndent())
        writer.save()
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private fun severityColor(s: FindingSeverity) = when (s) {
        FindingSeverity.CRITICAL -> COLOR_CRITICAL
        FindingSeverity.HIGH     -> COLOR_HIGH
        FindingSeverity.MEDIUM   -> COLOR_MEDIUM
        FindingSeverity.LOW      -> COLOR_LOW
        FindingSeverity.INFO     -> COLOR_INFO
    }

    private fun drawText(
        cs: PDPageContentStream, text: String, x: Float, y: Float,
        fontName: Standard14Fonts.FontName, size: Float,
    ) {
        cs.beginText()
        cs.setFont(PDType1Font(fontName), size)
        cs.newLineAtOffset(x, y)
        cs.showText(sanitize(text))
        cs.endText()
    }

    private fun drawWrappedText(
        cs: PDPageContentStream, text: String, x: Float, startY: Float,
        fontName: Standard14Fonts.FontName, size: Float, maxWidth: Float,
    ): Float {
        val font = PDType1Font(fontName)
        val words = text.split(" ")
        var line = StringBuilder()
        var y = startY
        for (word in words) {
            val test = if (line.isEmpty()) word else "$line $word"
            val w = font.getStringWidth(sanitize(test)) / 1000f * size
            if (w > maxWidth && line.isNotEmpty()) {
                drawText(cs, line.toString(), x, y, fontName, size)
                y -= (size + 2f)
                line = StringBuilder(word)
            } else {
                line = StringBuilder(test)
            }
        }
        if (line.isNotEmpty()) {
            drawText(cs, line.toString(), x, y, fontName, size)
            y -= (size + 2f)
        }
        return y
    }

    /** Remove non-WinAnsi characters from text for PDFBox compatibility */
    private fun sanitize(text: String): String =
        text.map { c -> if (c.code in 32..255 && c != '\n' && c != '\r') c else '?' }.joinToString("")

    // ----------------------------------------------------------------
    // PageWriter — manages multi-page content with auto page breaks
    // ----------------------------------------------------------------
    inner class PageWriter(private val doc: PDDocument) {
        private var currentPage: PDPage = PDPage(PDRectangle.LETTER)
        private var cs: PDPageContentStream
        private var y: Float = PAGE_HEIGHT - MARGIN
        private val pages = mutableListOf<Pair<PDPage, PDPageContentStream>>()
        private var pageNum = 1

        init {
            doc.addPage(currentPage)
            cs = PDPageContentStream(doc, currentPage)
            drawPageHeader()
            drawPageFooter()
        }

        private fun drawPageHeader() {
            cs.setNonStrokingColor(Color(20, 30, 55))
            cs.addRect(0f, PAGE_HEIGHT - 30f, PAGE_WIDTH, 30f)
            cs.fill()
            cs.setNonStrokingColor(Color.WHITE)
            beginText(cs, "CONFIDENTIAL  |  ISI-O-0196 Mobile Assessment", MARGIN, PAGE_HEIGHT - 18f,
                Standard14Fonts.FontName.HELVETICA, 8f)
            beginText(cs, "FridaLink Report", PAGE_WIDTH - MARGIN - 80f, PAGE_HEIGHT - 18f,
                Standard14Fonts.FontName.HELVETICA, 8f)
            y = PAGE_HEIGHT - 50f
        }

        private fun drawPageFooter() {
            cs.setStrokingColor(Color(180, 180, 180))
            cs.setLineWidth(0.5f)
            cs.moveTo(MARGIN, 35f)
            cs.lineTo(PAGE_WIDTH - MARGIN, 35f)
            cs.stroke()
            cs.setNonStrokingColor(Color(100, 100, 100))
            beginText(cs, "Page $pageNum", PAGE_WIDTH / 2 - 15f, 20f, Standard14Fonts.FontName.HELVETICA, 8f)
        }

        private fun beginText(cs: PDPageContentStream, text: String, x: Float, y: Float,
                               fontName: Standard14Fonts.FontName, size: Float) {
            cs.beginText()
            cs.setFont(PDType1Font(fontName), size)
            cs.newLineAtOffset(x, y)
            cs.showText(sanitize(text))
            cs.endText()
        }

        private fun newPage() {
            cs.close()
            currentPage = PDPage(PDRectangle.LETTER)
            doc.addPage(currentPage)
            cs = PDPageContentStream(doc, currentPage)
            pageNum++
            drawPageHeader()
            drawPageFooter()
        }

        private fun ensureSpace(needed: Float = LINE_HEIGHT + 4f) {
            if (y - needed < 50f) newPage()
        }

        fun addHeading1(text: String) {
            ensureSpace(40f)
            y -= 20f
            cs.setNonStrokingColor(COLOR_HEADING)
            cs.addRect(MARGIN - 4f, y - 4f, BODY_WIDTH + 8f, LINE_HEIGHT + 10f)
            cs.fill()
            cs.setNonStrokingColor(Color.WHITE)
            beginText(cs, text, MARGIN, y + 2f, Standard14Fonts.FontName.HELVETICA_BOLD, 13f)
            cs.setNonStrokingColor(Color.BLACK)
            y -= LINE_HEIGHT + 16f
        }

        fun addHeading2(text: String) {
            ensureSpace(30f)
            y -= 10f
            cs.setNonStrokingColor(Color(200, 30, 30))
            cs.setLineWidth(2f)
            cs.moveTo(MARGIN, y + LINE_HEIGHT)
            cs.lineTo(MARGIN + BODY_WIDTH, y + LINE_HEIGHT)
            cs.stroke()
            cs.setNonStrokingColor(COLOR_HEADING)
            beginText(cs, text, MARGIN, y, Standard14Fonts.FontName.HELVETICA_BOLD, 11f)
            y -= LINE_HEIGHT + 8f
        }

        fun addBody(text: String) {
            val lines = text.split("\n")
            for (line in lines) {
                ensureSpace(LINE_HEIGHT + 2f)
                cs.setNonStrokingColor(Color.BLACK)
                beginText(cs, line.take(120), MARGIN, y, Standard14Fonts.FontName.HELVETICA, 9f)
                y -= LINE_HEIGHT
            }
        }

        fun addColoredBody(text: String, color: Color) {
            val lines = text.split("\n")
            for (line in lines) {
                ensureSpace(LINE_HEIGHT + 2f)
                cs.setNonStrokingColor(color)
                beginText(cs, line.take(120), MARGIN, y, Standard14Fonts.FontName.HELVETICA_BOLD, 9f)
                y -= LINE_HEIGHT
            }
            cs.setNonStrokingColor(Color.BLACK)
        }

        fun save() {
            cs.close()
        }
    }
}
