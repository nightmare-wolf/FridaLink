package fridalink.ui

import burp.api.montoya.logging.Logging
import fridalink.model.CustomScript
import fridalink.model.FridaLinkState
import fridalink.model.InterceptItem
import fridalink.model.LibraryScript
import fridalink.model.MatchReplaceRule
import fridalink.model.ReplEntry
import fridalink.model.RuntimeEvent
import fridalink.service.FridaLinkController
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.JTextPane
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.event.ListSelectionEvent
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

class FridaLinkTab(
    private val controller: FridaLinkController,
    private val logging: Logging,
) {
    val root: JComponent

    // --- table models ---
    private val processTableModel = ProcessTableModel()
    private val eventTableModel = FilteredEventTableModel()
    private val interceptTableModel = InterceptTableModel()
    private val scriptListModel = DefaultListModel<CustomScript>()
    private val libraryListModel = DefaultListModel<LibraryScript>()

    // --- tables / lists ---
    private val processTable = JTable(processTableModel)
    private val eventTable = JTable(eventTableModel)
    private val interceptTable = JTable(interceptTableModel)
    private val scriptList = JList(scriptListModel)
    private val libraryList = JList(libraryListModel)

    // --- status bar labels ---
    private val statusLabel = JLabel("Disconnected", SwingConstants.LEFT)
    private val selectionLabel = JLabel("Selected: none", SwingConstants.LEFT)
    private val sessionLabel = JLabel("No FridaLink session", SwingConstants.LEFT)

    // --- toolbar fields (user types here — never touched by render) ---
    private val hostField = JTextField("127.0.0.1", 12)
    private val portField = JTextField("7766", 6)
    private val pythonField = JTextField("python", 18)
    private val projectRootField = JTextField(System.getProperty("user.dir"), 30)
    private val spawnField = JTextField("com.crunchyroll.bleachsoulres", 30)

    // --- custom script editor fields ---
    private val scriptName = JTextField()
    private val scriptLanguage = JComboBox(arrayOf("javascript", "python", "typescript"))
    private val scriptDescription = JTextField()
    private val scriptContent = JTextArea()

    // --- read-only display areas ---
    private val rawEventText = JTextArea()
    private val eventDetailsText = JTextArea()
    private val sidecarLogText = JTextArea()

    // --- intercept editing (editable, so protected from render stomping) ---
    private val interceptPayloadText = JTextArea()

    // --- library panel ---
    private val libraryPathField = JTextField(System.getProperty("user.dir") + "/scripts", 30)
    private val libraryMetaText = JTextArea()
    private val libraryContentText = JTextArea()
    private val libraryStatusLabel = JLabel("No library loaded")

    // --- event filter controls ---
    private val eventFilterText = JTextField(16)
    private val eventFilterCategory = JComboBox<String>(arrayOf("All"))
    private val eventFilterProcess = JComboBox<String>(arrayOf("All"))
    private val eventFilterModule = JTextField(12)
    private val eventFilterTarget = JTextField(14)
    private val showErrorsOnly = JCheckBox("Errors only")
    private val showBookmarkedOnly = JCheckBox("Bookmarked")

    // --- scroll lock ---
    private var scrollLocked = false
    private var lockedViewPos: java.awt.Point? = null   // position captured when lock is toggled ON
    private val scrollLockButton = JButton("⏸ Scroll Lock")
    private lateinit var eventScrollPane: JScrollPane

    // --- export controls ---
    private val exportDirField = JTextField(28)
    private val exportFileField = JTextField("fridalink_events", 18)
    private val exportStatusLabel = JLabel("Export disabled")
    private val exportEnabled = JCheckBox("Export to file")

    // --- match & replace ---
    private val matchReplaceTableModel = MatchReplaceTableModel(onEdit = { controller.updateMatchReplaceRule(it) })
    private val matchReplaceTable = JTable(matchReplaceTableModel)
    private val mrStatusLabel = JLabel("No rules defined")

    // --- new feature tab models + components (MUST be before init block) ---
    private val trafficTableModel  = TrafficTableModel()
    private val trafficTable       = JTable(trafficTableModel)
    private val trafficDetailText  = JTextArea()
    private val trafficStatusLabel = JLabel("No traffic loaded")
    private val trafficFilterField = JTextField(20)

    private val masvsTableModel  = MasvsTableModel()
    private val masvsTable       = JTable(masvsTableModel)
    private val masvsDetailText  = JTextArea()
    private val masvsStatusLabel = JLabel("Checklist not loaded")

    private val findingsTableModel  = FindingsTableModel()
    private val findingsTable       = JTable(findingsTableModel)
    private val findingDetailText   = JTextArea()
    private val apkPathField        = JTextField(40)
    private val decompSrcField      = JTextField(40)
    private val staticStatusLabel   = JLabel("No APK analyzed")
    // Static analysis subtab components
    private val certInfoText        = JTextArea().also { it.isEditable = false; it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11) }
    private val behaviorProfileText = JTextArea().also { it.isEditable = false; it.lineWrap = true; it.wrapStyleWord = true; it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11) }
    private val urlTableModel       = UrlRefTableModel()
    private val urlTable            = JTable(urlTableModel)
    private val libraryTableModel   = LibraryTableModel()
    private val libraryTable        = JTable(libraryTableModel)
    private val libraryDetailText   = JTextArea().also {
        it.isEditable = false; it.lineWrap = true; it.wrapStyleWord = true
        it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)
        it.text = "Select a library row to see verbose details."
    }
    private val extractLibBtn       = JButton("Extract from APK").also { it.isEnabled = false }

    private val geoTableModel      = GeoTableModel()
    private val geoTable           = JTable(geoTableModel)
    private val worldMapPanel      = WorldMapPanel()
    private val geoStatusLabel     = JLabel("No geolocation data")
    private val foreignTrafficText = JTextArea().also {
        it.isEditable = false; it.lineWrap = true; it.wrapStyleWord = true
        it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 10)
        it.text = "Click 'Analyze Foreign Traffic' after geolocating to see a summary\nof servers outside the US and known tracker/data-broker domains."
    }

    private val fridaTraceOutput    = JTextArea()
    private val fridaTargetField    = JTextField("com.crunchyroll.bleachsoulres", 30)
    private val fridaIncludeField   = JTextField("SSL_*,ikcp_*,GameStart,GameEnd", 30)
    private val fridaExcludeField   = JTextField("malloc,free", 20)
    private val fridaWorkDirField   = JTextField(System.getProperty("user.dir"), 25)

    private val reportTargetField     = JTextField("Bleach: Brave Souls (com.crunchyroll.bleachsoulres)", 40)
    private val reportAssessorField   = JTextField("Luis Del Rio", 20)
    private val reportEngagementField = JTextField("ISI-O-0196", 15)
    private val reportOutputField     = JTextField(System.getProperty("user.home") + "/FridaLink_Report.pdf", 35)
    private val reportStatusArea      = JTextArea()

    // --- ADB integration ---
    private val hostEnvLabel    = JLabel("Host OS: detecting...")
    private val adbStatusLabel  = JLabel("ADB not checked")
    private val adbPkgField     = JTextField("com.crunchyroll.bleachsoulres", 28)
    private val adbDeviceCombo  = JComboBox<String>(arrayOf("(auto – USB preferred)"))  // populated on Check ADB
    private val adbRawResultsText = JTextArea().also {
        it.isEditable = false; it.lineWrap = false
        it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)
        it.text = "Run ADB Checks to see raw device results here."
    }

    // --- RPC Console ---
    private val rpcResultText = JTextArea().also {
        it.isEditable = false
        it.lineWrap   = true
        it.wrapStyleWord = true
        it.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)
        it.text = "RPC results appear here after calling a method.\n" +
                  "Load 'Lua + IL2CPP + Network Inspector' from the Script Library first."
    }
    private val rpcMethodField  = JTextField("status", 20)
    private val rpcArgsField    = JTextField("", 30)
    private val rpcStatusLabel  = JLabel("No RPC calls dispatched yet")
    private var lastRpcResultCount = 0

    // --- Frida REPL ---
    private val replOutputPane = JTextPane().also {
        it.isEditable  = false
        it.background  = Color(20, 20, 20)
        it.foreground  = Color(204, 204, 204)
        it.caretColor  = Color(204, 204, 204)
        it.font        = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12)
        it.border      = BorderFactory.createEmptyBorder(6, 8, 6, 8)
    }
    private val replInputField = JTextField().also {
        it.font        = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12)
        it.background  = Color(30, 30, 30)
        it.foreground  = Color(204, 255, 153)
        it.caretColor  = Color(204, 255, 153)
        it.border      = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(80, 80, 80)),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)
        )
    }
    private val replCommandHistory = mutableListOf<String>()
    private var replHistoryIndex   = -1
    private var lastReplHistorySize = 0

    // -----------------------------------------------------------------------
    // Sync-suppression flags
    //
    // PROBLEM: render() is called every 200 ms by the publish timer.  Several
    // render steps call setSelectionInterval / scriptListModel.clear which
    // fire selection-changed events.  Those listeners call the controller,
    // which marks state dirty, scheduling another render — a tight loop that
    // also clears text fields the user is typing in.
    //
    // FIX: set suppressSync = true around any programmatic selection change so
    // the listeners can tell the difference between "user clicked" and
    // "render is syncing".  Never call controller from inside a sync guard.
    // -----------------------------------------------------------------------
    private var suppressSync = false

    // Similarly, rebuilding scriptListModel fires its own list-selection event
    // which calls populateScriptEditor and resets the editor fields.
    private var syncingScriptList = false

    // Track what was last rendered so we skip rebuilds when nothing changed.
    private var lastRenderedScriptSigs: List<String> = emptyList()
    private var lastRenderedLibrarySigs: List<String> = emptyList()

    init {
        root = JPanel(BorderLayout())
        root.preferredSize = Dimension(1440, 900)
        root.add(buildToolbar(), BorderLayout.NORTH)
        root.add(buildMainSplit(), BorderLayout.CENTER)
        root.add(buildStatusBar(), BorderLayout.SOUTH)

        // Script list: guard against events fired during model rebuild
        scriptList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        scriptList.addListSelectionListener { event ->
            if (!event.valueIsAdjusting && !syncingScriptList) {
                populateScriptEditor(scriptList.selectedValue)
            }
        }

        libraryList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        libraryList.cellRenderer = LibraryScriptRenderer()
        libraryList.addListSelectionListener { event ->
            if (!event.valueIsAdjusting && !syncingScriptList) {
                populateLibraryPreview(libraryList.selectedValue)
            }
        }

        processTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        processTable.autoCreateRowSorter = true
        processTable.setDefaultRenderer(Any::class.java, AttachedProcessRenderer(processTableModel))
        processTable.selectionModel.addListSelectionListener(::onProcessRowSelected)

        eventTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        eventTable.autoscrolls = false   // prevent JTable from auto-jumping viewport on selection/data change
        eventTable.setDefaultRenderer(Any::class.java, SeverityCellRenderer(eventTableModel))
        eventTable.selectionModel.addListSelectionListener(::onEventRowSelected)

        interceptTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        interceptTable.selectionModel.addListSelectionListener(::onInterceptRowSelected)

        // Read-only text areas
        rawEventText.isEditable = false
        rawEventText.lineWrap = false
        eventDetailsText.isEditable = false
        eventDetailsText.lineWrap = false
        sidecarLogText.isEditable = false
        sidecarLogText.lineWrap = false
        libraryMetaText.isEditable = false
        libraryMetaText.lineWrap = true
        libraryMetaText.wrapStyleWord = true
        libraryContentText.isEditable = false
        libraryContentText.lineWrap = false

        // Editable
        interceptPayloadText.lineWrap = false

        // Event filter document listeners — apply filter as user types
        eventFilterText.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = applyEventFilter()
            override fun removeUpdate(e: DocumentEvent?) = applyEventFilter()
            override fun changedUpdate(e: DocumentEvent?) = applyEventFilter()
        })
        eventFilterCategory.addActionListener { if (!suppressSync) applyEventFilter() }
        eventFilterProcess.addActionListener { if (!suppressSync) applyEventFilter() }
        showErrorsOnly.addActionListener { applyEventFilter() }
        showBookmarkedOnly.addActionListener { applyEventFilter() }

        fun addTextFilter(field: JTextField) {
            field.document.addDocumentListener(object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent?) = applyEventFilter()
                override fun removeUpdate(e: DocumentEvent?) = applyEventFilter()
                override fun changedUpdate(e: DocumentEvent?) = applyEventFilter()
            })
        }
        addTextFilter(eventFilterModule)
        addTextFilter(eventFilterTarget)

        // Right-click context menu on event table for bookmark
        val eventPopup = JPopupMenu()
        val bookmarkItem = JMenuItem("Bookmark / Unbookmark")
        bookmarkItem.addActionListener {
            val row = eventTable.selectedRow
            val event = if (row >= 0) eventTableModel.eventAt(row) else null
            if (event != null && event.id.isNotBlank()) controller.toggleBookmark(event.id)
        }
        eventPopup.add(bookmarkItem)
        eventTable.componentPopupMenu = eventPopup

        // Right-click context menu on findings table for False Positive
        val findingsPopup = JPopupMenu()
        val markFpItem = JMenuItem("Mark as False Positive (hides from list)")
        markFpItem.addActionListener {
            val row = findingsTable.selectedRow
            if (row >= 0) {
                val f = findingsTableModel.findingAt(findingsTable.convertRowIndexToModel(row))
                controller.markFindingFalsePositive(f.title, f.category)
            }
        }
        findingsPopup.add(markFpItem)
        findingsTable.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mousePressed(e: java.awt.event.MouseEvent) = maybeShowPopup(e)
            override fun mouseReleased(e: java.awt.event.MouseEvent) = maybeShowPopup(e)
            private fun maybeShowPopup(e: java.awt.event.MouseEvent) {
                if (!e.isPopupTrigger) return
                val row = findingsTable.rowAtPoint(e.point)
                if (row >= 0) {
                    findingsTable.setRowSelectionInterval(row, row)
                    findingsPopup.show(e.component, e.x, e.y)
                }
            }
        })

        // Scroll lock toggle
        scrollLockButton.addActionListener {
            scrollLocked = !scrollLocked
            if (scrollLocked) {
                // Capture viewport position NOW, before any new render can move it
                lockedViewPos = if (::eventScrollPane.isInitialized)
                    java.awt.Point(eventScrollPane.viewport.viewPosition)
                else null
            } else {
                lockedViewPos = null
            }
            scrollLockButton.text = if (scrollLocked) "▶ Scroll Running" else "⏸ Scroll Lock"
            scrollLockButton.foreground = if (scrollLocked) Color(180, 0, 0) else Color.BLACK
            scrollLockButton.toolTipText = if (scrollLocked)
                "Auto-scroll is PAUSED — click to resume"
            else
                "Click to pause auto-scroll and inspect events freely"
        }

        // Export checkbox toggle
        exportEnabled.addActionListener {
            if (exportEnabled.isSelected) {
                val dir = java.io.File(exportDirField.text.ifBlank { System.getProperty("user.home") })
                controller.configureExport(dir, exportFileField.text.ifBlank { "fridalink_events" })
            } else {
                controller.stopExport()
            }
            exportStatusLabel.text = controller.exportStatusLine()
        }

        controller.addListener(::render)
    }

    // -----------------------------------------------------------------------
    // Layout builders
    // -----------------------------------------------------------------------

    private fun buildToolbar(): JComponent {
        val panel = JPanel(WrapLayout(FlowLayout.LEFT))
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val connectButton = JButton("Connect Sidecar")
        connectButton.addActionListener {
            controller.connectSidecar(hostField.text.trim(), portField.text.trim().toIntOrNull() ?: 7766)
        }
        val disconnectButton = JButton("Disconnect")
        disconnectButton.addActionListener { controller.disconnectSidecar() }
        val launchSidecarButton = JButton("Launch Sidecar")
        launchSidecarButton.addActionListener {
            controller.launchSidecar(pythonField.text.trim(), projectRootField.text.trim())
        }
        val stopSidecarButton = JButton("Stop Sidecar")
        stopSidecarButton.addActionListener { controller.stopSidecar() }
        val refreshButton = JButton("Refresh")
        refreshButton.addActionListener { controller.refreshProcesses() }
        val attachButton = JButton("Attach Selected")
        attachButton.addActionListener { controller.attachSelectedProcess() }
        val detachButton = JButton("Detach")
        detachButton.addActionListener { controller.detachCurrentProcess() }
        val clearEvents = JButton("Clear Events")
        clearEvents.addActionListener { controller.clearEvents() }

        panel.add(JLabel("Host"))
        panel.add(hostField)
        panel.add(JLabel("Port"))
        panel.add(portField)
        panel.add(JLabel("Python"))
        panel.add(pythonField)
        panel.add(connectButton)
        panel.add(disconnectButton)
        panel.add(launchSidecarButton)
        panel.add(stopSidecarButton)
        panel.add(refreshButton)
        panel.add(attachButton)
        panel.add(detachButton)
        panel.add(clearEvents)
        return panel
    }

    private fun buildMainSplit(): JComponent {
        val left = JPanel(BorderLayout())
        left.border = BorderFactory.createTitledBorder("Targets")

        // Spawn panel at the TOP — always visible regardless of panel height.
        // Previously this was at SOUTH and would get clipped when the panel was small.
        val spawnButton = JButton("Spawn & Attach")
        spawnButton.addActionListener { controller.spawnProcess(spawnField.text.trim()) }
        val resumeButton = JButton("Resume")
        resumeButton.addActionListener { controller.resumeProcess() }

        val spawnRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        spawnRow.add(JLabel("Pkg:"))
        spawnRow.add(spawnField)
        spawnRow.add(spawnButton)
        spawnRow.add(resumeButton)
        spawnRow.border = BorderFactory.createTitledBorder("Spawn")

        val statusRow = JPanel(BorderLayout())
        statusRow.add(selectionLabel, BorderLayout.NORTH)
        statusRow.add(sessionLabel, BorderLayout.SOUTH)

        val header = JPanel(BorderLayout())
        header.add(spawnRow, BorderLayout.NORTH)
        header.add(statusRow, BorderLayout.SOUTH)

        left.add(header, BorderLayout.NORTH)
        left.add(JScrollPane(processTable), BorderLayout.CENTER)
        // Ensure the divider is always draggable regardless of process table content
        left.minimumSize = Dimension(180, 100)

        val tabs = JTabbedPane()
        tabs.addTab("Live Feed", buildFeedPanel())
        tabs.addTab("Match & Replace", buildMatchReplacePanel())
        tabs.addTab("Intercept", buildInterceptPanel())
        tabs.addTab("Sidecar Logs", buildSidecarLogsPanel())
        tabs.addTab("Script Library", buildScriptLibraryPanel())
        tabs.addTab("Custom Scripts", buildScriptsPanel())
        // ---- new feature tabs ----
        tabs.addTab("RPC Console", buildRpcConsoleTab())
        tabs.addTab("Frida REPL", buildFridaReplTab())
        tabs.addTab("Traffic", buildTrafficTab())
        tabs.addTab("Frida Trace", buildFridaTraceTab())
        tabs.addTab("MASVS", buildMasvsTab())
        tabs.addTab("Static Analysis", buildStaticAnalysisTab())
        tabs.addTab("Geo Map", buildGeoMapTab())
        tabs.addTab("Report", buildReportTab())
        tabs.minimumSize = Dimension(300, 100)

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, tabs)
        split.resizeWeight = 0.22
        split.isContinuousLayout = true      // divider drags smoothly without blank area
        split.isOneTouchExpandable = true    // arrow buttons to collapse/expand left panel
        return split
    }

    private fun buildFeedPanel(): JComponent {
        val eventPanel = JPanel(BorderLayout())
        eventPanel.border = BorderFactory.createTitledBorder("Live Events")
        eventPanel.add(buildFilterBar(), BorderLayout.NORTH)
        eventScrollPane = JScrollPane(eventTable)
        eventPanel.add(eventScrollPane, BorderLayout.CENTER)

        val detailsPanel = JPanel(BorderLayout())
        detailsPanel.border = BorderFactory.createTitledBorder("Event Details")
        detailsPanel.add(JScrollPane(eventDetailsText), BorderLayout.CENTER)

        val rawPanel = JPanel(BorderLayout())
        rawPanel.border = BorderFactory.createTitledBorder("Raw Event JSON")
        rawPanel.add(JScrollPane(rawEventText), BorderLayout.CENTER)

        val lowerSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, detailsPanel, rawPanel)
        lowerSplit.resizeWeight = 0.4

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, eventPanel, lowerSplit)
        split.resizeWeight = 0.65

        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        panel.add(split, BorderLayout.CENTER)
        return panel
    }

    private fun buildFilterBar(): JComponent {
        val outer = JPanel(BorderLayout())

        // Row 1: Scroll Lock is in its own panel at the very top so it NEVER gets
        // pushed off-screen by the filter row overflowing on narrow windows.
        val controlRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        scrollLockButton.font = java.awt.Font("SansSerif", java.awt.Font.BOLD, 11)
        controlRow.add(scrollLockButton)

        // Row 2: Filters — FlowLayout wraps if the window is narrow, but scroll lock
        // is already safe in its own row above.
        val filterRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        filterRow.border = BorderFactory.createTitledBorder("Filter")

        val clearButton = JButton("Clear")
        clearButton.addActionListener { clearEventFilter() }

        filterRow.add(JLabel("Search"))
        filterRow.add(eventFilterText)
        filterRow.add(JLabel("Category"))
        filterRow.add(eventFilterCategory)
        filterRow.add(JLabel("Process"))
        filterRow.add(eventFilterProcess)
        filterRow.add(JLabel("Module"))
        filterRow.add(eventFilterModule)
        filterRow.add(JLabel("Target"))
        filterRow.add(eventFilterTarget)
        filterRow.add(showErrorsOnly)
        filterRow.add(showBookmarkedOnly)
        filterRow.add(clearButton)

        // Row 3: Export
        val exportRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        exportRow.border = BorderFactory.createTitledBorder("Export")

        val browseButton = JButton("Browse…")
        browseButton.addActionListener {
            val chooser = JFileChooser(exportDirField.text.ifBlank { System.getProperty("user.home") })
            chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            chooser.dialogTitle = "Select export directory"
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                exportDirField.text = chooser.selectedFile.absolutePath
                if (exportEnabled.isSelected) {
                    controller.configureExport(chooser.selectedFile,
                        exportFileField.text.ifBlank { "fridalink_events" })
                }
            }
        }

        exportRow.add(exportEnabled)
        exportRow.add(JLabel("Dir:"))
        exportRow.add(exportDirField)
        exportRow.add(browseButton)
        exportRow.add(JLabel("File:"))
        exportRow.add(exportFileField)
        exportRow.add(exportStatusLabel)

        val topRows = JPanel(BorderLayout())
        topRows.add(controlRow, BorderLayout.NORTH)
        topRows.add(filterRow, BorderLayout.CENTER)

        outer.add(topRows, BorderLayout.NORTH)
        outer.add(exportRow, BorderLayout.SOUTH)
        return outer
    }

    private fun buildMatchReplacePanel(): JComponent {
        // Table setup — checkbox column uses Boolean renderer/editor
        matchReplaceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        matchReplaceTable.setDefaultRenderer(Boolean::class.java,
            matchReplaceTable.getDefaultRenderer(Boolean::class.javaObjectType))
        matchReplaceTable.setDefaultEditor(Boolean::class.java,
            matchReplaceTable.getDefaultEditor(Boolean::class.javaObjectType))
        matchReplaceTable.columnModel.getColumn(0).preferredWidth = 50   // On
        matchReplaceTable.columnModel.getColumn(1).preferredWidth = 180  // URL Pattern
        matchReplaceTable.columnModel.getColumn(2).preferredWidth = 180  // Match
        matchReplaceTable.columnModel.getColumn(3).preferredWidth = 180  // Replace
        matchReplaceTable.columnModel.getColumn(4).preferredWidth = 50   // Regex
        matchReplaceTable.columnModel.getColumn(5).preferredWidth = 120  // Comment

        val addButton = JButton("Add Rule")
        addButton.addActionListener {
            val rule = MatchReplaceRule(
                id = java.util.UUID.randomUUID().toString(),
                enabled = true,
                urlPattern = "",
                matchText = "quantity",
                replaceText = "999",
            )
            controller.addMatchReplaceRule(rule)
        }

        val removeButton = JButton("Remove Selected")
        removeButton.addActionListener {
            val row = matchReplaceTable.selectedRow
            if (row >= 0) {
                val rule = matchReplaceTableModel.ruleAt(row)
                if (rule != null) controller.removeMatchReplaceRule(rule.id)
            }
        }

        val pushButton = JButton("Push Rules to Session")
        pushButton.toolTipText = "Send all rules to the OkHttp observer running in the Frida session"
        pushButton.addActionListener { controller.pushMatchReplaceRules() }

        val hint = JLabel("<html><b>Tip:</b> Rules modify OkHttp JSON responses in-process before the app reads them. " +
            "Enable the <i>OkHttp3 Request Observer</i> script, define rules here, then click Push.</html>")
        hint.border = BorderFactory.createEmptyBorder(4, 8, 4, 8)

        val buttonRow = JPanel(WrapLayout(FlowLayout.LEFT, 6, 4))
        buttonRow.add(addButton)
        buttonRow.add(removeButton)
        buttonRow.add(pushButton)
        buttonRow.add(mrStatusLabel)

        val tablePanel = JPanel(BorderLayout())
        tablePanel.border = BorderFactory.createTitledBorder("Rules")
        tablePanel.add(JScrollPane(matchReplaceTable), BorderLayout.CENTER)

        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        panel.add(hint, BorderLayout.NORTH)
        panel.add(tablePanel, BorderLayout.CENTER)
        panel.add(buttonRow, BorderLayout.SOUTH)
        return panel
    }

    private fun buildInterceptPanel(): JComponent {
        val tablePanel = JPanel(BorderLayout())
        tablePanel.border = BorderFactory.createTitledBorder("Intercept Queue")
        tablePanel.add(JScrollPane(interceptTable), BorderLayout.CENTER)

        val payloadPanel = JPanel(BorderLayout())
        payloadPanel.border = BorderFactory.createTitledBorder("Intercept Payload (editable)")
        payloadPanel.add(JScrollPane(interceptPayloadText), BorderLayout.CENTER)

        val actions = JPanel(WrapLayout(FlowLayout.LEFT))
        val forwardButton = JButton("Forward")
        forwardButton.addActionListener {
            selectedIntercept()?.let { controller.submitInterceptAction(it.id, "forward", interceptPayloadText.text) }
        }
        val dropButton = JButton("Drop")
        dropButton.addActionListener {
            selectedIntercept()?.let { controller.submitInterceptAction(it.id, "drop", interceptPayloadText.text) }
        }
        val resendButton = JButton("Resend Edited")
        resendButton.addActionListener {
            selectedIntercept()?.let { controller.submitInterceptAction(it.id, "resend", interceptPayloadText.text) }
        }
        actions.add(forwardButton)
        actions.add(dropButton)
        actions.add(resendButton)
        payloadPanel.add(actions, BorderLayout.SOUTH)

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, payloadPanel)
        split.resizeWeight = 0.55
        return split
    }

    private fun buildSidecarLogsPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        val logPanel = JPanel(BorderLayout())
        logPanel.border = BorderFactory.createTitledBorder("Sidecar Output")
        logPanel.add(JScrollPane(sidecarLogText), BorderLayout.CENTER)
        panel.add(logPanel, BorderLayout.CENTER)
        return panel
    }

    private fun buildScriptLibraryPanel(): JComponent {
        // Top: library path + reload
        val pathPanel = JPanel(WrapLayout(FlowLayout.LEFT))
        pathPanel.border = BorderFactory.createTitledBorder("Library Path")
        val reloadButton = JButton("Reload Library")
        reloadButton.addActionListener {
            controller.loadScriptLibrary(libraryPathField.text.trim())
        }
        pathPanel.add(JLabel("Path"))
        pathPanel.add(libraryPathField)
        pathPanel.add(reloadButton)

        // Left: script list
        val listPanel = JPanel(BorderLayout())
        listPanel.border = BorderFactory.createTitledBorder("Available Scripts")
        listPanel.add(JScrollPane(libraryList), BorderLayout.CENTER)
        listPanel.add(libraryStatusLabel, BorderLayout.SOUTH)

        // Right top: metadata
        val metaPanel = JPanel(BorderLayout())
        metaPanel.border = BorderFactory.createTitledBorder("Script Metadata")
        metaPanel.preferredSize = Dimension(0, 120)
        metaPanel.add(JScrollPane(libraryMetaText), BorderLayout.CENTER)

        // Right bottom: content preview
        val contentPanel = JPanel(BorderLayout())
        contentPanel.border = BorderFactory.createTitledBorder("Script Content (preview)")
        contentPanel.add(JScrollPane(libraryContentText), BorderLayout.CENTER)

        // Right action buttons
        val actionPanel = JPanel(WrapLayout(FlowLayout.LEFT))
        val enableButton = JButton("Enable Selected")
        enableButton.addActionListener {
            libraryList.selectedValue?.let { controller.enableLibraryScript(it.id) }
        }
        val disableButton = JButton("Disable Selected")
        disableButton.addActionListener {
            libraryList.selectedValue?.let { controller.disableLibraryScript(it.id) }
        }
        actionPanel.add(enableButton)
        actionPanel.add(disableButton)

        val rightSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, metaPanel, contentPanel)
        rightSplit.resizeWeight = 0.25

        val rightPanel = JPanel(BorderLayout())
        rightPanel.add(rightSplit, BorderLayout.CENTER)
        rightPanel.add(actionPanel, BorderLayout.SOUTH)

        val mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listPanel, rightPanel)
        mainSplit.resizeWeight = 0.30

        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        panel.add(pathPanel, BorderLayout.NORTH)
        panel.add(mainSplit, BorderLayout.CENTER)
        return panel
    }

    private fun buildScriptsPanel(): JComponent {
        val listPane = JPanel(BorderLayout())
        listPane.border = BorderFactory.createTitledBorder("Scripts")
        listPane.add(JScrollPane(scriptList), BorderLayout.CENTER)

        val editor = JPanel()
        editor.layout = BoxLayout(editor, BoxLayout.Y_AXIS)
        editor.border = BorderFactory.createTitledBorder("Editor")
        scriptContent.lineWrap = false
        scriptContent.rows = 20

        editor.add(labeled("Project Root", projectRootField))
        editor.add(labeled("Name", scriptName))
        editor.add(labeled("Language", scriptLanguage))
        editor.add(labeled("Description", scriptDescription))
        editor.add(labeled("Content", JScrollPane(scriptContent)))

        val actions = JPanel(WrapLayout(FlowLayout.LEFT))
        val newButton = JButton("New")
        newButton.addActionListener {
            scriptList.clearSelection()
            populateScriptEditor(null)
            scriptName.text = "New Script"
        }
        val saveButton = JButton("Save")
        saveButton.addActionListener {
            controller.saveScript(
                scriptList.selectedValue?.id,
                scriptName.text,
                scriptLanguage.selectedItem?.toString().orEmpty(),
                scriptDescription.text,
                scriptContent.text,
            )
        }
        val deleteButton = JButton("Delete")
        deleteButton.addActionListener {
            scriptList.selectedValue?.let { controller.deleteScript(it.id) }
        }
        val runButton = JButton("Run Selected")
        runButton.addActionListener {
            val script = currentEditorScript()
            controller.runScript(script)
            logging.logToOutput("FridaLink run request: ${script.name}")
        }

        actions.add(newButton)
        actions.add(saveButton)
        actions.add(deleteButton)
        actions.add(runButton)
        editor.add(actions)

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listPane, editor)
        split.resizeWeight = 0.28
        return split
    }

    private fun buildStatusBar(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(6, 10, 6, 10)
        panel.add(statusLabel, BorderLayout.CENTER)
        return panel
    }

    private fun labeled(label: String, component: JComponent): JComponent {
        val panel = JPanel(BorderLayout(8, 8))
        panel.border = BorderFactory.createEmptyBorder(4, 0, 4, 0)
        panel.add(JLabel(label), BorderLayout.NORTH)
        panel.add(component, BorderLayout.CENTER)
        return panel
    }

    // -----------------------------------------------------------------------
    // Render — called on EDT every 200 ms via the controller publish timer.
    //
    // Rules enforced here:
    //  1. Never call setSelectionInterval without holding suppressSync=true so
    //     listeners know not to call back to the controller.
    //  2. Never rebuild a list model without syncingScriptList=true so
    //     populateScriptEditor / populateLibraryPreview don't fire.
    //  3. Never overwrite an editable area (interceptPayloadText, script editor
    //     fields) while the user has focus in that component.
    //  4. Only rebuild model content when the data actually changed.
    // -----------------------------------------------------------------------

    private fun render(state: FridaLinkState) {
        // --- status / labels ---
        statusLabel.text = buildString {
            append(state.status)
            append(" | mode="); append(state.mode)
            append(" | connected="); append(state.connected)
            append(" | processes="); append(state.processes.size)
            append(" | events="); append(state.events.size)
            append(" | intercepts="); append(state.intercepts.size)
        }
        val selected = state.processes.firstOrNull { it.pid == state.selectedPid }
        selectionLabel.text = "Selected: ${selected?.name ?: "none"} | attached=${state.attachedPid ?: "none"} | sidecarProcess=${controller.isSidecarProcessRunning()}"
        sessionLabel.text = "<html>${state.sessionStatus}</html>"

        // --- process table ---
        suppressSync = true
        try {
            processTableModel.setRows(state.processes)
            syncProcessSelection(state)
        } finally {
            suppressSync = false
        }

        // --- event table ---
        // Capture selected event BEFORE fireTableDataChanged() clears the selection
        val pinnedEvent = eventTable.selectedRow.takeIf { it >= 0 }?.let { eventTableModel.eventAt(it) }
        suppressSync = true
        try {
            eventTableModel.setAllRows(state.events)
            updateFilterDropdowns(state.events)
            syncEventSelection(state, pinnedEvent)
        } finally {
            suppressSync = false
        }

        // --- intercept table ---
        suppressSync = true
        try {
            interceptTableModel.setRows(state.intercepts)
            syncInterceptSelection(state)
        } finally {
            suppressSync = false
        }

        // --- bookmarks: push to model so bookmarked-only filter works ---
        eventTableModel.bookmarkedIds = state.bookmarkedIds

        // --- match & replace rules ---
        matchReplaceTableModel.setRules(state.matchReplaceRules)
        val active = state.matchReplaceRules.count { it.enabled }
        mrStatusLabel.text = "${state.matchReplaceRules.size} rule(s), $active active"

        // --- export status ---
        if (exportEnabled.isSelected) {
            exportStatusLabel.text = controller.exportStatusLine()
        }

        // --- sidecar log (read-only, always safe to replace) ---
        sidecarLogText.text = state.sidecarLogs.joinToString("\n")
        sidecarLogText.caretPosition = sidecarLogText.document.length

        // --- custom script list: only rebuild when script set actually changes ---
        val newScriptSigs = state.scripts.map { "${it.id}:${it.name}" }
        if (newScriptSigs != lastRenderedScriptSigs) {
            lastRenderedScriptSigs = newScriptSigs
            syncingScriptList = true
            try {
                val selectedId = scriptList.selectedValue?.id
                scriptListModel.clear()
                state.scripts.forEach(scriptListModel::addElement)
                if (selectedId != null) {
                    val idx = state.scripts.indexOfFirst { it.id == selectedId }
                    if (idx >= 0) scriptList.selectedIndex = idx
                } else if (state.scripts.isNotEmpty() && scriptList.selectedIndex < 0) {
                    scriptList.selectedIndex = 0
                }
            } finally {
                syncingScriptList = false
            }
        }

        // --- library script list: only rebuild when library set changes ---
        val newLibSigs = state.libraryScripts.map { "${it.id}:${it.enabled}" }
        if (newLibSigs != lastRenderedLibrarySigs) {
            lastRenderedLibrarySigs = newLibSigs
            syncingScriptList = true
            try {
                val selectedLibId = libraryList.selectedValue?.id
                libraryListModel.clear()
                state.libraryScripts.forEach(libraryListModel::addElement)
                if (selectedLibId != null) {
                    val idx = state.libraryScripts.indexOfFirst { it.id == selectedLibId }
                    if (idx >= 0) libraryList.selectedIndex = idx
                } else if (state.libraryScripts.isNotEmpty() && libraryList.selectedIndex < 0) {
                    libraryList.selectedIndex = 0
                }
            } finally {
                syncingScriptList = false
            }
            val enabledCount = state.libraryScripts.count { it.enabled }
            libraryStatusLabel.text = "${state.libraryScripts.size} script(s) discovered  |  $enabledCount enabled"
        }

        // ---- new feature tabs ----
        syncNewTabs(state)
    }

    // -----------------------------------------------------------------------
    // Selection sync helpers — all called inside suppressSync = true
    // -----------------------------------------------------------------------

    private fun syncProcessSelection(state: FridaLinkState) {
        val selectedPid = state.selectedPid ?: return
        val modelIndex = state.processes.indexOfFirst { it.pid == selectedPid }
        if (modelIndex >= 0) {
            val viewIndex = try { processTable.convertRowIndexToView(modelIndex) } catch (e: Exception) { -1 }
            if (viewIndex >= 0 && processTable.selectedRow != viewIndex) {
                processTable.selectionModel.setSelectionInterval(viewIndex, viewIndex)
            }
        }
    }

    private fun syncEventSelection(state: FridaLinkState, pinnedEvent: RuntimeEvent? = null) {
        if (state.events.isEmpty()) {
            rawEventText.text = ""
            eventDetailsText.text = ""
            return
        }

        if (scrollLocked) {
            // Restore the position that was captured when the user toggled the lock.
            // Using a single invokeLater is sufficient because lockedViewPos is stable
            // (it never changes while locked), so there is no race with any other render.
            val pos = lockedViewPos
            if (pos != null) {
                SwingUtilities.invokeLater {
                    if (::eventScrollPane.isInitialized) {
                        eventScrollPane.viewport.viewPosition = java.awt.Point(pos)
                    }
                }
            }
            return
        }

        // If the user had a row selected before the model rebuild, find it again
        // and restore the viewport so they can keep reading while new events arrive.
        if (pinnedEvent != null) {
            val newRow = eventTableModel.rowOf(pinnedEvent)
            if (newRow >= 0) {
                eventTable.selectionModel.setSelectionInterval(newRow, newRow)
                val savedViewPos = if (::eventScrollPane.isInitialized)
                    java.awt.Point(eventScrollPane.viewport.viewPosition)
                else null
                if (savedViewPos != null) {
                    SwingUtilities.invokeLater {
                        if (::eventScrollPane.isInitialized) {
                            eventScrollPane.viewport.viewPosition = savedViewPos
                        }
                    }
                }
                return
            }
        }

        // Normal (unlocked) mode — auto-select newest row (row 0) and scroll to top.
        if (eventTableModel.rowCount > 0) {
            eventTable.selectionModel.setSelectionInterval(0, 0)
            SwingUtilities.invokeLater {
                if (::eventScrollPane.isInitialized) {
                    eventScrollPane.viewport.viewPosition = java.awt.Point(0, 0)
                }
            }
        }
        val event = eventTableModel.eventAt(0) ?: return
        rawEventText.text = event.raw
        eventDetailsText.text = formatEventDetails(event)
        rawEventText.caretPosition = 0
        eventDetailsText.caretPosition = 0
    }

    private fun syncInterceptSelection(state: FridaLinkState) {
        if (state.intercepts.isEmpty()) {
            if (!interceptPayloadText.hasFocus()) interceptPayloadText.text = ""
            return
        }
        val selectedId = state.selectedInterceptId ?: state.intercepts.first().id
        val index = state.intercepts.indexOfFirst { it.id == selectedId }.takeIf { it >= 0 } ?: 0
        if (interceptTable.selectedRow != index) {
            interceptTable.selectionModel.setSelectionInterval(index, index)
        }
        // IMPORTANT: do not overwrite while the operator is actively editing the payload
        if (!interceptPayloadText.hasFocus()) {
            interceptPayloadText.text = state.intercepts[index].payload
            interceptPayloadText.caretPosition = 0
        }
    }

    // -----------------------------------------------------------------------
    // Event filter
    // -----------------------------------------------------------------------

    private fun applyEventFilter() {
        eventTableModel.searchText = eventFilterText.text
        eventTableModel.categoryFilter = eventFilterCategory.selectedItem?.toString() ?: "All"
        eventTableModel.processFilter = eventFilterProcess.selectedItem?.toString() ?: "All"
        eventTableModel.moduleFilter = eventFilterModule.text
        eventTableModel.targetFilter = eventFilterTarget.text
        eventTableModel.errorsOnly = showErrorsOnly.isSelected
        eventTableModel.bookmarkedOnly = showBookmarkedOnly.isSelected
        suppressSync = true
        try {
            eventTableModel.applyFilter()
        } finally {
            suppressSync = false
        }
    }

    private fun clearEventFilter() {
        suppressSync = true
        try {
            eventFilterText.text = ""
            eventFilterCategory.selectedItem = "All"
            eventFilterProcess.selectedItem = "All"
            eventFilterModule.text = ""
            eventFilterTarget.text = ""
            showErrorsOnly.isSelected = false
            showBookmarkedOnly.isSelected = false
            eventTableModel.searchText = ""
            eventTableModel.categoryFilter = "All"
            eventTableModel.processFilter = "All"
            eventTableModel.moduleFilter = ""
            eventTableModel.targetFilter = ""
            eventTableModel.errorsOnly = false
            eventTableModel.bookmarkedOnly = false
            eventTableModel.applyFilter()
        } finally {
            suppressSync = false
        }
    }

    /** Keep category/process dropdowns in sync with events, preserving current selection. */
    private fun updateFilterDropdowns(events: List<RuntimeEvent>) {
        val currentCat = eventFilterCategory.selectedItem?.toString() ?: "All"
        val currentProc = eventFilterProcess.selectedItem?.toString() ?: "All"

        val categories = listOf("All") + events.map { it.category }.distinct().sorted()
        val processes = listOf("All") + events.map { it.process }.distinct().sorted()

        // Only repopulate if items changed
        val existingCats = (0 until eventFilterCategory.itemCount).map { eventFilterCategory.getItemAt(it) }
        if (existingCats != categories) {
            suppressSync = true
            try {
                eventFilterCategory.removeAllItems()
                categories.forEach { eventFilterCategory.addItem(it) }
                eventFilterCategory.selectedItem = if (currentCat in categories) currentCat else "All"
            } finally {
                suppressSync = false
            }
        }

        val existingProcs = (0 until eventFilterProcess.itemCount).map { eventFilterProcess.getItemAt(it) }
        if (existingProcs != processes) {
            suppressSync = true
            try {
                eventFilterProcess.removeAllItems()
                processes.forEach { eventFilterProcess.addItem(it) }
                eventFilterProcess.selectedItem = if (currentProc in processes) currentProc else "All"
            } finally {
                suppressSync = false
            }
        }
    }

    // -----------------------------------------------------------------------
    // User-initiated selection listeners
    // -----------------------------------------------------------------------

    private fun onProcessRowSelected(event: ListSelectionEvent) {
        // Ignore events that originate from our own render-driven sync
        if (event.valueIsAdjusting || suppressSync) return
        val row = processTable.selectedRow
        if (row < 0) return
        val modelRow = processTable.convertRowIndexToModel(row)
        processTableModel.pidAt(modelRow)?.let(controller::selectProcess)
    }

    private fun onEventRowSelected(event: ListSelectionEvent) {
        if (event.valueIsAdjusting || suppressSync) return
        val row = eventTable.selectedRow
        if (row < 0) {
            rawEventText.text = ""
            eventDetailsText.text = ""
            return
        }
        val e = eventTableModel.eventAt(row)
        rawEventText.text = e?.raw.orEmpty()
        eventDetailsText.text = if (e == null) "" else formatEventDetails(e)
        rawEventText.caretPosition = 0
        eventDetailsText.caretPosition = 0
    }

    private fun formatEventDetails(e: RuntimeEvent): String = buildString {
        val sep = "─".repeat(52)
        fun section(title: String) { appendLine(); appendLine("── $title ${"─".repeat((48 - title.length).coerceAtLeast(2))}") }
        fun field(label: String, value: String) {
            if (value.isNotBlank()) appendLine("  %-18s %s".format(label, value))
        }

        section("OVERVIEW")
        field("timestamp", e.timestamp)
        field("severity", e.severity.uppercase())
        field("category", e.category)
        field("module", e.module)
        field("target", e.target)
        field("process", e.process)
        field("thread_id", e.threadId)
        field("bookmarked", if (e.id in (eventTableModel.bookmarkedIds)) "★ YES" else "")

        section("PAYLOAD")
        field("summary", e.summary)
        if (e.args.isNotBlank()) {
            // Pretty-print multi-line args
            val lines = e.args.lines()
            if (lines.size == 1) {
                field("args", e.args)
            } else {
                appendLine("  args:")
                lines.forEach { appendLine("    $it") }
            }
        }
        field("retval", e.retval)

        section("CONTEXT")
        field("script_source", e.scriptSource)
        field("correlation_id", e.correlationId)
        field("event_id", e.id)

        if (e.backtrace.isNotBlank()) {
            section("CALL STACK")
            e.backtrace.lines().forEach { appendLine("  $it") }
        }

        // Show any extra fields emitted by custom scripts that aren't mapped above
        val knownKeys = setOf("type","timestamp","process","category","module","target","summary",
            "severity","thread_id","script_source","correlation_id","args","retval","backtrace","id")
        val extras = e.details.filterKeys { it !in knownKeys && it.isNotBlank() }
        if (extras.isNotEmpty()) {
            section("EXTRA FIELDS")
            extras.forEach { (k, v) -> field(k, v) }
        }
    }

    private fun onInterceptRowSelected(event: ListSelectionEvent) {
        if (event.valueIsAdjusting || suppressSync) return
        val row = interceptTable.selectedRow
        if (row < 0) {
            interceptPayloadText.text = ""
            return
        }
        val modelRow = interceptTable.convertRowIndexToModel(row)
        val item = interceptTableModel.itemAt(modelRow)
        controller.selectIntercept(item?.id)
        interceptPayloadText.text = item?.payload.orEmpty()
        interceptPayloadText.caretPosition = 0
    }

    // -----------------------------------------------------------------------
    // Script editor helpers
    // -----------------------------------------------------------------------

    private fun populateScriptEditor(script: CustomScript?) {
        if (script == null) {
            // Only clear fields not currently focused
            if (!scriptName.hasFocus()) scriptName.text = ""
            if (!scriptDescription.hasFocus()) scriptDescription.text = ""
            if (!scriptContent.hasFocus()) scriptContent.text = ""
            scriptLanguage.selectedItem = "javascript"
            return
        }
        if (!scriptName.hasFocus()) scriptName.text = script.name
        if (!scriptDescription.hasFocus()) scriptDescription.text = script.description
        if (!scriptContent.hasFocus()) scriptContent.text = script.content
        scriptLanguage.selectedItem = script.language
    }

    private fun populateLibraryPreview(script: LibraryScript?) {
        if (script == null) {
            libraryMetaText.text = ""
            libraryContentText.text = ""
            return
        }
        libraryMetaText.text = buildString {
            appendLine("Name:        ${script.name}")
            appendLine("Category:    ${script.category}")
            appendLine("Version:     ${script.version}")
            appendLine("Status:      ${if (script.enabled) "ENABLED (loaded in session)" else "disabled"}")
            if (script.description.isNotBlank()) appendLine("Description: ${script.description}")
            if (script.path.isNotBlank()) appendLine("Path:        ${script.path}")
        }
        libraryMetaText.caretPosition = 0
        libraryContentText.text = script.content
        libraryContentText.caretPosition = 0
    }

    private fun currentEditorScript(): CustomScript =
        CustomScript(
            id = scriptList.selectedValue?.id ?: "ad-hoc",
            name = scriptName.text.ifBlank { "Ad-hoc Script" },
            language = scriptLanguage.selectedItem?.toString() ?: "javascript",
            description = scriptDescription.text,
            content = scriptContent.text,
        )

    private fun selectedIntercept(): InterceptItem? {
        val row = interceptTable.selectedRow
        if (row < 0) return null
        return interceptTableModel.itemAt(interceptTable.convertRowIndexToModel(row))
    }

    // =========================================================================
    // RPC CONSOLE TAB
    // =========================================================================

    private fun buildRpcConsoleTab(): JComponent {
        // ── Quick-action presets ──────────────────────────────────────────────
        val presetsPanel = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        presetsPanel.border = BorderFactory.createTitledBorder("Quick Actions (Lua + IL2CPP Inspector)")

        data class Preset(val label: String, val method: String, val args: List<Any>)
        val presets = listOf(
            Preset("Status",             "status",             emptyList()),
            Preset("List Reward Methods","listRewardMethods",  emptyList()),
            Preset("List Modules",       "listModules",        emptyList()),
            Preset("Enumerate IL2CPP Classes","enumerateClasses", listOf("libil2cpp.so")),
        )
        presets.forEach { p ->
            val btn = JButton(p.label)
            btn.toolTipText = "rpc.${p.method}(${p.args.joinToString()})"
            btn.addActionListener {
                controller.callRpc(p.method, p.args)
                rpcStatusLabel.text = "Dispatched: ${p.method}() — result will appear below"
            }
            presetsPanel.add(btn)
        }

        // ── Toggle buttons ────────────────────────────────────────────────────
        val togglePanel = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        togglePanel.border = BorderFactory.createTitledBorder("Runtime Toggles")

        val invokeOnBtn  = JButton("IL2CPP Invoke Log: ON")
        val invokeOffBtn = JButton("IL2CPP Invoke Log: OFF")
        val netOnBtn     = JButton("Net I/O Log: ON")
        val netOffBtn    = JButton("Net I/O Log: OFF")
        invokeOnBtn .addActionListener { controller.callRpc("setLogAllInvoke", listOf(true));  rpcStatusLabel.text = "Dispatched: setLogAllInvoke(true)" }
        invokeOffBtn.addActionListener { controller.callRpc("setLogAllInvoke", listOf(false)); rpcStatusLabel.text = "Dispatched: setLogAllInvoke(false)" }
        netOnBtn    .addActionListener { controller.callRpc("setLogAllNet",    listOf(true));  rpcStatusLabel.text = "Dispatched: setLogAllNet(true)" }
        netOffBtn   .addActionListener { controller.callRpc("setLogAllNet",    listOf(false)); rpcStatusLabel.text = "Dispatched: setLogAllNet(false)" }
        togglePanel.add(invokeOnBtn)
        togglePanel.add(invokeOffBtn)
        togglePanel.add(netOnBtn)
        togglePanel.add(netOffBtn)

        // ── Custom call ───────────────────────────────────────────────────────
        val customPanel = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        customPanel.border = BorderFactory.createTitledBorder("Custom RPC Call")

        val executeBtn = JButton("Execute")
        val clearBtn   = JButton("Clear Results")
        executeBtn.addActionListener {
            val method   = rpcMethodField.text.trim()
            val argsText = rpcArgsField.text.trim()
            val args: List<Any> = if (argsText.isBlank()) emptyList()
                                  else argsText.split(",").map { it.trim() }
            if (method.isNotBlank()) {
                controller.callRpc(method, args)
                rpcStatusLabel.text = "Dispatched: $method(${args.joinToString()}) — result incoming"
            }
        }
        clearBtn.addActionListener {
            rpcResultText.text = ""
            lastRpcResultCount = 0
        }

        customPanel.add(JLabel("Method:"))
        customPanel.add(rpcMethodField)
        customPanel.add(JLabel("Args (comma-separated):"))
        customPanel.add(rpcArgsField)
        customPanel.add(executeBtn)
        customPanel.add(clearBtn)

        // ── Hint label ────────────────────────────────────────────────────────
        val hintLabel = JLabel(
            "<html><i>Requires 'Lua + IL2CPP + Network Inspector' script to be loaded." +
            " Results stream in as <b>rpc_result</b> events.</i></html>"
        )
        hintLabel.border = BorderFactory.createEmptyBorder(2, 6, 2, 6)

        // ── Header assembly ───────────────────────────────────────────────────
        val header = JPanel()
        header.layout = BoxLayout(header, BoxLayout.Y_AXIS)
        header.add(presetsPanel)
        header.add(togglePanel)
        header.add(customPanel)
        header.add(hintLabel)
        header.add(rpcStatusLabel)

        // ── Results area ──────────────────────────────────────────────────────
        val resultsPanel = JPanel(BorderLayout())
        resultsPanel.border = BorderFactory.createTitledBorder("RPC Results")
        resultsPanel.add(JScrollPane(rpcResultText), BorderLayout.CENTER)

        val panel = JPanel(BorderLayout(0, 4))
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        panel.add(header,       BorderLayout.NORTH)
        panel.add(resultsPanel, BorderLayout.CENTER)
        return panel
    }

    // =========================================================================
    // FRIDA REPL TAB
    // =========================================================================

    private fun buildFridaReplTab(): JComponent {

        // ── Submit logic ──────────────────────────────────────────────────────
        fun submitCode() {
            val code = replInputField.text.trim()
            if (code.isBlank()) return
            if (replCommandHistory.isEmpty() || replCommandHistory.last() != code) {
                replCommandHistory.add(code)
            }
            replHistoryIndex = -1
            replInputField.text = ""
            controller.evalRepl(code)
        }

        // ── Input field key bindings ──────────────────────────────────────────
        replInputField.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                when (e.keyCode) {
                    KeyEvent.VK_ENTER -> submitCode()
                    KeyEvent.VK_UP    -> {
                        if (replCommandHistory.isEmpty()) return
                        if (replHistoryIndex == -1) replHistoryIndex = replCommandHistory.size - 1
                        else if (replHistoryIndex > 0) replHistoryIndex--
                        replInputField.text = replCommandHistory[replHistoryIndex]
                        e.consume()
                    }
                    KeyEvent.VK_DOWN  -> {
                        if (replHistoryIndex == -1) return
                        replHistoryIndex++
                        if (replHistoryIndex >= replCommandHistory.size) {
                            replHistoryIndex = -1
                            replInputField.text = ""
                        } else {
                            replInputField.text = replCommandHistory[replHistoryIndex]
                        }
                        e.consume()
                    }
                }
            }
        })

        // ── Input bar ─────────────────────────────────────────────────────────
        val promptLabel = JLabel("> ").also {
            it.font       = java.awt.Font("Monospaced", java.awt.Font.BOLD, 13)
            it.foreground = Color(120, 220, 90)
        }
        val sendBtn  = JButton("Eval").also { it.toolTipText = "Evaluate (or press Enter)" }
        val clearBtn = JButton("Clear")
        sendBtn .addActionListener { submitCode() }
        clearBtn.addActionListener {
            replOutputPane.document.remove(0, replOutputPane.document.length)
            lastReplHistorySize = 0
        }

        val inputBar = JPanel(BorderLayout(4, 0)).also {
            it.background = Color(30, 30, 30)
            it.border     = BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color(70, 70, 70)),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
            )
        }
        val btnPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).also { it.isOpaque = false }
        btnPanel.add(sendBtn)
        btnPanel.add(clearBtn)
        inputBar.add(promptLabel,   BorderLayout.WEST)
        inputBar.add(replInputField, BorderLayout.CENTER)
        inputBar.add(btnPanel,       BorderLayout.EAST)

        // ── Terminal panel ────────────────────────────────────────────────────
        val termScroll = JScrollPane(replOutputPane).also {
            it.border           = null
            it.background       = Color(20, 20, 20)
            it.viewport.background = Color(20, 20, 20)
        }
        val termPanel = JPanel(BorderLayout()).also {
            it.background = Color(20, 20, 20)
            it.border     = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(70, 70, 70)), "Frida JS Console"
            )
        }
        termPanel.add(termScroll, BorderLayout.CENTER)
        termPanel.add(inputBar,   BorderLayout.SOUTH)

        // ── Cheat sheet ───────────────────────────────────────────────────────
        val cheatText = JTextArea(REPL_CHEAT_SHEET).also {
            it.isEditable     = false
            it.lineWrap       = false
            it.font           = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)
            it.background     = Color(28, 28, 40)
            it.foreground     = Color(180, 200, 255)
            it.caretColor     = Color(180, 200, 255)
            it.border         = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        }
        val cheatScroll = JScrollPane(cheatText).also { it.border = null }
        val cheatPanel  = JPanel(BorderLayout()).also {
            it.border = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color(70, 70, 90)), "Frida JS Cheat Sheet"
            )
        }
        cheatPanel.add(cheatScroll, BorderLayout.CENTER)

        // ── Layout ────────────────────────────────────────────────────────────
        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, termPanel, cheatPanel).also {
            it.resizeWeight    = 0.6
            it.dividerSize     = 5
            it.isContinuousLayout = true
        }

        val panel = JPanel(BorderLayout(0, 0))
        panel.border = BorderFactory.createEmptyBorder(6, 6, 6, 6)
        panel.add(split, BorderLayout.CENTER)
        return panel
    }

    /** Append a new REPL entry to the output pane without rebuilding the whole doc. */
    private fun appendReplEntry(entry: ReplEntry) {
        try {
            val doc = replOutputPane.styledDocument

            val tsAttr = SimpleAttributeSet().also {
                StyleConstants.setForeground(it, Color(100, 100, 100))
                StyleConstants.setFontSize(it, 10)
            }
            val promptAttr = SimpleAttributeSet().also {
                StyleConstants.setForeground(it, Color(120, 220, 90))
                StyleConstants.setBold(it, true)
            }
            val codeAttr = SimpleAttributeSet().also {
                StyleConstants.setForeground(it, Color(204, 255, 153))
            }
            val resultAttr = SimpleAttributeSet().also {
                StyleConstants.setForeground(it, Color(204, 204, 204))
            }
            val errorAttr = SimpleAttributeSet().also {
                StyleConstants.setForeground(it, Color(255, 110, 110))
            }

            val ts = entry.timestamp.take(19).replace("T", " ")
            doc.insertString(doc.length, "$ts  ", tsAttr)
            doc.insertString(doc.length, "> ", promptAttr)
            doc.insertString(doc.length, "${entry.code}\n", codeAttr)
            when {
                entry.error != null ->
                    doc.insertString(doc.length, "  \u2717 ${entry.error}\n\n", errorAttr)
                entry.result != null ->
                    doc.insertString(doc.length, "  ${entry.result.replace("\n", "\n  ")}\n\n", resultAttr)
                else ->
                    doc.insertString(doc.length, "  (no result)\n\n", resultAttr)
            }
            replOutputPane.caretPosition = doc.length
        } catch (_: Exception) { /* BadLocationException — ignore */ }
    }

    // Comprehensive Frida JS reference for the cheat sheet panel
    private val REPL_CHEAT_SHEET = """
── PROCESS INFO ──────────────────────────────────────────────────────────────
Process.id                              → current PID (number)
Process.platform                        → 'android' / 'ios' / 'linux'
Process.arch                            → 'arm64' / 'x64' / 'arm'
Process.pageSize                        → memory page size in bytes
Process.enumerateModules()              → [{name, base, size, path}, ...]
Process.findModuleByName('libgame.so')  → {name, base, size, path} or null
Process.getModuleByName('libgame.so')   → same but throws if not found
Process.enumerateRanges('r-x')          → executable memory ranges
Process.enumerateThreads()              → [{id, state, context}, ...]

── MODULE & EXPORT LOOKUP ────────────────────────────────────────────────────
Module.findExportByName(null,'SSL_read')                 → NativePointer or null
Module.findExportByName('libgame.so','lua_pushstring')   → NativePointer or null
Module.getExportByName('libssl.so','SSL_read')           → NativePointer (throws)
Module.findBaseAddress('libgame.so')                     → NativePointer or null
Module.enumerateExports('libgame.so')                    → [{name, type, address}, ...]
Module.enumerateImports('libgame.so')                    → [{name, type, address}, ...]
Module.enumerateSymbols('libgame.so')                    → [{name, address, ...}, ...]

── MEMORY & POINTERS ─────────────────────────────────────────────────────────
ptr('0x12345678')                   → NativePointer from hex string
ptr('0x...').readCString()          → read null-terminated C string
ptr('0x...').readUtf8String()       → read UTF-8 string (with length opt)
ptr('0x...').readS32()              → signed 32-bit int
ptr('0x...').readU32()              → unsigned 32-bit int
ptr('0x...').readS64()              → signed 64-bit int
ptr('0x...').readU64()              → unsigned 64-bit int
ptr('0x...').readPointer()          → pointer-sized value
ptr('0x...').readByteArray(16)      → Uint8Array of 16 bytes
ptr('0x...').add(16)                → ptr arithmetic: base + offset
ptr('0x...').sub(16)                → ptr arithmetic: base - offset
Memory.alloc(64)                    → allocate 64-byte NativePointer buffer
Memory.allocUtf8String('hello')     → allocate C string, return NativePointer
Memory.scanSync(base, size, 'DE AD BE EF')   → [{address, size}, ...]
Memory.scan(base, size, pat, { onMatch:function(a,s){} })
DebugSymbol.fromAddress(ptr('0x...'))        → {name, moduleName, fileName, lineNumber}
DebugSymbol.getFunctionByName('open')        → NativePointer

── NATIVE HOOKS ──────────────────────────────────────────────────────────────
Interceptor.attach(ptr, {
  onEnter: function(args) {
    console.log(args[0], args[1].readCString());
    this.firstArg = args[0];
  },
  onLeave: function(retval) {
    console.log('ret', retval.toInt32());
    retval.replace(ptr(42));     // replace return value
  }
})
Interceptor.replace(ptr, new NativeCallback(
  function(a0) { return 0; }, 'int', ['pointer']
))
Interceptor.revert(ptr)             → remove replacement

── NATIVE FUNCTION CALLS ─────────────────────────────────────────────────────
var fn = new NativeFunction(
    Module.findExportByName('libgame.so','lua_type'),
    'int',                          // return type
    ['pointer','int']               // arg types
)
fn(L, -1)                           → call directly, returns JS number

Common Frida NativeFunction types:
  'void' 'bool' 'int' 'uint' 'int32' 'uint32' 'int64' 'uint64'
  'float' 'double' 'pointer' 'size_t' 'ssize_t'

── BACKTRACE ─────────────────────────────────────────────────────────────────
// Inside Interceptor.attach onEnter:
Thread.backtrace(this.context, Backtracer.ACCURATE)
    .map(DebugSymbol.fromAddress)
    .join('\n')

── JAVA / ANDROID HOOKS ──────────────────────────────────────────────────────
// Note: Java.use() works fine for Java-layer app hooks on Android 16 / Frida 17.
// The "may fail" warning applies only to IL2CPP/native-bridge hooks in game apps.

Java.available                                  → true when ART is running
Java.perform(function() { ... })                → run code on the ART thread

// --- Class & method lookup ---
var Cls = Java.use('com.example.MyClass')
Cls.someMethod.implementation = function(arg) {
    console.log('called with', arg)
    return this.someMethod(arg)   // call original
}

// --- Overloaded methods (must specify types) ---
Cls.parse.overload('java.lang.String').implementation = function(s) {
    console.log('parse:', s)
    return this.parse(s)
}

// --- Static methods ---
var Uri = Java.use('android.net.Uri')
Uri.parse.overload('java.lang.String').implementation = function(s) {
    console.log('Uri.parse:', s); return this.parse(s)
}

// --- Constructors ---
Cls.${'$'}init.overload('java.lang.String', 'int').implementation = function(s, n) {
    console.log('new MyClass(', s, n, ')')
    this.${'$'}init(s, n)
}
Cls.${'$'}init.overload().implementation = function() {   // no-arg constructor
    this.${'$'}init()
}

// --- Read / write instance fields ---
var inst = ...           // obtain from Java.choose or hook onEnter
inst.mToken.value        // read field
inst.mToken.value = 'x' // write field

// --- Enumerate live instances ---
Java.choose('com.example.MyClass', {
    onMatch:    function(inst) { console.log(JSON.stringify(inst)); },
    onComplete: function()     {}
})

// --- List all loaded classes matching a pattern ---
Java.enumerateLoadedClassesSync().filter(c => c.includes('Auth'))

// --- Cast a raw handle to a typed wrapper ---
Java.cast(rawHandle, Java.use('android.content.Context'))

// --- Call a Java method from Frida ---
var ctx = Java.use('android.app.ActivityThread').currentApplication()
ctx.getPackageName()     // → 'com.etoro.openbook'

// --- Intercept OkHttp requests (eToro uses OkHttp) ---
Java.perform(function() {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall')
    RealCall.execute.implementation = function() {
        var req = this.request()
        console.log('[OkHttp]', req.method(), req.url().toString())
        return this.execute()
    }
})

// --- Read SharedPreferences (NativeStorage tokens) ---
Java.perform(function() {
    var ctx = Java.use('android.app.ActivityThread').currentApplication()
    var prefs = ctx.getSharedPreferences('NativeStorage', 0)  // mode=0 PRIVATE
    var all = prefs.getAll()
    var iter = all.entrySet().iterator()
    while (iter.hasNext()) {
        var e = iter.next(); console.log(e.getKey(), '=', e.getValue())
    }
})

// --- Dump a JSON object returned from a Java method ---
Java.perform(function() {
    var JSONObject = Java.use('org.json.JSONObject')
    // override toString() to capture whenever a JSONObject is serialized
    JSONObject.toString.overload().implementation = function() {
        var s = this.toString()
        if (s.includes('token') || s.includes('auth')) send(s)
        return s
    }
})

── RPC EXPORTS (LOADED SCRIPTS) ──────────────────────────────────────────────
rpc.exports                         → object with all exported methods

Script 23 — boughtNum intercept:
  rpc.exports.status()              → {armed, injectCount, missCount, targetQty}
  rpc.exports.arm()                 → manually arm the boughtNum intercept
  rpc.exports.setQty(99)            → change injection quantity

Script 24 — product ID capture:
  rpc.exports.products()            → [{id, info}, ...] captured product IDs
  rpc.exports.clear()               → clear the captured list

── LUA C API  (libgame.so — BLEACH: Soul Resonance) ─────────────────────────
var mod = Process.getModuleByName('libgame.so')

// Resolve function addresses:
mod.findExportByName('lua_pushstring')   // void(L, const char*)
mod.findExportByName('lua_rawget')       // void(L, int idx)
mod.findExportByName('lua_gettable')     // void(L, int idx)
mod.findExportByName('lua_type')         // int(L, int idx)
mod.findExportByName('lua_tointegerx')   // int64(L, int, int*)
mod.findExportByName('lua_settop')       // void(L, int idx)
mod.findExportByName('lua_pushinteger')  // void(L, int64)
mod.findExportByName('lua_tolstring')    // char*(L, int, size_t*)

// Lua type constants:
//   LUA_TNIL=0  LUA_TBOOLEAN=1  LUA_TNUMBER=3  LUA_TSTRING=4  LUA_TTABLE=5

// Call lua_type (check what's at stack[-1]):
var fnType = new NativeFunction(
    mod.findExportByName('lua_type'), 'int', ['pointer','int'])
fnType(L, -1)    // where L = lua_State* captured in onEnter

── SSL / NETWORK ─────────────────────────────────────────────────────────────
Module.findExportByName(null,'SSL_read')    → NativePointer or null
Module.findExportByName(null,'SSL_write')   → NativePointer or null
Module.findExportByName(null,'connect')     → socket connect
Module.findExportByName(null,'send')        → socket send
Module.findExportByName(null,'recv')        → socket recv

── USEFUL SNIPPETS ───────────────────────────────────────────────────────────
// List all loaded modules sorted by name:
Process.enumerateModules().map(m=>m.name).sort().join('\n')

// Find all exports containing 'lua':
Module.enumerateExports('libgame.so').filter(e=>e.name.includes('lua')).map(e=>e.name).join('\n')

// Dump 64 bytes at an address:
hexdump(ptr('0x12345678'), {length:64, header:true})

// Read a C string at a computed offset:
var base = Module.findBaseAddress('libgame.so')
base.add(0x1a2b3c).readCString()

// Enumerate classes matching a pattern (safe, no Java.use needed):
Java.enumerateLoadedClassesSync().filter(c=>c.includes('Mall'))
""".trimIndent()

    // =========================================================================
    // TRAFFIC TAB
    // =========================================================================

    private fun buildTrafficTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        // Toolbar — "Load Proxy History" removed: loading all request/response bodies caused OOM.
        // Use the Geo Map tab to geolocate proxy traffic without duplicating data into memory.
        val repeaterBtn   = JButton("Send to Repeater")
        val intruderBtn   = JButton("Send to Intruder")
        val exportCsvBtn  = JButton("Export CSV")

        repeaterBtn.addActionListener {
            val row = trafficTable.selectedRow
            if (row >= 0) controller.sendEntryToRepeater(trafficTableModel.entryAt(trafficTable.convertRowIndexToModel(row)))
        }
        intruderBtn.addActionListener {
            val row = trafficTable.selectedRow
            if (row >= 0) controller.sendEntryToIntruder(trafficTableModel.entryAt(trafficTable.convertRowIndexToModel(row)))
        }
        exportCsvBtn.addActionListener {
            val chooser = JFileChooser(System.getProperty("user.home"))
            chooser.dialogTitle = "Save CSV"
            chooser.selectedFile = java.io.File("fridalink_traffic.csv")
            if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                controller.exportTrafficCsv(chooser.selectedFile)
            }
        }

        // Filter
        trafficFilterField.toolTipText = "Filter by host / path / method"
        trafficFilterField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = applyTrafficFilter()
            override fun removeUpdate(e: DocumentEvent?) = applyTrafficFilter()
            override fun changedUpdate(e: DocumentEvent?) = applyTrafficFilter()
        })

        val toolBar = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        toolBar.add(JLabel("Filter:")); toolBar.add(trafficFilterField)
        toolBar.add(repeaterBtn); toolBar.add(intruderBtn); toolBar.add(exportCsvBtn)
        toolBar.add(trafficStatusLabel)

        // Table
        trafficTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        trafficTable.autoCreateRowSorter = true
        trafficTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                val row = trafficTable.selectedRow
                if (row >= 0) {
                    val entry = trafficTableModel.entryAt(trafficTable.convertRowIndexToModel(row))
                    trafficDetailText.text = formatTrafficEntry(entry)
                    trafficDetailText.caretPosition = 0
                }
            }
        }

        trafficDetailText.isEditable = false
        trafficDetailText.lineWrap = false
        trafficDetailText.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            JScrollPane(trafficTable),
            JScrollPane(trafficDetailText))
        split.resizeWeight = 0.60

        panel.add(toolBar, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)
        return panel
    }

    private fun applyTrafficFilter() {
        trafficTableModel.filterText = trafficFilterField.text
        trafficTableModel.applyFilter()
    }

    private fun formatTrafficEntry(e: fridalink.model.TrafficEntry): String = buildString {
        appendLine("═══ REQUEST ═══════════════════════════════════════════")
        appendLine("${e.method} ${e.url}")
        appendLine("")
        if (e.requestHeaders.isNotBlank()) { appendLine(e.requestHeaders); appendLine("") }
        if (e.requestBody.isNotBlank()) { appendLine(e.requestBody); appendLine("") }
        appendLine("═══ RESPONSE ══════════════════════════════════════════")
        appendLine("HTTP ${e.statusCode}  ${e.mimeType}")
        appendLine("")
        if (e.responseHeaders.isNotBlank()) { appendLine(e.responseHeaders); appendLine("") }
        if (e.responseBody.isNotBlank()) appendLine(e.responseBody)
        if (e.params.isNotEmpty()) { appendLine(""); appendLine("Parameters: ${e.params.joinToString(", ")}") }
        if (e.ip.isNotBlank()) appendLine("Server IP: ${e.ip}")
    }

    // =========================================================================
    // FRIDA TRACE TAB
    // =========================================================================

    private fun buildFridaTraceTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        // Mutual-exclusivity warning banner
        val warningText = JTextArea(
            "⚠  IMPORTANT: frida-trace runs its own Frida instance and CANNOT run at the same time as the Script Library.\n" +
            "   If Script Library scripts are currently injected, stop them first (Detach from the main toolbar).\n" +
            "   Trying to use both simultaneously will cause conflicts — only one Frida session per device at a time."
        )
        warningText.isEditable  = false
        warningText.lineWrap    = true
        warningText.wrapStyleWord = true
        warningText.font        = java.awt.Font("SansSerif", java.awt.Font.BOLD, 11)
        warningText.foreground  = Color(120, 60, 0)
        warningText.background  = Color(255, 243, 205)
        warningText.border      = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(200, 140, 0), 1),
            BorderFactory.createEmptyBorder(6, 8, 6, 8),
        )

        val startBtn = JButton("Start Frida Trace")
        val stopBtn  = JButton("Stop")
        val clearBtn = JButton("Clear")
        val statusLbl = JLabel("Not running")

        startBtn.addActionListener {
            val include = fridaIncludeField.text.split(",").map { it.trim() }.filter { it.isNotBlank() }
            val exclude = fridaExcludeField.text.split(",").map { it.trim() }.filter { it.isNotBlank() }
            val cfg = fridalink.model.FridaTraceConfig(
                targetPkg       = fridaTargetField.text.trim(),
                includePatterns = include,
                excludePatterns = exclude,
            )
            val workDir = java.io.File(fridaWorkDirField.text.ifBlank { System.getProperty("user.dir") })
            controller.startFridaTrace(cfg, workDir)
            statusLbl.text = "Running..."
            statusLbl.foreground = Color(0, 150, 0)
        }
        stopBtn.addActionListener {
            controller.stopFridaTrace()
            statusLbl.text = "Stopped"
            statusLbl.foreground = Color(180, 0, 0)
        }
        clearBtn.addActionListener { fridaTraceOutput.text = "" }

        val cfg = JPanel(java.awt.GridLayout(0, 2, 6, 4))
        cfg.border = BorderFactory.createTitledBorder("Configuration")
        cfg.add(JLabel("Target Package")); cfg.add(fridaTargetField)
        cfg.add(JLabel("Include patterns (comma-sep)")); cfg.add(fridaIncludeField)
        cfg.add(JLabel("Exclude patterns")); cfg.add(fridaExcludeField)
        cfg.add(JLabel("Work directory")); cfg.add(fridaWorkDirField)

        val btnRow = JPanel(WrapLayout(FlowLayout.LEFT))
        btnRow.add(startBtn); btnRow.add(stopBtn); btnRow.add(clearBtn); btnRow.add(statusLbl)

        val helpText = JTextArea("""
frida-trace must be installed: pip install frida-tools

Include pattern examples:
  SSL_*          — all OpenSSL functions
  ikcp_*         — KCP game protocol
  Java_com_*     — JNI exports
  getaddrinfo    — DNS resolution
  recv           — raw socket recv

The __handlers__/ directory will contain generated JS files.
Edit them to modify arguments or return values.
        """.trimIndent())
        helpText.isEditable = false
        helpText.background = Color(245, 248, 255)
        helpText.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 10)

        fridaTraceOutput.isEditable = false
        fridaTraceOutput.lineWrap = false
        fridaTraceOutput.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 10)

        val top = JPanel(BorderLayout())
        top.add(warningText, BorderLayout.NORTH)
        top.add(cfg, BorderLayout.CENTER)
        top.add(btnRow, BorderLayout.SOUTH)

        val left = JPanel(BorderLayout())
        left.add(top, BorderLayout.NORTH)
        left.add(JScrollPane(helpText), BorderLayout.CENTER)
        left.minimumSize = Dimension(220, 100)

        val logPanel = JScrollPane(fridaTraceOutput)
        logPanel.minimumSize = Dimension(300, 100)

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, logPanel)
        split.resizeWeight = 0.35
        split.isOneTouchExpandable = true
        split.dividerSize = 8

        panel.add(split, BorderLayout.CENTER)
        return panel
    }

    // =========================================================================
    // MASVS TAB
    // =========================================================================

    private fun buildMasvsTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val initBtn   = JButton("Load Checklist")
        val evalBtn   = JButton("Re-evaluate")
        val passBtn   = JButton("Mark PASS")
        val failBtn   = JButton("Mark FAIL")
        val naBtn     = JButton("Mark N/A")

        initBtn.addActionListener { controller.initMasvsChecklist() }
        evalBtn.addActionListener { controller.reevaluateMasvs() }

        passBtn.addActionListener { updateSelectedMasvsStatus(fridalink.model.MasvsStatus.PASS) }
        failBtn.addActionListener { updateSelectedMasvsStatus(fridalink.model.MasvsStatus.FAIL) }
        naBtn.addActionListener   { updateSelectedMasvsStatus(fridalink.model.MasvsStatus.NOT_APPLICABLE) }

        // ADB device-level checks panel
        val checkAdbBtn = JButton("Check ADB")
        val runAdbBtn   = JButton("Run ADB Checks")
        adbPkgField.toolTipText = "Package name to test (e.g. com.example.app)"
        adbDeviceCombo.toolTipText = "Select target device — USB devices are preferred automatically; TCP addresses matching the sidecar host are excluded"
        adbDeviceCombo.preferredSize = java.awt.Dimension(220, adbDeviceCombo.preferredSize.height)

        checkAdbBtn.addActionListener { controller.checkAdbAvailability() }
        runAdbBtn.addActionListener {
            val pkg    = adbPkgField.text.trim()
            val selected = adbDeviceCombo.selectedItem as? String ?: ""
            val serial = if (selected.startsWith("(auto")) null else selected.substringBefore(" (")
            controller.runAdbMasvsChecks(pkg, serial)
        }

        val adbRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        adbRow.border = BorderFactory.createTitledBorder("ADB Device Checks  (requires adb on PATH + device connected)")
        hostEnvLabel.toolTipText = "Detected at startup. Git Bash is needed for host-side bash pipe commands on Windows."
        adbRow.add(hostEnvLabel)
        adbRow.add(JLabel("  |  Package:")); adbRow.add(adbPkgField)
        adbRow.add(JLabel("Device:")); adbRow.add(adbDeviceCombo)
        adbRow.add(checkAdbBtn); adbRow.add(runAdbBtn); adbRow.add(adbStatusLabel)

        masvsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        masvsTable.autoCreateRowSorter = true
        masvsTable.setDefaultRenderer(Any::class.java, MasvsStatusRenderer(masvsTableModel))
        masvsTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                val row = masvsTable.selectedRow
                if (row >= 0) {
                    val item = masvsTableModel.itemAt(masvsTable.convertRowIndexToModel(row))
                    masvsDetailText.text = formatMasvsItem(item)
                    masvsDetailText.caretPosition = 0
                }
            }
        }

        masvsDetailText.isEditable = false
        masvsDetailText.lineWrap = true
        masvsDetailText.wrapStyleWord = true
        masvsDetailText.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)

        val toolBar = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        toolBar.add(initBtn); toolBar.add(evalBtn); toolBar.add(passBtn)
        toolBar.add(failBtn); toolBar.add(naBtn); toolBar.add(masvsStatusLabel)

        // Right panel: detail text on top, raw ADB results on bottom
        val rightSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            JScrollPane(masvsDetailText),
            JScrollPane(adbRawResultsText))
        rightSplit.resizeWeight = 0.50
        rightSplit.isOneTouchExpandable = true
        val adbLabel = JLabel("  Raw ADB Check Output").also {
            it.font = it.font.deriveFont(java.awt.Font.BOLD)
            it.border = BorderFactory.createEmptyBorder(4, 4, 2, 4)
        }
        val rightPanel = JPanel(BorderLayout())
        rightPanel.add(adbLabel, BorderLayout.NORTH)
        rightPanel.add(rightSplit, BorderLayout.CENTER)

        val mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            JScrollPane(masvsTable), rightPanel)
        mainSplit.resizeWeight = 0.55
        mainSplit.isOneTouchExpandable = true

        val north = JPanel(BorderLayout())
        north.add(toolBar, BorderLayout.NORTH)
        north.add(adbRow, BorderLayout.SOUTH)

        panel.add(north, BorderLayout.NORTH)
        panel.add(mainSplit, BorderLayout.CENTER)
        return panel
    }

    private fun updateSelectedMasvsStatus(status: fridalink.model.MasvsStatus) {
        val row = masvsTable.selectedRow
        if (row < 0) return
        val item = masvsTableModel.itemAt(masvsTable.convertRowIndexToModel(row))
        controller.updateMasvsItem(item.id, status, item.notes)
    }

    private fun formatMasvsItem(item: fridalink.model.MasvsItem): String = buildString {
        appendLine("ID:          ${item.id}")
        appendLine("Category:    ${item.category}")
        appendLine("Level:       ${item.level}")
        appendLine("Test ID:     ${item.testId}")
        appendLine("Status:      ${item.status}")
        appendLine("")
        appendLine("Control:")
        appendLine("  ${item.control}")
        appendLine("")
        appendLine("Description:")
        item.description.lines().forEach { appendLine("  $it") }
        if (item.evidence.isNotBlank()) {
            appendLine("")
            appendLine("Evidence:")
            item.evidence.lines().forEach { appendLine("  $it") }
        }
        if (item.notes.isNotBlank()) {
            appendLine("")
            appendLine("Notes:")
            appendLine("  ${item.notes}")
        }
    }

    // =========================================================================
    // STATIC ANALYSIS TAB
    // =========================================================================

    private fun buildStaticAnalysisTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val browseBtn       = JButton("Browse APK…")
        val analyzeBtn      = JButton("Analyze APK")
        val browseDecompBtn = JButton("Browse jadx dir…")
        val scanSrcBtn      = JButton("Scan Source")

        browseBtn.addActionListener {
            val chooser = JFileChooser()
            chooser.fileFilter = javax.swing.filechooser.FileNameExtensionFilter("APK files", "apk")
            chooser.dialogTitle = "Select APK"
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                apkPathField.text = chooser.selectedFile.absolutePath
            }
        }
        analyzeBtn.addActionListener {
            if (apkPathField.text.isNotBlank()) {
                controller.analyzeApk(apkPathField.text.trim())
                staticStatusLabel.text = "Analyzing..."
            }
        }
        browseDecompBtn.addActionListener {
            val chooser = JFileChooser()
            chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            chooser.dialogTitle = "Select jadx decompiled output directory"
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                decompSrcField.text = chooser.selectedFile.absolutePath
            }
        }
        scanSrcBtn.addActionListener {
            val dir = decompSrcField.text.trim()
            if (dir.isNotBlank()) {
                controller.analyzeDecompiledSource(dir)
                staticStatusLabel.text = "Scanning source..."
            }
        }
        decompSrcField.toolTipText = "Path to jadx-decompiled APK directory (contains sources/ and resources/)"

        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        findingsTable.autoCreateRowSorter = true
        findingsTable.setDefaultRenderer(Any::class.java, FindingsSeverityRenderer(findingsTableModel))
        findingsTable.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                val row = findingsTable.selectedRow
                if (row >= 0) {
                    val f = findingsTableModel.findingAt(findingsTable.convertRowIndexToModel(row))
                    findingDetailText.text = formatFinding(f)
                    findingDetailText.caretPosition = 0
                }
            }
        }
        findingDetailText.isEditable = false
        findingDetailText.lineWrap = true
        findingDetailText.wrapStyleWord = true
        findingDetailText.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11)

        // URL table
        urlTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        urlTable.autoCreateRowSorter = true
        urlTable.columnModel.getColumn(0).preferredWidth = 340
        urlTable.columnModel.getColumn(1).preferredWidth = 160
        urlTable.columnModel.getColumn(2).preferredWidth = 55
        urlTable.columnModel.getColumn(3).preferredWidth = 200

        // Library table
        libraryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        libraryTable.autoCreateRowSorter = true
        libraryTable.setDefaultRenderer(Any::class.java, LibraryRiskRenderer(libraryTableModel))
        libraryTable.columnModel.getColumn(0).preferredWidth = 200
        libraryTable.columnModel.getColumn(1).preferredWidth = 200
        libraryTable.columnModel.getColumn(2).preferredWidth = 80
        libraryTable.columnModel.getColumn(3).preferredWidth = 320
        libraryTable.selectionModel.addListSelectionListener { e: ListSelectionEvent ->
            if (!e.valueIsAdjusting) {
                val row = libraryTable.selectedRow
                if (row >= 0) {
                    val lib = libraryTableModel.libraryAt(libraryTable.convertRowIndexToModel(row))
                    libraryDetailText.text = formatLibraryDetail(lib)
                    libraryDetailText.caretPosition = 0
                    extractLibBtn.isEnabled = lib.risk != "none"
                    // wire extract action each time selection changes (captures current lib)
                    for (l in extractLibBtn.actionListeners) extractLibBtn.removeActionListener(l)
                    extractLibBtn.addActionListener {
                        extractLibraryFromApk(lib, apkPathField.text.trim())
                    }
                } else {
                    libraryDetailText.text = "Select a library row to see verbose details."
                    extractLibBtn.isEnabled = false
                }
            }
        }

        val apkRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        apkRow.add(JLabel("APK:")); apkRow.add(apkPathField)
        apkRow.add(browseBtn); apkRow.add(analyzeBtn); apkRow.add(staticStatusLabel)
        val srcRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        srcRow.add(JLabel("jadx dir:")); srcRow.add(decompSrcField)
        srcRow.add(browseDecompBtn); srcRow.add(scanSrcBtn)
        srcRow.add(JLabel("(optional — scans decompiled Java source for deeper findings)").also {
            it.font = it.font.deriveFont(java.awt.Font.ITALIC, 10f); it.foreground = Color.GRAY })
        val pathRow = JPanel()
        pathRow.layout = BoxLayout(pathRow, BoxLayout.Y_AXIS)
        pathRow.add(apkRow)
        pathRow.add(srcRow)

        // Findings sub-tab
        val findingsSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT,
            JScrollPane(findingsTable),
            JScrollPane(findingDetailText))
        findingsSplit.resizeWeight = 0.55

        // URL sub-tab
        val urlPanel = JPanel(BorderLayout())
        urlPanel.add(JScrollPane(urlTable), BorderLayout.CENTER)

        // Libraries sub-tab — table + detail pane + extract button
        val libExtractRow = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        libExtractRow.add(extractLibBtn)
        libExtractRow.add(JLabel("(only enabled for libraries with risk > none)").also {
            it.font = it.font.deriveFont(java.awt.Font.ITALIC, 10f)
            it.foreground = Color.GRAY
        })
        val libDetailPanel = JPanel(BorderLayout())
        libDetailPanel.add(JLabel("  Details:").also { it.font = it.font.deriveFont(java.awt.Font.BOLD) }, BorderLayout.NORTH)
        libDetailPanel.add(JScrollPane(libraryDetailText), BorderLayout.CENTER)
        libDetailPanel.add(libExtractRow, BorderLayout.SOUTH)
        val libSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(libraryTable), libDetailPanel)
        libSplit.resizeWeight = 0.45
        libSplit.isOneTouchExpandable = true
        val libPanel = JPanel(BorderLayout())
        libPanel.add(libSplit, BorderLayout.CENTER)

        // Certificate sub-tab
        val certPanel = JPanel(BorderLayout())
        val certToolBar = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        val pullCertBtn = JButton("Pull Cert via ADB")
        pullCertBtn.toolTipText = "Pull the APK from the connected device and extract its signing certificate"
        pullCertBtn.addActionListener {
            val pkg    = adbPkgField.text.trim().ifBlank { "com.crunchyroll.bleachsoulres" }
            val selected = adbDeviceCombo.selectedItem as? String ?: ""
            val serial = if (selected.startsWith("(auto")) null else selected.substringBefore(" (")
            // Clear existing text so the render update triggers a refresh
            certInfoText.text = ""
            controller.pullCertViaAdb(pkg, serial)
        }
        certToolBar.add(pullCertBtn)
        certToolBar.add(JLabel("(requires ADB — same package/serial as MASVS tab)").also {
            it.font = it.font.deriveFont(java.awt.Font.ITALIC, 10f); it.foreground = Color.GRAY })
        certPanel.add(certToolBar, BorderLayout.NORTH)
        certPanel.add(JScrollPane(certInfoText), BorderLayout.CENTER)

        // Behavior sub-tab
        val behaviorPanel = JPanel(BorderLayout())
        behaviorPanel.add(JScrollPane(behaviorProfileText), BorderLayout.CENTER)

        val subTabs = JTabbedPane()
        subTabs.addTab("Findings", findingsSplit)
        subTabs.addTab("URLs", urlPanel)
        subTabs.addTab("Libraries", libPanel)
        subTabs.addTab("Certificate", certPanel)
        subTabs.addTab("Behavior", behaviorPanel)

        panel.add(pathRow, BorderLayout.NORTH)
        panel.add(subTabs, BorderLayout.CENTER)
        return panel
    }

    private fun formatFinding(f: fridalink.model.ApkFinding): String = buildString {
        appendLine("Severity:   ${f.severity}")
        appendLine("Category:   ${f.category}")
        appendLine("MASVS Ref:  ${f.masvsRef.ifBlank { "N/A" }}")
        appendLine("CWE:        ${f.cweRef.ifBlank { "N/A" }}")
        appendLine("CVSS:       ${f.cvssScore}")
        appendLine("")
        appendLine("Title:")
        appendLine("  ${f.title}")
        appendLine("")
        appendLine("Description:")
        f.description.lines().forEach { appendLine("  $it") }
        appendLine("")
        appendLine("Evidence:")
        f.evidence.lines().forEach { appendLine("  $it") }
        appendLine("")
        appendLine("Mitigation:")
        f.mitigation.lines().forEach { appendLine("  $it") }
    }

    private fun formatLibraryDetail(lib: fridalink.model.LibraryInfo): String = buildString {
        appendLine("Library:       ${lib.displayName}")
        appendLine("Package:       ${lib.packagePrefix}")
        appendLine("Risk:          ${lib.risk.uppercase()}")
        if (lib.knownIssue.isNotBlank()) {
            appendLine("Known Issue:   ${lib.knownIssue}")
        }
        if (lib.foundNativeLibs.isNotEmpty()) {
            appendLine("")
            appendLine("Native .so files found in this APK:")
            lib.foundNativeLibs.forEach { appendLine("  $it") }
        } else if (lib.nativeLibHints.isNotEmpty()) {
            appendLine("")
            appendLine("Known native lib hints (not found in this APK build):")
            appendLine("  ${lib.nativeLibHints.joinToString(", ")}")
        }
        appendLine("")
        appendLine("─".repeat(72))
        appendLine("")
        if (lib.details.isNotBlank()) {
            lib.details.trimIndent().lines().forEach { appendLine(it) }
        } else {
            appendLine("No additional details available.")
        }
    }

    private fun extractLibraryFromApk(lib: fridalink.model.LibraryInfo, apkPath: String) {
        if (apkPath.isBlank()) {
            javax.swing.JOptionPane.showMessageDialog(null,
                "No APK path set. Run static analysis first.", "Extract Library", javax.swing.JOptionPane.WARNING_MESSAGE)
            return
        }
        // If no native libs were pre-found during analysis, inform user immediately
        if (lib.foundNativeLibs.isEmpty()) {
            val msg = buildString {
                appendLine("No native .so files for '${lib.displayName}' were found in this APK.")
                appendLine("")
                appendLine("This SDK is DEX-only (pure Java/Kotlin code).")
                appendLine("To inspect it, decompile with jadx and navigate to:")
                appendLine("  ${lib.packagePrefix.replace('.', '/')}/")
                if (lib.nativeLibHints.isNotEmpty()) {
                    appendLine("")
                    appendLine("Known native hints (not present in this build):")
                    lib.nativeLibHints.forEach { appendLine("  $it") }
                }
            }
            javax.swing.JOptionPane.showMessageDialog(null, msg, "Extract Library — DEX Only",
                javax.swing.JOptionPane.INFORMATION_MESSAGE)
            return
        }

        val chooser = JFileChooser()
        chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
        chooser.dialogTitle = "Choose output directory (will extract ${lib.foundNativeLibs.size} .so file(s))"
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return
        val outDir = chooser.selectedFile

        Thread {
            try {
                val extracted = mutableListOf<String>()
                java.util.zip.ZipFile(apkPath).use { zip ->
                    for (entryPath in lib.foundNativeLibs) {
                        val entry = zip.getEntry(entryPath) ?: continue
                        // Preserve lib/arch/ directory structure
                        val outFile = java.io.File(outDir, entryPath.replace('/', java.io.File.separatorChar))
                        outFile.parentFile?.mkdirs()
                        zip.getInputStream(entry).use { input ->
                            outFile.outputStream().use { output -> input.copyTo(output) }
                        }
                        extracted.add(outFile.absolutePath)
                    }
                }

                SwingUtilities.invokeLater {
                    if (extracted.isEmpty()) {
                        javax.swing.JOptionPane.showMessageDialog(null,
                            "Extraction failed — entries not found in APK ZIP.\n" +
                            "The APK may have been replaced since analysis was run.",
                            "Extract Library", javax.swing.JOptionPane.WARNING_MESSAGE)
                    } else {
                        javax.swing.JOptionPane.showMessageDialog(null,
                            "Extracted ${extracted.size} file(s) to:\n${outDir.absolutePath}\n\n" +
                            extracted.joinToString("\n") + "\n\nNext steps:\n" +
                            "• Disassemble with: aarch64-linux-gnu-objdump -d <file>\n" +
                            "• Analyze with Ghidra: File → Import File\n" +
                            "• Hook at runtime with Frida: Module.findExportByName(\"${lib.foundNativeLibs.first().substringAfterLast('/')}\", \"...\")",
                            "Extract Library", javax.swing.JOptionPane.INFORMATION_MESSAGE)
                    }
                }
            } catch (ex: Exception) {
                SwingUtilities.invokeLater {
                    javax.swing.JOptionPane.showMessageDialog(null,
                        "Extraction failed: ${ex.message}", "Error", javax.swing.JOptionPane.ERROR_MESSAGE)
                }
            }
        }.also { it.isDaemon = true }.start()
    }

    // =========================================================================
    // GEO MAP TAB
    // =========================================================================

    private fun buildGeoMapTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val geoAllBtn     = JButton("Geolocate from Proxy History")
        val geoEventsBtn  = JButton("Geo from Live Events")
        val analyzeFgnBtn = JButton("Analyze Foreign Traffic")
        val clearBtn      = JButton("Clear")
        // Pull unique hosts directly from Burp proxy history — no full body loading, no OOM
        geoAllBtn.addActionListener { controller.geolocateFromBurpProxy() }
        // Extract IPs/hosts from the Frida live event stream (dns, caller_net, etc.)
        geoEventsBtn.toolTipText = "Extract IPs and hostnames from live Frida events and geolocate them"
        geoEventsBtn.addActionListener { controller.geolocateFromEventStream() }
        analyzeFgnBtn.addActionListener {
            foreignTrafficText.text = controller.analyzeForeignTraffic()
            foreignTrafficText.caretPosition = 0
        }
        clearBtn.addActionListener { }

        geoTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        geoTable.setDefaultRenderer(Any::class.java, GeoStatusRenderer(geoTableModel))
        // Column widths: Host, IP, Country, Code, City, ISP/Org, US?, Threat
        geoTable.columnModel.getColumn(0).preferredWidth = 200
        geoTable.columnModel.getColumn(1).preferredWidth = 110
        geoTable.columnModel.getColumn(2).preferredWidth = 100
        geoTable.columnModel.getColumn(3).preferredWidth = 40
        geoTable.columnModel.getColumn(4).preferredWidth = 100
        geoTable.columnModel.getColumn(5).preferredWidth = 160
        geoTable.columnModel.getColumn(6).preferredWidth = 70
        geoTable.columnModel.getColumn(7).preferredWidth = 200  // Threat label

        val toolBar = JPanel(WrapLayout(FlowLayout.LEFT, 4, 2))
        toolBar.add(geoAllBtn); toolBar.add(geoEventsBtn); toolBar.add(analyzeFgnBtn); toolBar.add(clearBtn)
        toolBar.add(geoStatusLabel)

        worldMapPanel.minimumSize = Dimension(400, 250)
        worldMapPanel.preferredSize = Dimension(600, 300)

        val tableSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            JScrollPane(geoTable), JScrollPane(foreignTrafficText))
        tableSplit.resizeWeight = 0.60

        val mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, worldMapPanel, tableSplit)
        mainSplit.resizeWeight = 0.45

        panel.add(toolBar, BorderLayout.NORTH)
        panel.add(mainSplit, BorderLayout.CENTER)
        return panel
    }

    // =========================================================================
    // REPORT TAB
    // =========================================================================

    private fun buildReportTab(): JComponent {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val browseBtn  = JButton("Output…")
        val genBtn     = JButton("Generate PDF Report")

        browseBtn.addActionListener {
            val chooser = JFileChooser(System.getProperty("user.home"))
            chooser.selectedFile = java.io.File("FridaLink_Report.pdf")
            chooser.fileFilter = javax.swing.filechooser.FileNameExtensionFilter("PDF files", "pdf")
            if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                reportOutputField.text = chooser.selectedFile.absolutePath
            }
        }

        genBtn.addActionListener {
            val out = java.io.File(reportOutputField.text.ifBlank { System.getProperty("user.home") + "/FridaLink_Report.pdf" })
            controller.generateReport(out, reportTargetField.text, reportAssessorField.text, reportEngagementField.text)
        }

        reportStatusArea.isEditable = false
        reportStatusArea.lineWrap = true
        reportStatusArea.wrapStyleWord = true
        reportStatusArea.font = java.awt.Font("Monospaced", java.awt.Font.PLAIN, 10)

        val form = JPanel(java.awt.GridLayout(0, 2, 6, 6))
        form.border = BorderFactory.createTitledBorder("Report Configuration")
        form.add(JLabel("Target Application")); form.add(reportTargetField)
        form.add(JLabel("Assessor Name"));      form.add(reportAssessorField)
        form.add(JLabel("Engagement ID"));      form.add(reportEngagementField)
        form.add(JLabel("Output File (PDF)"));  form.add(JPanel(WrapLayout(FlowLayout.LEFT, 2, 0)).also {
            it.add(reportOutputField); it.add(browseBtn)
        })

        val infoText = JTextArea("""
Report Sections Generated:
  1. Cover Page
  2. Engagement Overview & Methodology
  3. Executive Summary (with jurisdiction warnings)
  4. Detailed Findings (CVSS scores + mitigations)
  5. OWASP MASVS v2 Checklist Results
  6. Network Traffic Analysis
  7. Server Geolocation — Non-US servers flagged in RED
  8. Appendix (all captured URLs)

Pre-requisites for a complete report:
  • Run APK static analysis (Static Analysis tab)
  • Load Burp proxy history (Traffic tab)
  • Geolocate all servers (Geo Map tab)
  • Initialize/evaluate MASVS checklist (MASVS tab)
        """.trimIndent())
        infoText.isEditable = false
        infoText.background = Color(245, 248, 252)
        infoText.font = java.awt.Font("SansSerif", java.awt.Font.PLAIN, 11)

        val top = JPanel(BorderLayout())
        top.add(form, BorderLayout.NORTH)
        top.add(JScrollPane(infoText), BorderLayout.CENTER)
        top.add(JPanel(WrapLayout(FlowLayout.LEFT)).also { it.add(genBtn) }, BorderLayout.SOUTH)

        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(reportStatusArea), BorderLayout.CENTER)
        return panel
    }

    // =========================================================================
    // Render sync for new tabs
    // =========================================================================

    private fun syncNewTabs(state: FridaLinkState) {
        // RPC Console — collect rpc_result events and append new ones to the text area
        val rpcEvents = state.events.filter { it.category == "rpc_result" }
        if (rpcEvents.size != lastRpcResultCount) {
            lastRpcResultCount = rpcEvents.size
            val sb = StringBuilder()
            rpcEvents.asReversed().forEach { ev ->
                sb.append("── ").append(ev.timestamp.take(19)).append(" │ ").append(ev.target).appendLine(" ─────────────────────")
                sb.appendLine(ev.summary)
                if (ev.args.isNotBlank() && ev.args != "{}") {
                    try {
                        val parsed = com.fasterxml.jackson.module.kotlin.jacksonObjectMapper().readTree(ev.args)
                        val resultNode = parsed.get("result")
                        if (resultNode != null) {
                            sb.appendLine(parsed.toPrettyString())
                        } else {
                            sb.appendLine(ev.args)
                        }
                    } catch (e: Exception) {
                        sb.appendLine(ev.args)
                    }
                }
                sb.appendLine()
            }
            val newText = sb.toString()
            if (rpcResultText.text != newText) {
                rpcResultText.text = newText
                rpcResultText.caretPosition = 0
            }
            if (rpcEvents.isNotEmpty()) {
                rpcStatusLabel.text = "${rpcEvents.size} RPC result(s) received — last: ${rpcEvents.first().target}"
            }
        }

        // Frida REPL — append only new entries (newest-first in state, so prepend order)
        if (state.replHistory.size != lastReplHistorySize) {
            val newCount = state.replHistory.size - lastReplHistorySize
            lastReplHistorySize = state.replHistory.size
            // The first newCount entries in replHistory are the newest (just added)
            state.replHistory.take(newCount).asReversed().forEach { appendReplEntry(it) }
        }

        // Traffic
        trafficTableModel.setEntries(state.trafficEntries)
        trafficStatusLabel.text = "${state.trafficEntries.size} entries  |  " +
            "${state.trafficEntries.map { it.host }.distinct().size} unique hosts"

        // Frida trace
        if (state.fridaTraceOutput.isNotEmpty()) {
            val text = state.fridaTraceOutput.takeLast(2000).joinToString("\n")
            if (fridaTraceOutput.text != text) {
                fridaTraceOutput.text = text
                fridaTraceOutput.caretPosition = fridaTraceOutput.document.length
            }
        }

        // MASVS
        masvsTableModel.setItems(state.masvsItems)
        val failCnt = state.masvsItems.count { it.status == fridalink.model.MasvsStatus.FAIL }
        val passCnt = state.masvsItems.count { it.status == fridalink.model.MasvsStatus.PASS }
        masvsStatusLabel.text = "${state.masvsItems.size} controls  |  FAIL:$failCnt  PASS:$passCnt"

        // APK findings + deep analysis
        findingsTableModel.setFindings(state.apkFindings)
        staticStatusLabel.text = if (state.apkFindings.isEmpty()) "No findings"
            else "${state.apkFindings.size} findings (${state.apkFindings.count { it.severity == fridalink.model.FindingSeverity.CRITICAL || it.severity == fridalink.model.FindingSeverity.HIGH }} high+)"
        urlTableModel.setRefs(state.analysisUrlRefs)
        libraryTableModel.setLibraries(state.analysisLibraries)
        if (state.analysisCertInfo != null) {
            val newCertText = state.analysisCertInfo.rawText
            if (certInfoText.text != newCertText) {
                certInfoText.text = newCertText
                certInfoText.caretPosition = 0
            }
        }
        if (state.analysisBehaviorProfile.isNotBlank() && behaviorProfileText.text.isBlank()) {
            behaviorProfileText.text = state.analysisBehaviorProfile
            behaviorProfileText.caretPosition = 0
        }

        // Geo
        geoTableModel.setResults(state.geoResults.values.toList())
        worldMapPanel.updateLocations(state.geoResults.values.toList())
        val nonUs = state.geoResults.values.count { !it.isUS && it.status == "success" && it.countryCode != "LO" }
        geoStatusLabel.text = "${state.geoResults.size} IPs resolved  |  $nonUs non-US"
        if (nonUs > 0) geoStatusLabel.foreground = Color(200, 0, 0)
        else geoStatusLabel.foreground = Color.BLACK

        // Host environment
        val env = state.hostShellEnv
        if (env != null) {
            if (!env.isWindows) {
                hostEnvLabel.text = "Host: Linux/macOS | bash: OK"
                hostEnvLabel.foreground = java.awt.Color(0, 140, 0)
            } else if (env.hasBash) {
                hostEnvLabel.text = "Host: Windows | Git Bash: FOUND"
                hostEnvLabel.foreground = java.awt.Color(0, 140, 0)
            } else {
                hostEnvLabel.text = "Host: Windows | Git Bash: NOT FOUND — install from git-scm.com"
                hostEnvLabel.foreground = java.awt.Color(200, 100, 0)
            }
        }

        // ADB
        adbStatusLabel.text = state.adbStatus
        // Repopulate device combo when the device list changes
        val comboDeviceItems = buildList {
            add("(auto – USB preferred)")
            state.adbDevices.forEach { serial ->
                val label = if (serial.matches(Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+""")))
                    "$serial (TCP)" else "$serial (USB)"
                add(label)
            }
        }
        val currentItems = (0 until adbDeviceCombo.itemCount).map { adbDeviceCombo.getItemAt(it) }
        if (currentItems != comboDeviceItems) {
            val prevSelected = adbDeviceCombo.selectedItem as? String
            adbDeviceCombo.removeAllItems()
            comboDeviceItems.forEach { adbDeviceCombo.addItem(it) }
            val restored = comboDeviceItems.firstOrNull { it == prevSelected }
            if (restored != null) adbDeviceCombo.selectedItem = restored
        }
        if (state.adbRawDisplay.isNotBlank() && adbRawResultsText.text != state.adbRawDisplay) {
            adbRawResultsText.text = state.adbRawDisplay
            adbRawResultsText.caretPosition = 0
        }
        // Sync decompiled source path field if set programmatically
        if (state.decompSrcPath.isNotBlank() && decompSrcField.text.isBlank()) {
            decompSrcField.text = state.decompSrcPath
        }

        // Report
        if (state.reportStatus.isNotBlank()) {
            reportStatusArea.text = reportStatusArea.text + "\n" + state.reportStatus
        }
    }
}

// ---------------------------------------------------------------------------
// Table models
// ---------------------------------------------------------------------------

private class ProcessTableModel : AbstractTableModel() {
    private val columns = arrayOf("PID", "Name", "Platform", "State", "Sel", "Att")
    var rows: List<fridalink.model.TargetProcess> = emptyList()
        private set

    fun setRows(rows: List<fridalink.model.TargetProcess>) {
        this.rows = rows
        fireTableDataChanged()
    }

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = when (columnIndex) {
        0 -> rows[rowIndex].pid
        1 -> rows[rowIndex].name
        2 -> rows[rowIndex].platform
        3 -> rows[rowIndex].state
        4 -> rows[rowIndex].selected
        else -> rows[rowIndex].attached
    }

    fun pidAt(rowIndex: Int): Int? = rows.getOrNull(rowIndex)?.pid
}

/**
 * Event table model that maintains a full list plus a filtered view.
 * Filtering is applied in-memory; the table always shows filteredRows.
 */
class FilteredEventTableModel : AbstractTableModel() {
    private val columns = arrayOf("Sev", "Time", "Process", "Category", "Module", "Target", "Summary")
    private var allRows: List<RuntimeEvent> = emptyList()
    private var filteredRows: List<RuntimeEvent> = emptyList()

    var searchText: String = ""
    var categoryFilter: String = "All"
    var processFilter: String = "All"
    var moduleFilter: String = ""
    var targetFilter: String = ""
    var errorsOnly: Boolean = false
    var bookmarkedOnly: Boolean = false
    var bookmarkedIds: Set<String> = emptySet()

    fun setAllRows(rows: List<RuntimeEvent>) {
        allRows = rows
        applyFilter()
    }

    fun applyFilter() {
        val q = searchText.lowercase()
        val mf = moduleFilter.lowercase()
        val tf = targetFilter.lowercase()
        filteredRows = allRows.filter { e ->
            (categoryFilter == "All" || e.category == categoryFilter) &&
            (processFilter == "All" || e.process == processFilter) &&
            (!errorsOnly || e.severity == "error") &&
            (!bookmarkedOnly || e.id in bookmarkedIds) &&
            (mf.isBlank() || e.module.contains(mf, true)) &&
            (tf.isBlank() || e.target.contains(tf, true)) &&
            (q.isBlank() || e.process.contains(q, true) || e.module.contains(q, true) ||
                e.target.contains(q, true) || e.summary.contains(q, true) ||
                e.args.contains(q, true) || e.retval.contains(q, true))
        }
        fireTableDataChanged()
    }

    fun eventAt(rowIndex: Int): RuntimeEvent? = filteredRows.getOrNull(rowIndex)

    /** Find the row index of [event] after a model rebuild, matched by identity. */
    fun rowOf(event: RuntimeEvent): Int = filteredRows.indexOfFirst {
        it.timestamp == event.timestamp && it.module == event.module && it.summary == event.summary
    }

    override fun getRowCount(): Int = filteredRows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = with(filteredRows[rowIndex]) {
        when (columnIndex) {
            0 -> severity
            1 -> formatLocalTime(timestamp)
            2 -> process
            3 -> category
            4 -> module
            5 -> target
            else -> summary
        }
    }

    companion object {
        private val ISO_FORMATTERS = listOf(
            java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME,
            java.time.format.DateTimeFormatter.ISO_ZONED_DATE_TIME,
            java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME,
        )
        private val LOCAL_FMT = java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS")
        private val localZone = java.time.ZoneId.systemDefault()

        fun formatLocalTime(timestamp: String): String {
            if (timestamp.isBlank()) return ""
            for (fmt in ISO_FORMATTERS) {
                try {
                    val zdt = java.time.ZonedDateTime.parse(timestamp, fmt)
                    return zdt.withZoneSameInstant(localZone).format(LOCAL_FMT)
                } catch (_: Exception) {}
            }
            // Fallback: strip date and show time portion as-is
            return timestamp.substringAfterLast("T").take(12).ifBlank { timestamp.take(12) }
        }
    }
}

private class InterceptTableModel : AbstractTableModel() {
    private val columns = arrayOf("ID", "Time", "Process", "Direction", "Channel", "Summary")
    private var rows: List<InterceptItem> = emptyList()

    fun setRows(rows: List<InterceptItem>) {
        this.rows = rows
        fireTableDataChanged()
    }

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = when (columnIndex) {
        0 -> rows[rowIndex].id
        1 -> rows[rowIndex].timestamp
        2 -> rows[rowIndex].process
        3 -> rows[rowIndex].direction
        4 -> rows[rowIndex].channel
        else -> rows[rowIndex].summary
    }

    fun itemAt(rowIndex: Int): InterceptItem? = rows.getOrNull(rowIndex)
}

/**
 * Editable table model for Match & Replace rules.
 * Columns: On | URL Pattern | Match | Replace | Regex | Comment
 */
private class MatchReplaceTableModel(
    private val onEdit: (MatchReplaceRule) -> Unit = {},
) : AbstractTableModel() {
    private val columns = arrayOf("On", "URL Pattern", "Match", "Replace", "Regex", "Comment")
    private var rows: List<MatchReplaceRule> = emptyList()
    private var suppressEdit = false

    fun setRules(rules: List<MatchReplaceRule>) {
        suppressEdit = true
        rows = rules
        fireTableDataChanged()
        suppressEdit = false
    }

    fun ruleAt(rowIndex: Int): MatchReplaceRule? = rows.getOrNull(rowIndex)

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = true
    override fun getColumnClass(columnIndex: Int): Class<*> =
        if (columnIndex == 0 || columnIndex == 4) Boolean::class.javaObjectType else String::class.java

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = with(rows[rowIndex]) {
        when (columnIndex) {
            0 -> enabled
            1 -> urlPattern
            2 -> matchText
            3 -> replaceText
            4 -> isRegex
            else -> comment
        }
    }

    override fun setValueAt(value: Any?, rowIndex: Int, columnIndex: Int) {
        if (suppressEdit) return
        val rule = rows.getOrNull(rowIndex) ?: return
        val updated = when (columnIndex) {
            0 -> rule.copy(enabled = value as? Boolean ?: rule.enabled)
            1 -> rule.copy(urlPattern = value?.toString() ?: rule.urlPattern)
            2 -> rule.copy(matchText = value?.toString() ?: rule.matchText)
            3 -> rule.copy(replaceText = value?.toString() ?: rule.replaceText)
            4 -> rule.copy(isRegex = value as? Boolean ?: rule.isRegex)
            else -> rule.copy(comment = value?.toString() ?: rule.comment)
        }
        onEdit(updated)
    }
}

// ---------------------------------------------------------------------------
// Cell renderers
// ---------------------------------------------------------------------------

/**
 * Colors event rows by severity + bookmark + category.
 * Priority: bookmark (gold) > error (red) > inject-warn (orange) > warn (yellow) > category color > default.
 */
private class SeverityCellRenderer(private val model: FilteredEventTableModel) : DefaultTableCellRenderer() {
    private val errorBg    = Color(255, 210, 210)   // red — errors
    private val warnBg     = Color(255, 250, 195)   // yellow — general warnings
    private val bookmarkBg = Color(255, 236, 130)   // gold — bookmarks

    // Per-category background colors (applied when no severity override)
    private val categoryColors = mapOf(
        "dns"    to Color(205, 235, 255),   // sky blue   — DNS lookups
        "udp"    to Color(200, 248, 235),   // mint       — UDP game packets
        "native" to Color(235, 220, 255),   // lavender   — native socket / recv / send
        "socket" to Color(240, 228, 255),   // light violet
        "jni"    to Color(255, 238, 205),   // peach      — JNI library loads / RegisterNatives
        "http"   to Color(210, 255, 218),   // green      — OkHttp requests/responses
        "tls"    to Color(255, 215, 235),   // pink       — TLS/SSL events
        "ssl"    to Color(255, 215, 235),   // pink
        "hades"  to Color(255, 225, 180),   // amber      — Hades asset-patch SDK
        "inject" to Color(255, 165, 100),   // strong orange — active injection events
        "script" to Color(235, 235, 235),   // light gray — script load/status
        "spawn"  to Color(220, 245, 220),   // pale green — process spawn events
    )

    override fun getTableCellRendererComponent(
        table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int,
    ): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        if (!isSelected) {
            val event = model.eventAt(row)
            c.background = when {
                event != null && event.id in model.bookmarkedIds -> bookmarkBg
                event?.severity == "error"                       -> errorBg
                event?.severity == "warn" && event.category == "inject" -> Color(255, 140, 80)
                event?.severity == "warn"                        -> warnBg
                event != null -> categoryColors[event.category] ?: table.background
                else -> table.background
            }
        }
        return c
    }
}

/** Highlights attached-process rows in the process table. */
private class AttachedProcessRenderer(private val model: ProcessTableModel) : DefaultTableCellRenderer() {
    private val attachedBg = Color(220, 255, 220)
    private val selectedBg = Color(220, 235, 255)

    override fun getTableCellRendererComponent(
        table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int,
    ): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        if (!isSelected) {
            val modelRow = try { table.convertRowIndexToModel(row) } catch (e: Exception) { row }
            val process = model.rows.getOrNull(modelRow)
            c.background = when {
                process?.attached == true -> attachedBg
                process?.selected == true -> selectedBg
                else -> table.background
            }
        }
        return c
    }
}

/** Shows [enabled] badge in the library script list. */
private class LibraryScriptRenderer : DefaultListCellRenderer() {
    override fun getListCellRendererComponent(
        list: JList<*>, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean,
    ): Component {
        val script = value as? LibraryScript
        val display = if (script != null) {
            val prefix = "[${script.category}]"
            val badge = if (script.enabled) " ✓" else ""
            "$prefix ${script.name}$badge"
        } else {
            value?.toString() ?: ""
        }
        return super.getListCellRendererComponent(list, display, index, isSelected, cellHasFocus)
    }
}

// ---------------------------------------------------------------------------
// Traffic table model
// ---------------------------------------------------------------------------
private class TrafficTableModel : AbstractTableModel() {
    private val columns = arrayOf("Method", "Host", "Path", "Status", "MIME", "Params", "IP")
    private var allEntries: List<fridalink.model.TrafficEntry> = emptyList()
    private var filtered: List<fridalink.model.TrafficEntry> = emptyList()
    var filterText: String = ""

    fun setEntries(entries: List<fridalink.model.TrafficEntry>) {
        allEntries = entries; applyFilter()
    }
    fun applyFilter() {
        val q = filterText.lowercase()
        filtered = if (q.isBlank()) allEntries
        else allEntries.filter {
            it.host.contains(q) || it.path.contains(q) || it.method.contains(q) || it.url.contains(q)
        }
        fireTableDataChanged()
    }
    fun entryAt(row: Int): fridalink.model.TrafficEntry = filtered[row]
    override fun getRowCount(): Int = filtered.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(c: Int): String = columns[c]
    override fun getValueAt(row: Int, col: Int): Any = with(filtered[row]) {
        when (col) {
            0 -> method; 1 -> host; 2 -> path.take(80)
            3 -> if (statusCode > 0) statusCode.toString() else ""
            4 -> mimeType.take(25); 5 -> params.take(5).joinToString(",")
            else -> ip
        }
    }
}

// ---------------------------------------------------------------------------
// MASVS table model
// ---------------------------------------------------------------------------
private class MasvsTableModel : AbstractTableModel() {
    private val columns = arrayOf("ID", "Level", "Control", "Status", "Category")
    private var items: List<fridalink.model.MasvsItem> = emptyList()

    fun setItems(newItems: List<fridalink.model.MasvsItem>) { items = newItems; fireTableDataChanged() }
    fun itemAt(row: Int): fridalink.model.MasvsItem = items[row]
    override fun getRowCount(): Int = items.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(c: Int): String = columns[c]
    override fun getValueAt(row: Int, col: Int): Any = with(items[row]) {
        when (col) { 0 -> id; 1 -> level; 2 -> control; 3 -> status.name.replace("_", " "); else -> category }
    }
}

private class MasvsStatusRenderer(private val model: MasvsTableModel) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, col: Int): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        if (!isSelected) {
            val item = try { model.itemAt(table.convertRowIndexToModel(row)) } catch (_: Exception) { null }
            c.background = when (item?.status) {
                fridalink.model.MasvsStatus.FAIL           -> Color(255, 210, 210)
                fridalink.model.MasvsStatus.PASS           -> Color(210, 255, 215)
                fridalink.model.MasvsStatus.NOT_APPLICABLE -> Color(235, 235, 235)
                else                                      -> table.background
            }
        }
        return c
    }
}

// ---------------------------------------------------------------------------
// APK Findings table model  (false positives are hidden)
// ---------------------------------------------------------------------------
private class FindingsTableModel : AbstractTableModel() {
    private val columns = arrayOf("Severity", "Category", "Title", "CVSS", "MASVS")
    private var findings: List<fridalink.model.ApkFinding> = emptyList()

    /** Only non-FP findings are exposed to the table. */
    fun setFindings(f: List<fridalink.model.ApkFinding>) {
        findings = f.filter { !it.isFalsePositive }
        fireTableDataChanged()
    }
    fun findingAt(row: Int): fridalink.model.ApkFinding = findings[row]
    override fun getRowCount(): Int = findings.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(c: Int): String = columns[c]
    override fun getValueAt(row: Int, col: Int): Any = with(findings[row]) {
        when (col) { 0 -> severity.name; 1 -> category; 2 -> title.take(60)
                     3 -> cvssScore.toString(); else -> masvsRef }
    }
}

private class FindingsSeverityRenderer(private val model: FindingsTableModel) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, col: Int): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        if (!isSelected) {
            val f = try { model.findingAt(table.convertRowIndexToModel(row)) } catch (_: Exception) { null }
            c.background = when (f?.severity) {
                fridalink.model.FindingSeverity.CRITICAL -> Color(220, 50, 50)
                fridalink.model.FindingSeverity.HIGH     -> Color(255, 160, 80)
                fridalink.model.FindingSeverity.MEDIUM   -> Color(255, 230, 100)
                fridalink.model.FindingSeverity.LOW      -> Color(200, 230, 255)
                fridalink.model.FindingSeverity.INFO     -> Color(235, 235, 235)
                else                                    -> table.background
            }
        }
        return c
    }
}

// ---------------------------------------------------------------------------
// Geo table model
// ---------------------------------------------------------------------------
private class GeoTableModel : AbstractTableModel() {
    private val columns = arrayOf(
        "Host", "IP", "Country", "Code", "City / Region",
        "ISP / Org", "ASN", "Reverse DNS", "TZ", "DC?", "Proxy?", "Threat"
    )
    private var results: List<fridalink.model.GeoResult> = emptyList()

    fun setResults(r: List<fridalink.model.GeoResult>) { results = r; fireTableDataChanged() }
    fun resultAt(row: Int): fridalink.model.GeoResult = results[row]
    override fun getRowCount(): Int = results.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(c: Int): String = columns[c]
    override fun getValueAt(row: Int, col: Int): Any = with(results[row]) {
        when (col) {
            0  -> host.ifBlank { ip }
            1  -> ip
            2  -> country.ifBlank { if (status.startsWith("fail")) "FAIL" else "—" }
            3  -> countryCode
            4  -> buildString {
                    if (city.isNotBlank()) append(city)
                    if (regionName.isNotBlank()) { if (isNotEmpty()) append(", "); append(regionName.take(20)) }
                    if (isEmpty()) append("—")
                 }
            5  -> (org.ifBlank { isp }).take(44)
            6  -> asn.take(30).ifBlank { "—" }
            7  -> reverse.take(44).ifBlank { "—" }
            8  -> timezone.substringAfterLast('/').ifBlank { "—" }
            9  -> if (isHosting) "DC" else "—"
            10 -> if (isProxy) "VPN/Proxy" else "—"
            else -> threatLabel.ifBlank { "—" }
        }
    }
}

private class UrlRefTableModel : AbstractTableModel() {
    private val columns = arrayOf("URL", "Domain", "Scheme", "Threat")
    private var rows: List<fridalink.model.UrlReference> = emptyList()

    fun setRefs(refs: List<fridalink.model.UrlReference>) {
        rows = refs
        fireTableDataChanged()
    }

    fun refAt(rowIndex: Int): fridalink.model.UrlReference = rows[rowIndex]

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = when (columnIndex) {
        0 -> rows[rowIndex].url
        1 -> rows[rowIndex].domain
        2 -> rows[rowIndex].scheme
        else -> rows[rowIndex].threatLabel
    }
}

private class LibraryTableModel : AbstractTableModel() {
    private val columns = arrayOf("Library", "Package Prefix", "Risk", "Known Issue")
    private var rows: List<fridalink.model.LibraryInfo> = emptyList()

    fun setLibraries(libs: List<fridalink.model.LibraryInfo>) {
        rows = libs
        fireTableDataChanged()
    }

    fun libraryAt(rowIndex: Int): fridalink.model.LibraryInfo = rows[rowIndex]

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]
    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = when (columnIndex) {
        0 -> rows[rowIndex].displayName
        1 -> rows[rowIndex].packagePrefix
        2 -> rows[rowIndex].risk
        else -> rows[rowIndex].knownIssue
    }
}

private class LibraryRiskRenderer(private val model: LibraryTableModel) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, col: Int): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        if (!isSelected) {
            val mr = try { table.convertRowIndexToModel(row) } catch (_: Exception) { return c }
            val lib = try { model.libraryAt(mr) } catch (_: Exception) { return c }
            c.background = when (lib.risk) {
                "critical" -> Color(255, 160, 160)
                "high"     -> Color(255, 210, 160)
                "medium"   -> Color(255, 245, 180)
                else       -> table.background
            }
        }
        return c
    }
}

private class GeoStatusRenderer(private val model: GeoTableModel) : DefaultTableCellRenderer() {
    override fun getTableCellRendererComponent(table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, col: Int): Component {
        val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        if (!isSelected) {
            val mr = try { table.convertRowIndexToModel(row) } catch (_: Exception) { return c }
            val result = try { model.resultAt(mr) } catch (_: Exception) { return c }
            c.background = when {
                result.threatLabel.contains("CN")   -> Color(255, 160, 160)   // Chinese data entity — bright red
                result.threatLabel.isNotBlank()     -> Color(255, 220, 130)   // Tracker/analytics — amber
                !result.isUS && result.status == "success" -> Color(255, 235, 200)   // Foreign — light orange
                else -> table.background
            }
        }
        return c
    }
}

// ---------------------------------------------------------------------------
// World Map Panel — equirectangular projection, smooth Catmull-Rom coastlines
// ---------------------------------------------------------------------------
private class WorldMapPanel : JPanel() {
    private var locations: List<fridalink.model.GeoResult> = emptyList()

    init {
        background = Color(22, 60, 110)   // deep ocean blue
        toolTipText = "Server locations — red = non-US, green = US"
        preferredSize = java.awt.Dimension(700, 360)
    }

    fun updateLocations(locs: List<fridalink.model.GeoResult>) {
        locations = locs
        repaint()
    }

    override fun paintComponent(g: java.awt.Graphics) {
        super.paintComponent(g)
        val g2 = g as java.awt.Graphics2D
        // Quality rendering hints for smooth coastlines
        g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,        java.awt.RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(java.awt.RenderingHints.KEY_RENDERING,           java.awt.RenderingHints.VALUE_RENDER_QUALITY)
        g2.setRenderingHint(java.awt.RenderingHints.KEY_STROKE_CONTROL,      java.awt.RenderingHints.VALUE_STROKE_PURE)
        g2.setRenderingHint(java.awt.RenderingHints.KEY_COLOR_RENDERING,     java.awt.RenderingHints.VALUE_COLOR_RENDER_QUALITY)
        val w = width.toDouble(); val h = height.toDouble()

        fun toXY(lat: Double, lon: Double): java.awt.geom.Point2D.Double {
            val x = (lon + 180.0) / 360.0 * w
            val y = (90.0 - lat) / 180.0 * h
            return java.awt.geom.Point2D.Double(x, y)
        }

        // ---- Grid lines ----
        g2.color = Color(40, 90, 155, 70)
        g2.stroke = java.awt.BasicStroke(0.5f)
        for (lon in -180..180 step 30) {
            val x = toXY(0.0, lon.toDouble()).x.toInt()
            g2.drawLine(x, 0, x, h.toInt())
        }
        for (lat in -90..90 step 30) {
            val y = toXY(lat.toDouble(), 0.0).y.toInt()
            g2.drawLine(0, y, w.toInt(), y)
        }
        // Equator — brighter
        g2.color = Color(60, 120, 200, 100)
        g2.stroke = java.awt.BasicStroke(1f)
        val eqY = toXY(0.0, 0.0).y.toInt()
        g2.drawLine(0, eqY, w.toInt(), eqY)

        // ---- Draw landmasses with smooth Catmull-Rom splines ----
        val landFill   = Color(110, 145, 75)
        val landBorder = Color(85, 115, 55)
        for ((_, poly) in CONTINENT_POLYS) {
            val path = buildCatmullRomPath(poly, ::toXY)
            g2.color = landFill;   g2.fill(path)
            g2.color = landBorder; g2.stroke = java.awt.BasicStroke(0.8f); g2.draw(path)
        }

        // ---- Server location dots ----
        g2.stroke = java.awt.BasicStroke(1.5f)
        for (loc in locations) {
            if (loc.lat == 0.0 && loc.lon == 0.0) continue
            if (loc.status != "success" && loc.status != "local") continue
            val pt = toXY(loc.lat, loc.lon)
            val px = pt.x.toInt(); val py = pt.y.toInt()
            val dotSize = 9
            // Glow shadow
            g2.color = if (loc.isUS) Color(0, 180, 60, 80) else Color(220, 30, 30, 80)
            g2.fillOval(px - dotSize/2 - 2, py - dotSize/2 - 2, dotSize + 4, dotSize + 4)
            // Main dot
            g2.color = if (loc.isUS) Color(40, 210, 90) else Color(230, 50, 50)
            g2.fillOval(px - dotSize/2, py - dotSize/2, dotSize, dotSize)
            // White ring
            g2.color = Color(255, 255, 255, 200)
            g2.drawOval(px - dotSize/2, py - dotSize/2, dotSize, dotSize)
        }

        // ---- Legend (bottom-left) ----
        g2.font = java.awt.Font("SansSerif", java.awt.Font.BOLD, 10)
        val lx = 8; var ly = h.toInt() - 32
        g2.color = Color(0, 0, 0, 100); g2.fillRoundRect(lx - 4, ly - 14, 148, 36, 6, 6)
        g2.color = Color(40, 210, 90);  g2.fillOval(lx, ly - 7, 10, 10)
        g2.color = Color.WHITE;         g2.drawString("US Server", lx + 14, ly + 1)
        ly += 18
        g2.color = Color(230, 50, 50);  g2.fillOval(lx, ly - 7, 10, 10)
        g2.color = Color.WHITE;         g2.drawString("Non-US Server  !", lx + 14, ly + 1)

        // ---- Warning banner (top-right) ----
        val nonUs = locations.count { !it.isUS && it.status == "success" && it.countryCode != "LO" }
        if (nonUs > 0) {
            g2.color = Color(180, 20, 20, 210)
            g2.fillRoundRect(w.toInt() - 248, 6, 240, 24, 8, 8)
            g2.color = Color.WHITE
            g2.font = java.awt.Font("SansSerif", java.awt.Font.BOLD, 11)
            g2.drawString("! $nonUs NON-US SERVER(S) DETECTED", w.toInt() - 244, 23)
        }
    }

    /**
     * Converts an array of [lat, lon] pairs into a smooth closed Path2D
     * using Catmull-Rom → cubic Bézier conversion.
     *
     * For each segment p[i] → p[i+1]:
     *   cp1 = p[i]   + (p[i+1] - p[i-1]) / 6
     *   cp2 = p[i+1] - (p[i+2] - p[i])   / 6
     */
    private fun buildCatmullRomPath(
        poly: Array<DoubleArray>,
        toXY: (Double, Double) -> java.awt.geom.Point2D.Double
    ): java.awt.geom.Path2D.Double {
        val path = java.awt.geom.Path2D.Double()
        val n = poly.size
        if (n < 3) return path

        val pts = Array(n) { i -> toXY(poly[i][0], poly[i][1]) }

        path.moveTo(pts[0].x, pts[0].y)

        for (i in 0 until n) {
            val p0 = pts[(i - 1 + n) % n]
            val p1 = pts[i]
            val p2 = pts[(i + 1) % n]
            val p3 = pts[(i + 2) % n]

            val cp1x = p1.x + (p2.x - p0.x) / 6.0
            val cp1y = p1.y + (p2.y - p0.y) / 6.0
            val cp2x = p2.x - (p3.x - p1.x) / 6.0
            val cp2y = p2.y - (p3.y - p1.y) / 6.0

            path.curveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y)
        }

        path.closePath()
        return path
    }

    // Detailed continent outlines [lat, lon] — ~40–60 points per landmass.
    // Points are ordered clockwise around the outer boundary.
    companion object {
        @Suppress("SpellCheckingInspection")
        val CONTINENT_POLYS = mapOf(

            // ── North America ──────────────────────────────────────────
            "North America" to arrayOf(
                // Alaska north + west
                doubleArrayOf(71.3,-156.8), doubleArrayOf(70.5,-162.0), doubleArrayOf(66.0,-162.5),
                doubleArrayOf(63.7,-163.0), doubleArrayOf(60.5,-165.0), doubleArrayOf(58.8,-158.0),
                doubleArrayOf(57.0,-153.5), doubleArrayOf(57.5,-135.5), doubleArrayOf(55.2,-130.0),
                // Pacific coast
                doubleArrayOf(52.0,-128.5), doubleArrayOf(49.0,-125.5), doubleArrayOf(46.5,-124.5),
                doubleArrayOf(42.8,-124.5), doubleArrayOf(40.5,-124.4), doubleArrayOf(38.3,-123.1),
                doubleArrayOf(37.7,-122.5), doubleArrayOf(35.4,-120.9), doubleArrayOf(34.4,-119.8),
                doubleArrayOf(33.9,-118.4), doubleArrayOf(32.6,-117.2),
                // Baja + Mexico Pacific
                doubleArrayOf(30.5,-114.9), doubleArrayOf(27.8,-110.8), doubleArrayOf(22.9,-109.8),
                doubleArrayOf(22.5,-105.7), doubleArrayOf(19.3,-104.3), doubleArrayOf(16.3,-95.8),
                doubleArrayOf(14.7,-92.2), doubleArrayOf(13.2,-89.3), doubleArrayOf(11.2,-85.8),
                // Central America + Panama
                doubleArrayOf(9.3,-83.0), doubleArrayOf(8.5,-78.5), doubleArrayOf(9.5,-77.4),
                // Caribbean coast then skip north to Cuba
                doubleArrayOf(11.0,-74.8), doubleArrayOf(15.8,-67.0), doubleArrayOf(19.7,-69.8),
                doubleArrayOf(22.3,-84.2), doubleArrayOf(23.1,-82.4),
                // Florida peninsula
                doubleArrayOf(24.5,-81.8), doubleArrayOf(25.3,-80.2), doubleArrayOf(25.8,-80.1),
                doubleArrayOf(29.0,-80.9), doubleArrayOf(30.4,-81.4),
                // Atlantic seaboard
                doubleArrayOf(31.3,-81.3), doubleArrayOf(32.1,-80.8), doubleArrayOf(34.0,-77.9),
                doubleArrayOf(35.5,-75.5), doubleArrayOf(37.0,-76.0), doubleArrayOf(38.3,-75.2),
                doubleArrayOf(39.4,-74.4), doubleArrayOf(40.5,-74.0), doubleArrayOf(41.0,-71.9),
                doubleArrayOf(41.5,-70.7), doubleArrayOf(42.0,-70.0), doubleArrayOf(42.9,-70.9),
                doubleArrayOf(44.1,-68.0), doubleArrayOf(44.9,-66.9),
                // Maritimes + Newfoundland
                doubleArrayOf(46.5,-60.5), doubleArrayOf(47.1,-53.0), doubleArrayOf(50.0,-55.8),
                doubleArrayOf(52.5,-55.8), doubleArrayOf(54.2,-57.8), doubleArrayOf(57.5,-61.6),
                doubleArrayOf(60.5,-64.8),
                // Labrador + Baffin
                doubleArrayOf(62.8,-69.8), doubleArrayOf(63.2,-74.5), doubleArrayOf(60.3,-78.0),
                // Hudson Bay west coast simplified (jump over bay)
                doubleArrayOf(62.0,-92.5), doubleArrayOf(60.0,-94.5), doubleArrayOf(58.8,-93.8),
                // Arctic coast
                doubleArrayOf(65.0,-83.0), doubleArrayOf(67.5,-86.5), doubleArrayOf(68.3,-96.5),
                doubleArrayOf(70.0,-103.0), doubleArrayOf(70.5,-114.5), doubleArrayOf(70.0,-122.5),
                doubleArrayOf(69.5,-138.5), doubleArrayOf(71.3,-156.8),
            ),

            // ── South America ──────────────────────────────────────────
            "South America" to arrayOf(
                doubleArrayOf(12.2,-71.8), doubleArrayOf(11.7,-62.5), doubleArrayOf(9.7,-60.8),
                doubleArrayOf(8.3,-60.0), doubleArrayOf(6.0,-57.5), doubleArrayOf(5.1,-52.6),
                doubleArrayOf(3.8,-51.0), doubleArrayOf(1.5,-49.5), doubleArrayOf(-0.5,-48.5),
                doubleArrayOf(-3.5,-37.0), doubleArrayOf(-5.5,-35.2), doubleArrayOf(-7.2,-34.8),
                doubleArrayOf(-10.0,-37.1), doubleArrayOf(-13.0,-38.5), doubleArrayOf(-16.5,-39.1),
                doubleArrayOf(-20.0,-40.1), doubleArrayOf(-22.8,-43.2), doubleArrayOf(-24.3,-46.5),
                doubleArrayOf(-26.3,-48.5), doubleArrayOf(-28.5,-49.0), doubleArrayOf(-30.5,-50.7),
                doubleArrayOf(-33.0,-52.5), doubleArrayOf(-34.5,-53.5), doubleArrayOf(-34.9,-56.2),
                doubleArrayOf(-36.5,-57.0), doubleArrayOf(-38.5,-58.8), doubleArrayOf(-40.5,-62.2),
                doubleArrayOf(-42.5,-64.5), doubleArrayOf(-46.5,-65.5), doubleArrayOf(-51.5,-69.0),
                doubleArrayOf(-54.5,-67.5), doubleArrayOf(-55.8,-67.3), doubleArrayOf(-55.0,-71.5),
                doubleArrayOf(-52.5,-73.5), doubleArrayOf(-46.5,-74.2), doubleArrayOf(-43.5,-74.0),
                doubleArrayOf(-40.5,-73.2), doubleArrayOf(-37.5,-73.8), doubleArrayOf(-33.0,-71.5),
                doubleArrayOf(-27.0,-70.8), doubleArrayOf(-22.5,-70.3), doubleArrayOf(-18.5,-70.2),
                doubleArrayOf(-15.0,-75.2), doubleArrayOf(-10.0,-78.5), doubleArrayOf(-4.5,-81.3),
                doubleArrayOf(-1.0,-80.3), doubleArrayOf(0.5,-80.0), doubleArrayOf(3.5,-77.5),
                doubleArrayOf(6.5,-77.5), doubleArrayOf(8.5,-77.4), doubleArrayOf(10.5,-73.5),
                doubleArrayOf(12.2,-71.8),
            ),

            // ── Europe ────────────────────────────────────────────────
            "Europe" to arrayOf(
                // N Cape Norway → Norwegian coast
                doubleArrayOf(71.2,25.8), doubleArrayOf(70.5,22.0), doubleArrayOf(69.5,18.5),
                doubleArrayOf(68.0,15.5), doubleArrayOf(65.5,14.3), doubleArrayOf(63.5,8.5),
                doubleArrayOf(62.0,5.5), doubleArrayOf(59.0,5.0), doubleArrayOf(57.9,7.0),
                doubleArrayOf(57.5,8.0), doubleArrayOf(57.8,10.5), doubleArrayOf(56.5,8.2),
                // Jutland + Denmark + Baltic
                doubleArrayOf(55.5,8.5), doubleArrayOf(54.5,9.0), doubleArrayOf(54.5,11.0),
                doubleArrayOf(53.5,14.0), doubleArrayOf(54.5,16.5), doubleArrayOf(55.0,18.0),
                doubleArrayOf(54.7,19.5), doubleArrayOf(54.7,20.5), doubleArrayOf(56.0,21.0),
                doubleArrayOf(57.5,21.5), doubleArrayOf(58.5,22.5), doubleArrayOf(59.5,24.5),
                doubleArrayOf(60.0,25.0), doubleArrayOf(59.8,27.5), doubleArrayOf(59.5,29.0),
                // Gulf of Finland → White Sea → Urals (Russia in Europe)
                doubleArrayOf(60.5,30.5), doubleArrayOf(61.5,30.5), doubleArrayOf(65.5,33.0),
                doubleArrayOf(67.5,33.0), doubleArrayOf(68.5,33.5), doubleArrayOf(69.0,32.5),
                doubleArrayOf(69.5,33.5), doubleArrayOf(70.0,30.5), doubleArrayOf(71.2,25.8),
            ),
            // Iberian Peninsula
            "Iberia" to arrayOf(
                doubleArrayOf(43.8,-8.2), doubleArrayOf(43.4,-8.5), doubleArrayOf(42.8,-9.3),
                doubleArrayOf(41.0,-8.5), doubleArrayOf(38.7,-9.5), doubleArrayOf(37.0,-8.9),
                doubleArrayOf(36.0,-7.0), doubleArrayOf(36.0,-5.6), doubleArrayOf(36.2,-2.5),
                doubleArrayOf(37.5,-1.0), doubleArrayOf(39.5,0.3), doubleArrayOf(40.5,0.7),
                doubleArrayOf(42.5,3.2), doubleArrayOf(43.5,3.3), doubleArrayOf(43.8,1.5),
                doubleArrayOf(43.4,-1.8), doubleArrayOf(43.8,-8.2),
            ),
            // Italy
            "Italy" to arrayOf(
                doubleArrayOf(44.2,7.8), doubleArrayOf(43.8,8.0), doubleArrayOf(43.5,10.0),
                doubleArrayOf(42.5,11.2), doubleArrayOf(41.5,12.5), doubleArrayOf(41.0,14.5),
                doubleArrayOf(40.0,15.5), doubleArrayOf(38.5,15.8), doubleArrayOf(37.9,15.7),
                doubleArrayOf(37.9,16.0), doubleArrayOf(40.0,18.5), doubleArrayOf(41.0,16.8),
                doubleArrayOf(41.5,15.5), doubleArrayOf(43.5,13.8), doubleArrayOf(44.5,12.3),
                doubleArrayOf(45.6,13.8), doubleArrayOf(46.0,13.2), doubleArrayOf(44.2,7.8),
            ),
            // Balkans + Greece
            "Balkans" to arrayOf(
                doubleArrayOf(45.8,13.8), doubleArrayOf(44.8,14.5), doubleArrayOf(43.5,16.5),
                doubleArrayOf(42.5,18.5), doubleArrayOf(41.8,19.5), doubleArrayOf(41.0,20.5),
                doubleArrayOf(40.5,22.5), doubleArrayOf(39.5,22.0), doubleArrayOf(38.5,22.5),
                doubleArrayOf(37.5,22.5), doubleArrayOf(36.8,22.0), doubleArrayOf(36.5,23.0),
                doubleArrayOf(37.5,24.5), doubleArrayOf(38.0,26.5), doubleArrayOf(40.0,26.5),
                doubleArrayOf(41.8,26.5), doubleArrayOf(41.5,28.5), doubleArrayOf(42.5,27.5),
                doubleArrayOf(43.5,28.5), doubleArrayOf(44.0,29.0), doubleArrayOf(45.0,29.5),
                doubleArrayOf(46.5,30.0), doubleArrayOf(47.5,32.0), doubleArrayOf(48.5,33.5),
                doubleArrayOf(46.5,32.0), doubleArrayOf(47.0,30.0), doubleArrayOf(46.5,26.5),
                doubleArrayOf(45.8,22.5), doubleArrayOf(45.5,18.5), doubleArrayOf(45.8,13.8),
            ),

            // ── Africa ────────────────────────────────────────────────
            "Africa" to arrayOf(
                // N Africa west → east
                doubleArrayOf(35.8,-5.8), doubleArrayOf(36.8,-2.5), doubleArrayOf(37.0,1.5),
                doubleArrayOf(37.2,5.5), doubleArrayOf(37.0,9.5), doubleArrayOf(36.5,10.5),
                doubleArrayOf(33.5,11.5), doubleArrayOf(32.9,12.5), doubleArrayOf(32.5,15.0),
                doubleArrayOf(30.0,19.0), doubleArrayOf(31.5,25.0), doubleArrayOf(31.0,32.0),
                doubleArrayOf(29.5,32.5), doubleArrayOf(27.5,34.0), doubleArrayOf(22.0,37.0),
                // Horn of Africa
                doubleArrayOf(12.5,44.0), doubleArrayOf(11.0,45.0), doubleArrayOf(9.0,50.0),
                doubleArrayOf(11.5,51.5), doubleArrayOf(12.0,51.2),
                // East Africa coast south
                doubleArrayOf(10.0,42.5), doubleArrayOf(5.0,41.5), doubleArrayOf(2.0,41.5),
                doubleArrayOf(-1.0,40.5), doubleArrayOf(-4.5,39.8), doubleArrayOf(-7.0,39.8),
                doubleArrayOf(-10.5,40.5), doubleArrayOf(-14.5,40.5), doubleArrayOf(-17.5,37.0),
                doubleArrayOf(-20.0,35.5), doubleArrayOf(-25.0,33.5), doubleArrayOf(-29.5,30.5),
                doubleArrayOf(-34.5,26.5), doubleArrayOf(-35.0,19.5), doubleArrayOf(-33.5,18.5),
                doubleArrayOf(-34.5,18.0),
                // Cape → west coast north
                doubleArrayOf(-29.0,17.0), doubleArrayOf(-23.5,14.5), doubleArrayOf(-17.5,12.0),
                doubleArrayOf(-12.5,13.5), doubleArrayOf(-6.5,12.0), doubleArrayOf(-2.0,9.5),
                doubleArrayOf(2.0,5.5), doubleArrayOf(4.5,2.5), doubleArrayOf(5.0,-1.5),
                doubleArrayOf(5.5,-4.5), doubleArrayOf(4.5,-7.5), doubleArrayOf(9.0,-13.5),
                doubleArrayOf(12.5,-16.5), doubleArrayOf(14.5,-17.2),
                // NW Africa (Mauritania/Senegal → Morocco)
                doubleArrayOf(17.0,-16.5), doubleArrayOf(20.5,-17.0), doubleArrayOf(21.5,-17.0),
                doubleArrayOf(27.0,-13.0), doubleArrayOf(30.0,-10.0), doubleArrayOf(33.0,-8.5),
                doubleArrayOf(35.8,-5.8),
            ),

            // ── Asia ──────────────────────────────────────────────────
            "Asia" to arrayOf(
                // Turkey west → Caucasus → Caspian → Central Asia → Siberia
                doubleArrayOf(41.0,28.5), doubleArrayOf(40.8,26.5), doubleArrayOf(38.0,26.5),
                doubleArrayOf(36.8,27.0), doubleArrayOf(36.0,28.5), doubleArrayOf(36.5,30.5),
                doubleArrayOf(36.0,32.5), doubleArrayOf(36.5,35.5), doubleArrayOf(36.8,36.5),
                doubleArrayOf(37.0,36.5), doubleArrayOf(36.5,37.5),
                // Syrian coast → Arabian peninsula
                doubleArrayOf(35.5,36.0), doubleArrayOf(33.0,35.5), doubleArrayOf(31.5,34.5),
                doubleArrayOf(29.5,34.5), doubleArrayOf(27.5,34.5), doubleArrayOf(28.5,34.0),
                doubleArrayOf(29.5,32.5), doubleArrayOf(29.0,34.5), doubleArrayOf(28.0,34.5),
                doubleArrayOf(23.5,37.5), doubleArrayOf(19.0,42.5), doubleArrayOf(16.0,43.0),
                doubleArrayOf(12.5,44.5), doubleArrayOf(11.8,51.5),
                // Oman → India west coast
                doubleArrayOf(22.5,59.5), doubleArrayOf(22.5,60.5), doubleArrayOf(24.0,56.5),
                doubleArrayOf(25.5,57.0), doubleArrayOf(26.5,56.5), doubleArrayOf(22.0,60.5),
                doubleArrayOf(18.5,58.5), doubleArrayOf(16.5,54.5), doubleArrayOf(14.5,51.0),
                doubleArrayOf(12.0,44.0), // (already above - jump to India)
                doubleArrayOf(23.0,68.5), doubleArrayOf(20.5,66.8),
                doubleArrayOf(22.5,69.0), doubleArrayOf(20.5,71.5), doubleArrayOf(18.5,72.0),
                doubleArrayOf(16.5,73.0), doubleArrayOf(14.0,74.5), doubleArrayOf(11.0,76.5),
                doubleArrayOf(8.5,77.0), doubleArrayOf(8.0,77.8),
                // India tip → east coast
                doubleArrayOf(8.5,78.5), doubleArrayOf(10.0,80.0), doubleArrayOf(13.5,80.5),
                doubleArrayOf(15.5,80.0), doubleArrayOf(18.5,84.0), doubleArrayOf(20.5,86.5),
                doubleArrayOf(22.0,87.5), doubleArrayOf(21.5,88.0), doubleArrayOf(22.5,90.0),
                doubleArrayOf(21.0,92.5), doubleArrayOf(22.5,92.5),
                // Bangladesh coast → SE Asia
                doubleArrayOf(20.5,93.0), doubleArrayOf(17.5,95.5), doubleArrayOf(16.0,98.0),
                doubleArrayOf(13.5,100.0), doubleArrayOf(7.5,100.5), doubleArrayOf(5.5,103.5),
                doubleArrayOf(2.5,103.5), doubleArrayOf(1.5,104.5),
                // Singapore → Indochina east coast
                doubleArrayOf(4.5,103.5), doubleArrayOf(6.0,103.0), doubleArrayOf(10.0,105.0),
                doubleArrayOf(14.0,108.5), doubleArrayOf(16.5,108.0), doubleArrayOf(18.5,106.5),
                doubleArrayOf(20.0,107.0), doubleArrayOf(21.5,108.0),
                // S China coast
                doubleArrayOf(21.5,111.5), doubleArrayOf(22.5,114.0), doubleArrayOf(22.5,114.5),
                doubleArrayOf(23.0,116.5), doubleArrayOf(24.0,118.5), doubleArrayOf(26.0,120.0),
                doubleArrayOf(28.5,121.5), doubleArrayOf(30.5,122.5), doubleArrayOf(32.0,121.5),
                doubleArrayOf(34.5,120.0), doubleArrayOf(35.5,120.5), doubleArrayOf(37.5,122.5),
                doubleArrayOf(39.0,122.0), doubleArrayOf(40.5,122.5), doubleArrayOf(41.5,121.0),
                // Manchuria → Russian Far East
                doubleArrayOf(42.0,130.5), doubleArrayOf(44.5,136.0), doubleArrayOf(46.5,138.0),
                doubleArrayOf(48.0,140.5), doubleArrayOf(49.5,140.5), doubleArrayOf(52.0,141.0),
                doubleArrayOf(54.5,142.5), doubleArrayOf(53.5,142.5), doubleArrayOf(54.0,141.5),
                doubleArrayOf(55.0,137.5), doubleArrayOf(57.0,135.0), doubleArrayOf(60.0,152.0),
                doubleArrayOf(62.5,163.0), doubleArrayOf(64.0,173.5), doubleArrayOf(66.0,173.0),
                doubleArrayOf(66.5,179.5),
                // Arctic Siberia
                doubleArrayOf(70.0,174.0), doubleArrayOf(72.0,162.0), doubleArrayOf(73.0,142.0),
                doubleArrayOf(73.0,130.0), doubleArrayOf(74.5,120.0), doubleArrayOf(75.5,107.0),
                doubleArrayOf(76.0,90.0), doubleArrayOf(76.5,82.0), doubleArrayOf(77.5,68.5),
                doubleArrayOf(73.5,57.5), doubleArrayOf(70.5,60.0), doubleArrayOf(68.5,54.0),
                // Ural → Caspian → Caucasus → back to Turkey
                doubleArrayOf(66.5,49.5), doubleArrayOf(65.5,44.0), doubleArrayOf(67.0,41.0),
                doubleArrayOf(68.5,38.0), doubleArrayOf(70.5,30.0), doubleArrayOf(68.5,33.0),
                doubleArrayOf(67.5,33.0), doubleArrayOf(64.5,38.5), doubleArrayOf(60.5,38.5),
                doubleArrayOf(58.5,44.5), doubleArrayOf(56.5,47.5), doubleArrayOf(54.5,50.5),
                doubleArrayOf(52.5,51.5), doubleArrayOf(51.5,52.5), doubleArrayOf(49.5,51.5),
                doubleArrayOf(47.0,47.5), doubleArrayOf(46.0,48.5), doubleArrayOf(43.5,50.5),
                doubleArrayOf(42.5,49.5), doubleArrayOf(40.5,50.5), doubleArrayOf(38.5,49.0),
                doubleArrayOf(41.5,41.5), doubleArrayOf(41.5,36.5), doubleArrayOf(40.5,36.5),
                doubleArrayOf(41.0,28.5),
            ),

            // ── Australia ─────────────────────────────────────────────
            "Australia" to arrayOf(
                // Cape York → NE coast
                doubleArrayOf(-10.7,142.5), doubleArrayOf(-12.5,136.5), doubleArrayOf(-12.0,130.0),
                doubleArrayOf(-13.5,130.0), doubleArrayOf(-14.5,128.5), doubleArrayOf(-15.0,129.0),
                doubleArrayOf(-15.5,124.0), doubleArrayOf(-20.5,116.5), doubleArrayOf(-22.0,114.0),
                doubleArrayOf(-26.0,113.5), doubleArrayOf(-28.5,114.5), doubleArrayOf(-31.5,115.5),
                doubleArrayOf(-34.5,115.0), doubleArrayOf(-35.0,117.5), doubleArrayOf(-34.0,120.0),
                doubleArrayOf(-34.0,123.5), doubleArrayOf(-33.5,124.0), doubleArrayOf(-32.5,127.5),
                doubleArrayOf(-32.0,133.0), doubleArrayOf(-32.0,134.0), doubleArrayOf(-32.5,137.5),
                doubleArrayOf(-35.5,139.0), doubleArrayOf(-38.5,140.5), doubleArrayOf(-38.5,143.0),
                doubleArrayOf(-37.5,148.0), doubleArrayOf(-37.0,150.0), doubleArrayOf(-35.5,150.5),
                doubleArrayOf(-33.5,151.5), doubleArrayOf(-31.5,153.0), doubleArrayOf(-29.0,153.5),
                doubleArrayOf(-25.0,153.0), doubleArrayOf(-22.0,150.0), doubleArrayOf(-20.0,148.5),
                doubleArrayOf(-18.0,147.5), doubleArrayOf(-14.5,145.5), doubleArrayOf(-10.7,142.5),
            ),

            // ── Greenland ─────────────────────────────────────────────
            "Greenland" to arrayOf(
                doubleArrayOf(83.5,-30.0), doubleArrayOf(82.5,-18.0), doubleArrayOf(82.5,-10.0),
                doubleArrayOf(79.5,-18.0), doubleArrayOf(76.5,-18.5), doubleArrayOf(72.5,-22.5),
                doubleArrayOf(72.0,-26.0), doubleArrayOf(70.0,-25.0), doubleArrayOf(65.5,-38.0),
                doubleArrayOf(63.5,-42.5), doubleArrayOf(63.0,-44.5), doubleArrayOf(64.5,-40.5),
                doubleArrayOf(65.5,-37.5), doubleArrayOf(68.0,-32.5), doubleArrayOf(68.0,-31.0),
                doubleArrayOf(70.0,-24.0), doubleArrayOf(72.5,-24.5), doubleArrayOf(73.5,-20.5),
                doubleArrayOf(75.5,-18.5), doubleArrayOf(76.5,-25.0), doubleArrayOf(77.5,-26.0),
                doubleArrayOf(77.5,-30.5), doubleArrayOf(79.5,-37.5), doubleArrayOf(80.5,-45.5),
                doubleArrayOf(82.0,-45.5), doubleArrayOf(83.0,-40.0), doubleArrayOf(83.5,-30.0),
            ),

            // ── UK + Ireland ──────────────────────────────────────────
            "UK" to arrayOf(
                doubleArrayOf(58.5,-3.2), doubleArrayOf(57.5,-1.8), doubleArrayOf(56.0,-2.0),
                doubleArrayOf(55.0,-1.6), doubleArrayOf(54.5,-0.5), doubleArrayOf(53.5,-0.2),
                doubleArrayOf(52.5,1.7), doubleArrayOf(51.5,1.4), doubleArrayOf(50.8,0.3),
                doubleArrayOf(50.0,-5.5), doubleArrayOf(51.5,-5.2), doubleArrayOf(52.0,-5.0),
                doubleArrayOf(53.5,-4.8), doubleArrayOf(54.5,-3.5), doubleArrayOf(55.0,-5.0),
                doubleArrayOf(55.5,-4.8), doubleArrayOf(57.0,-6.0), doubleArrayOf(58.0,-5.0),
                doubleArrayOf(58.5,-3.2),
            ),
            "Ireland" to arrayOf(
                doubleArrayOf(55.2,-6.5), doubleArrayOf(54.3,-8.5), doubleArrayOf(53.5,-10.0),
                doubleArrayOf(52.0,-10.5), doubleArrayOf(51.5,-9.5), doubleArrayOf(51.5,-8.5),
                doubleArrayOf(52.5,-6.5), doubleArrayOf(53.0,-6.0), doubleArrayOf(54.0,-6.5),
                doubleArrayOf(55.2,-6.5),
            ),

            // ── Japan (main island Honshu + Kyushu/Shikoku simplified) ─
            "Japan" to arrayOf(
                doubleArrayOf(41.5,140.5), doubleArrayOf(40.5,141.5), doubleArrayOf(38.5,141.5),
                doubleArrayOf(37.5,141.0), doubleArrayOf(36.5,140.5), doubleArrayOf(35.5,140.0),
                doubleArrayOf(34.5,137.0), doubleArrayOf(34.0,135.5), doubleArrayOf(34.5,133.0),
                doubleArrayOf(33.5,131.5), doubleArrayOf(33.0,130.5), doubleArrayOf(33.5,131.5),
                doubleArrayOf(34.5,133.5), doubleArrayOf(35.0,135.0), doubleArrayOf(35.5,136.0),
                doubleArrayOf(35.5,135.5), doubleArrayOf(35.5,137.0), doubleArrayOf(37.0,138.0),
                doubleArrayOf(38.0,139.0), doubleArrayOf(39.5,140.0), doubleArrayOf(40.5,139.5),
                doubleArrayOf(41.5,140.5),
            ),

            // ── Iceland ───────────────────────────────────────────────
            "Iceland" to arrayOf(
                doubleArrayOf(66.5,-14.0), doubleArrayOf(66.0,-18.5), doubleArrayOf(64.5,-22.5),
                doubleArrayOf(63.5,-20.5), doubleArrayOf(63.5,-17.5), doubleArrayOf(64.0,-13.5),
                doubleArrayOf(65.5,-13.5), doubleArrayOf(66.5,-14.0),
            ),

            // ── New Zealand (simplified) ──────────────────────────────
            "New Zealand N" to arrayOf(
                doubleArrayOf(-34.5,172.5), doubleArrayOf(-35.0,174.5), doubleArrayOf(-36.5,175.5),
                doubleArrayOf(-38.5,178.0), doubleArrayOf(-39.5,177.0), doubleArrayOf(-41.0,175.0),
                doubleArrayOf(-41.5,174.0), doubleArrayOf(-40.5,172.5), doubleArrayOf(-38.5,174.5),
                doubleArrayOf(-36.5,174.5), doubleArrayOf(-34.5,172.5),
            ),
            "New Zealand S" to arrayOf(
                doubleArrayOf(-40.5,172.5), doubleArrayOf(-41.5,171.5), doubleArrayOf(-43.0,171.0),
                doubleArrayOf(-44.5,168.0), doubleArrayOf(-46.5,168.5), doubleArrayOf(-46.0,170.5),
                doubleArrayOf(-44.5,171.5), doubleArrayOf(-43.5,172.5), doubleArrayOf(-42.5,173.5),
                doubleArrayOf(-41.5,174.0), doubleArrayOf(-40.5,172.5),
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// WrapLayout — FlowLayout that correctly reports its wrapped preferred/minimum
// size so BorderLayout.NORTH/SOUTH slots grow to fit all items on any screen.
//
// Standard approach: override preferredLayoutSize / minimumLayoutSize to walk
// the container and calculate actual multi-row height.
// ---------------------------------------------------------------------------
private class WrapLayout(align: Int = FlowLayout.LEFT, hgap: Int = 5, vgap: Int = 5)
    : FlowLayout(align, hgap, vgap) {

    override fun preferredLayoutSize(target: java.awt.Container): java.awt.Dimension =
        layoutSize(target, preferred = true)

    override fun minimumLayoutSize(target: java.awt.Container): java.awt.Dimension =
        layoutSize(target, preferred = false)

    private fun layoutSize(target: java.awt.Container, preferred: Boolean): java.awt.Dimension {
        synchronized(target.treeLock) {
            // Use the target's own width when laid out; fall back to parent or a large default.
            val targetWidth = target.size.width
                .takeIf { it > 0 }
                ?: (target.parent?.size?.width ?: Int.MAX_VALUE)

            val insets   = target.insets
            val maxWidth = targetWidth - insets.left - insets.right - hgap * 2

            var dim       = java.awt.Dimension(0, 0)
            var rowWidth  = 0
            var rowHeight = 0

            for (i in 0 until target.componentCount) {
                val c = target.getComponent(i)
                if (!c.isVisible) continue
                val d = if (preferred) c.preferredSize else c.minimumSize

                // Wrap to a new row when this component won't fit
                if (rowWidth + d.width > maxWidth && rowWidth > 0) {
                    dim = java.awt.Dimension(
                        maxOf(dim.width, rowWidth),
                        dim.height + rowHeight + vgap,
                    )
                    rowWidth  = 0
                    rowHeight = 0
                }

                if (rowWidth > 0) rowWidth += hgap
                rowWidth  += d.width
                rowHeight  = maxOf(rowHeight, d.height)
            }

            // Add the final (or only) row
            dim = java.awt.Dimension(
                maxOf(dim.width, rowWidth) + insets.left + insets.right + hgap * 2,
                dim.height + rowHeight    + insets.top  + insets.bottom + vgap * 2,
            )
            return dim
        }
    }
}
