import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "SentryModel.js" as SentryModel

// cyber.sentry — a cybersecurity threat-intel bar widget + panel.
//
// Sources: Arch Security Tracker, CISA KEV, NVD 2.0, ExploitDB,
// NCSC-NL advisories. EPSS scores enrich all CVE-bearing rows.
//
// v2.0: added NVD Recent, Alerts, EPSS, ExploitDB, KEV-installed
// correlation, bootstrap notification suppression, recency filters.
// v2.2: added an exposure-trend sparkline, a CVE watchlist, a weekly
// digest notification, theme-derived severity colors, a do-not-disturb
// notification schedule, and the cyber-sentry-status CLI companion.

Panel {
  id: root

  readonly property string pluginId: "cyber.sentry"

  moduleName: pluginId
  ipcTarget: pluginId

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  readonly property string shieldGlyph: "󰕥"   // nf-md-shield-check
  readonly property string refreshGlyph: "󰑐"  // nf-md-refresh
  readonly property string pauseGlyph: "󰏤"    // nf-md-pause
  readonly property string closeGlyph: "󰅖"    // nf-md-close
  readonly property string alertGlyph: "󰀦"    // nf-md-alert-circle

  readonly property string archPath: Qt.resolvedUrl("arch-fetch").toString().replace(/^file:\/\//, "")
  readonly property string kevPath: Qt.resolvedUrl("kev-fetch").toString().replace(/^file:\/\//, "")
  readonly property string cvePath: Qt.resolvedUrl("cve-fetch").toString().replace(/^file:\/\//, "")
  readonly property string epssPath: Qt.resolvedUrl("epss-fetch").toString().replace(/^file:\/\//, "")
  readonly property string exploitdbPath: Qt.resolvedUrl("exploitdb-fetch").toString().replace(/^file:\/\//, "")
  readonly property string nvdPath: Qt.resolvedUrl("nvd-fetch").toString().replace(/^file:\/\//, "")
  readonly property string alertsPath: Qt.resolvedUrl("alerts-fetch").toString().replace(/^file:\/\//, "")
  readonly property string osvPath: Qt.resolvedUrl("osv-fetch").toString().replace(/^file:\/\//, "")

  readonly property string stateDir: Quickshell.env("HOME") + "/.local/state/omarchy/settings"
  readonly property string configPath: stateDir + "/cyber-sentry.json"
  readonly property string notifyStatePath: stateDir + "/cyber-sentry-state.json"
  readonly property string historyPath: stateDir + "/cyber-sentry-history.json"
  readonly property int historyMaxPoints: 200
  readonly property int historyMinIntervalMs: 5 * 60000

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accentColor: Color.accent
  readonly property color mutedColor: Color.muted
  readonly property color dim: Qt.darker(foreground, 1.45)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  // --- schema-driven settings ------------------------------------------------
  readonly property int refreshIntervalMs: Math.round(SentryModel.clamp(setting("refreshIntervalMin", 30), 10, 1440, 30)) * 60000
  readonly property string severityThreshold: String(setting("severityThreshold", "Medium"))
  readonly property bool archEnabled: setting("archEnabled", true)
  readonly property bool kevEnabled: setting("kevEnabled", true)
  readonly property bool nvdEnabled: setting("nvdEnabled", true)
  readonly property bool alertsEnabled: setting("alertsEnabled", true)
  readonly property bool epssEnabled: setting("epssEnabled", true)
  readonly property bool exploitdbEnabled: setting("exploitdbEnabled", true)
  readonly property bool osvEnabled: setting("osvEnabled", true)
  readonly property bool notifyOnAffected: setting("notifyOnAffected", true)
  readonly property bool notifyOnKev: setting("notifyOnKev", true)
  readonly property bool notifyOnNvd: setting("notifyOnNvd", false)
  readonly property bool notifyOnAlerts: setting("notifyOnAlerts", false)
  readonly property int notifyCooldownMs: Math.round(SentryModel.clamp(setting("notifyCooldownMin", 60), 5, 1440, 60)) * 60000
  readonly property int maxItems: Math.round(SentryModel.clamp(setting("maxItems", 50), 10, 500, 10))
  readonly property bool showBadge: setting("showBadge", true)
  readonly property bool showKevBadge: setting("showKevBadge", false)
  readonly property int kevRecentDays: Math.round(SentryModel.clamp(setting("kevRecentDays", 90), 0, 365, 90))
  readonly property bool kevAffectsMeOnly: setting("kevAffectsMeOnly", false)
  readonly property bool showTrend: setting("showTrend", true)
  readonly property bool digestEnabled: setting("digestEnabled", true)
  readonly property int digestIntervalDays: Math.round(SentryModel.clamp(setting("digestIntervalDays", 7), 1, 30, 7))
  readonly property bool dndEnabled: setting("dndEnabled", false)
  readonly property string dndStart: String(setting("dndStart", "22:00"))
  readonly property string dndEnd: String(setting("dndEnd", "07:00"))

  // --- live state -----------------------------------------------------------
  property var archParsed: null
  property var kevParsed: null
  property var nvdParsed: null
  property var alertsParsed: null
  property var epssParsed: null
  property var exploitdbParsed: null
  property var osvParsed: null
  property var installedMap: ({})
  property var aurPackages: []
  // Never fold into totalBadge/urgent color below: these are real installed
  // packages, not detected threats — only uncorrelated by Arch Security Tracker.
  readonly property int aurCount: aurPackages.length
  property bool initialized: false
  property bool archFetching: false
  property bool kevFetching: false
  property bool nvdFetching: false
  property bool alertsFetching: false
  property bool epssFetching: false
  property bool exploitdbFetching: false
  property bool osvFetching: false
  property var notified: ({})
  property real lastDigestAt: 0
  property bool stateLoaded: false
  property var history: []
  property bool historyLoaded: false
  property bool bootstrapDone: false
  property int activeTab: 0  // 0=System, 1=Exploited, 2=Recent, 3=Alerts, 4=AUR, 5=Dev
  property string cveDetailTitle: ""
  property string cveDetailText: ""
  property bool cveDetailOpen: false
  property bool cveDetailError: false
  property var cveDetailFix: null

  property var userConfig: ({})
  property bool configLoaded: false

  readonly property bool refreshing: archFetching || kevFetching || nvdFetching || alertsFetching || epssFetching || exploitdbFetching || osvFetching
  readonly property bool paused: conf("paused", false)

  // --- config / settings lookups -------------------------------------------
  function booleanValue(value) {
    if (typeof value === "string") return value !== "false" && value !== "0" && value !== ""
    return value !== false
  }

  function setting(key, fallback) {
    var value = settings ? settings[key] : undefined
    if (value === undefined || value === null) return fallback
    if (typeof fallback !== "boolean") return value
    return booleanValue(value)
  }

  function conf(key, fallback) {
    var value
    if (userConfig && userConfig[key] !== undefined && userConfig[key] !== null) value = userConfig[key]
    var fromShell = settings ? settings[key] : undefined
    if (value === undefined && fromShell !== undefined && fromShell !== null) value = fromShell
    if (value === undefined) return fallback
    return typeof fallback === "boolean" ? booleanValue(value) : value
  }

  function applyUserConfig(raw) {
    var parsed
    try {
      parsed = JSON.parse(String(raw || "{}"))
    } catch (e) {
      parsed = {}
    }
    userConfig = (parsed && typeof parsed === "object") ? parsed : ({})
    configLoaded = true
  }

  function saveConfig(values) {
    var next = ({})
    for (var k in userConfig) next[k] = userConfig[k]
    for (var key in values) {
      if (values[key] === null) delete next[key]
      else next[key] = values[key]
    }
    userConfig = next
    configFile.setText(JSON.stringify(next, null, 2) + "\n")
  }

  // --- derived data ----------------------------------------------------------
  property var enrichedRows: {
    var r = SentryModel.buildRows(archParsed, kevParsed, nvdParsed, alertsParsed, osvParsed)
    if (epssParsed) r = SentryModel.epssMerge(r, epssParsed)
    if (exploitdbParsed) r = SentryModel.exploitMerge(r, exploitdbParsed)
    if (Object.keys(installedMap).length > 0) r = SentryModel.installMerge(r, installedMap)
    return r
  }

  readonly property var watchlist: {
    var w = conf("watchlist", [])
    return Array.isArray(w) ? w : []
  }

  function toggleWatch(cveId) {
    if (!cveId) return
    var next = watchlist.slice()
    var idx = next.indexOf(cveId)
    if (idx >= 0) next.splice(idx, 1)
    else next.push(cveId)
    saveConfig({ watchlist: next })
  }

  readonly property var systemRows: SentryModel.sortBySeverity(
    SentryModel.filterByThresholdOrWatched(SentryModel.archRows(enrichedRows), severityThreshold, watchlist)
  ).slice(0, maxItems)
  readonly property var fixSummary: SentryModel.fixableSummary(systemRows)
  readonly property var kevFiltered: {
    var kRows = SentryModel.kevRows(enrichedRows)
    if (kevRecentDays > 0) kRows = SentryModel.kevRecentFilter(kRows, kevRecentDays)
    if (kevAffectsMeOnly) kRows = kRows.filter(function(r) { return r.installed })
    return SentryModel.sortByDateDesc(kRows).slice(0, maxItems)
  }
  readonly property var nvdRows: SentryModel.sortBySeverity(
    SentryModel.filterByThresholdOrWatched(SentryModel.nvdRows(enrichedRows), severityThreshold, watchlist)
  ).slice(0, maxItems)
  readonly property var alertRows: SentryModel.sortByDateDesc(SentryModel.alertRows(enrichedRows)).slice(0, maxItems)
  readonly property var osvRows: SentryModel.sortBySeverity(
    SentryModel.filterByThresholdOrWatched(SentryModel.osvRows(enrichedRows), severityThreshold, watchlist)
  ).slice(0, maxItems)

  readonly property int badgeCount: SentryModel.affectedCount(archParsed, severityThreshold)
  readonly property int kevCount: kevFiltered.length
  // Intentionally excludes aurCount — see its declaration above.
  readonly property int totalBadge: showKevBadge ? badgeCount + kevCount : badgeCount
  readonly property bool badgeVisible: showBadge && totalBadge > 0 && !paused

  // Theme-derived severity colors, following the same idiom Omarchy's own
  // notification cards use for collapsing more urgency levels than the
  // theme has distinct tokens for: the alarm color (urgent) at full and
  // reduced alpha for the two most severe tiers, then accent/muted for the
  // remaining two. Omarchy has no danger/warning/success scale — only
  // foreground/background/accent/urgent/muted — so this is a deliberate
  // choice, not a stand-in for a "real" 4-hue palette that doesn't exist.
  function severityColor(sev) {
    switch (SentryModel.severityKey(sev)) {
      case "critical": return urgent
      case "high": return Qt.rgba(urgent.r, urgent.g, urgent.b, 0.7)
      case "medium": return accentColor
      case "low": return mutedColor
      default: return dim
    }
  }

  readonly property string archStatusLabel: {
    if (!archEnabled) return "off"
    if (archFetching) return "syncing"
    if (archParsed === null) return "idle"
    return SentryModel.sourceOk(archParsed) ? "ok" : "error"
  }

  readonly property string kevStatusLabel: {
    if (!kevEnabled) return "off"
    if (kevFetching) return "syncing"
    if (kevParsed === null) return "idle"
    return SentryModel.sourceOk(kevParsed) ? "ok" : "error"
  }

  readonly property string nvdStatusLabel: {
    if (!nvdEnabled) return "off"
    if (nvdFetching) return "syncing"
    if (nvdParsed === null) return "idle"
    return SentryModel.sourceOk(nvdParsed) ? "ok" : "error"
  }

  readonly property string alertsStatusLabel: {
    if (!alertsEnabled) return "off"
    if (alertsFetching) return "syncing"
    if (alertsParsed === null) return "idle"
    return SentryModel.sourceOk(alertsParsed) ? "ok" : "error"
  }

  readonly property string epssStatusLabel: {
    if (!epssEnabled) return "off"
    if (epssFetching) return "syncing"
    if (epssParsed === null) return "idle"
    return SentryModel.sourceOk(epssParsed) ? "ok" : "error"
  }

  readonly property string exploitdbStatusLabel: {
    if (!exploitdbEnabled) return "off"
    if (exploitdbFetching) return "syncing"
    if (exploitdbParsed === null) return "idle"
    return SentryModel.sourceOk(exploitdbParsed) ? "ok" : "error"
  }

  readonly property string osvStatusLabel: {
    if (!osvEnabled) return "off"
    if (osvFetching) return "syncing"
    if (osvParsed === null) return "idle"
    return SentryModel.sourceOk(osvParsed) ? "ok" : "error"
  }

  readonly property string lastUpdatedText: {
    var sources = [archParsed, kevParsed, nvdParsed, alertsParsed, epssParsed, exploitdbParsed, osvParsed]
    var newest = ""
    for (var i = 0; i < sources.length; i++) {
      var t = SentryModel.checkedAt(sources[i])
      if (t > newest) newest = t
    }
    return SentryModel.timeAgo(newest, Date.now())
  }

  readonly property string summary: {
    if (paused) return "Sentry paused"
    if (!initialized) return "Checking for threats…"
    if (archEnabled && archParsed !== null && !SentryModel.sourceOk(archParsed))
      return "Arch feed unavailable: " + SentryModel.sourceError(archParsed)
    var parts = []
    if (badgeCount > 0) parts.push(badgeCount + " affected")
    if (kevCount > 0) parts.push(kevCount + " exploited")
    if (nvdRows.length > 0) parts.push(nvdRows.length + " recent CVE")
    if (alertRows.length > 0) parts.push(alertRows.length + " alert")
    if (osvRows.length > 0) parts.push(osvRows.length + " dev package")
    if (parts.length > 0) return parts.join(" · ")
    return "No threats matching the threshold — you are up to date"
  }

  // --- fetching -------------------------------------------------------------
  function refresh() {
    if (paused) return
    if (archEnabled && !archFetching) {
      archFetching = true
      archProcess.command = [archPath]
      archProcess.running = true
    }
    if (kevEnabled && !kevFetching) {
      kevFetching = true
      kevProcess.command = [kevPath]
      kevProcess.running = true
    }
    if (nvdEnabled && !nvdFetching) {
      nvdFetching = true
      nvdProcess.command = [nvdPath]
      nvdProcess.running = true
    }
    if (alertsEnabled && !alertsFetching) {
      alertsFetching = true
      alertsProcess.command = [alertsPath]
      alertsProcess.running = true
    }
    if (exploitdbEnabled && !exploitdbFetching) {
      exploitdbFetching = true
      exploitdbProcess.command = [exploitdbPath]
      exploitdbProcess.running = true
    }
    if (osvEnabled && !osvFetching) {
      osvFetching = true
      osvProcess.command = [osvPath]
      osvProcess.running = true
    }
    // EPSS runs after other sources (needs CVE list from their caches)
    if (epssEnabled && !epssFetching) {
      epssFetching = true
      epssProcess.command = [epssPath]
      epssProcess.running = true
    }
    checkDigest()
    recordHistoryPoint()
  }

  // --- weekly digest ----------------------------------------------------
  function checkDigest() {
    if (!digestEnabled || !stateLoaded) return
    var now = Date.now()
    if (lastDigestAt === 0) {
      // First run: establish a baseline rather than firing immediately —
      // same bootstrap-suppression idea used for regular notifications.
      lastDigestAt = now
      saveNotifyState()
      return
    }
    if (now - lastDigestAt < digestIntervalDays * 86400000) return

    var parts = []
    if (badgeCount > 0) parts.push(badgeCount + " affected")
    if (kevCount > 0) parts.push(kevCount + " exploited")
    if (nvdRows.length > 0) parts.push(nvdRows.length + " recent CVE")
    var body = parts.length > 0 ? parts.join(" · ") : "No threats matching your threshold — you are up to date"

    lastDigestAt = now
    saveNotifyState()
    sendNotification("Cyber Sentry — " + digestIntervalDays + "-day digest", body, false)
  }

  function applyArch(exitCode, out, err) {
    archFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "arch", error: detail !== "" ? detail : "arch-fetch exited " + exitCode }
    }
    archParsed = parsed
    initialized = true
    evaluateNotifications("arch")
    refreshTimer.restart()
  }

  function applyKev(exitCode, out, err) {
    kevFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "kev", error: detail !== "" ? detail : "kev-fetch exited " + exitCode }
    }
    kevParsed = parsed
    initialized = true
    evaluateNotifications("kev")
    refreshTimer.restart()
  }

  function applyNvd(exitCode, out, err) {
    nvdFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "nvd", error: detail !== "" ? detail : "nvd-fetch exited " + exitCode }
    }
    nvdParsed = parsed
    initialized = true
    evaluateNotifications("nvd")
  }

  function applyAlerts(exitCode, out, err) {
    alertsFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "alerts", error: detail !== "" ? detail : "alerts-fetch exited " + exitCode }
    }
    alertsParsed = parsed
    initialized = true
    evaluateNotifications("alerts")
  }

  function applyEpss(exitCode, out, err) {
    epssFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "epss", error: detail !== "" ? detail : "epss-fetch exited " + exitCode }
    }
    epssParsed = parsed
    initialized = true
  }

  function applyExploitdb(exitCode, out, err) {
    exploitdbFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "exploitdb", error: detail !== "" ? detail : "exploitdb-fetch exited " + exitCode }
    }
    exploitdbParsed = parsed
    initialized = true
  }

  function applyOsv(exitCode, out, err) {
    osvFetching = false
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      parsed = { ok: false, source: "osv", error: detail !== "" ? detail : "osv-fetch exited " + exitCode }
    }
    osvParsed = parsed
    initialized = true
  }

  // --- notifications --------------------------------------------------------
  function evaluateNotifications(type) {
    // Bootstrap suppression: on the very first successful fetch, mark all items
    // seen silently — no notification flood.
    if (!bootstrapDone) {
      if (SentryModel.sourceOk(archParsed) && SentryModel.sourceOk(kevParsed)) {
        bootstrapDone = true
        var allRows = SentryModel.buildRows(archParsed, kevParsed, null, null, null)
        SentryModel.markAllSeen(allRows, notified, Date.now())
        saveNotifyState()
        return
      }
    }

    var now = Date.now()
    var fresh = []
    if (type === "arch" && notifyOnAffected) {
      fresh = SentryModel.newNotifiable(
        SentryModel.filterByThreshold(SentryModel.archRows(enrichedRows), severityThreshold),
        notified, now, notifyCooldownMs)
    } else if (type === "kev" && notifyOnKev) {
      fresh = SentryModel.newNotifiable(SentryModel.kevRows(enrichedRows), notified, now, notifyCooldownMs)
    } else if (type === "nvd" && notifyOnNvd) {
      fresh = SentryModel.newNotifiable(
        SentryModel.filterByThreshold(SentryModel.nvdRows(enrichedRows), severityThreshold),
        notified, now, notifyCooldownMs)
    } else if (type === "alerts" && notifyOnAlerts) {
      fresh = SentryModel.newNotifiable(SentryModel.alertRows(enrichedRows), notified, now, notifyCooldownMs)
    }

    if (fresh.length === 0) return
    var isUrgent = false
    var text = SentryModel.notificationText(fresh[0])
    for (var i = 0; i < fresh.length; i++) {
      notified[fresh[i].id] = now
      if (fresh[i].type === "arch" && SentryModel.severityRank(fresh[i].severity) >= 2) isUrgent = true
      if (fresh[i].type === "kev") isUrgent = true
      if (fresh[i].type === "nvd") isUrgent = true
    }
    saveNotifyState()
    if (fresh.length === 1) {
      sendNotification(text.headline, text.body, isUrgent)
    } else {
      var n = fresh.length
      var label = type === "arch" ? "affected advisories" : type === "kev" ? "exploited CVEs" : type === "nvd" ? "recent CVEs" : "vendor advisories"
      sendNotification(n + " new " + label,
        "Check the panel for details", isUrgent)
    }
  }

  function sendNotification(headline, body, isUrgent) {
    // DND suppresses the OS popup only — notified-state above is already
    // updated by the caller regardless, so ending the window doesn't cause
    // a backlog flood, and the badge/panel keep reflecting live data.
    if (dndEnabled && SentryModel.isWithinDnd(dndStart, dndEnd, new Date())) return
    notificationProcess.running = false
    notificationProcess.command = ["omarchy-notification-send", "-a", "--app-name", "sentry",
      "-u", isUrgent ? "critical" : "normal", "-g", shieldGlyph, headline, body]
    notificationProcess.running = true
  }

  function applyNotifyState(raw) {
    var parsed
    try { parsed = JSON.parse(String(raw || "{}")) } catch (e) { parsed = {} }
    notified = (parsed && typeof parsed === "object" && parsed.notified) ? parsed.notified : ({})
    lastDigestAt = (parsed && typeof parsed === "object" && parsed.lastDigestAt) ? Number(parsed.lastDigestAt) || 0 : 0
    stateLoaded = true
  }

  function saveNotifyState() {
    if (!stateLoaded) return
    SentryModel.pruneNotified(notified, 7 * 86400000)
    notifyStateFile.setText(JSON.stringify({ notified: notified, lastDigestAt: lastDigestAt }, null, 2) + "\n")
  }

  // --- trend history ------------------------------------------------------
  function applyHistory(raw) {
    var parsed
    try { parsed = JSON.parse(String(raw || "[]")) } catch (e) { parsed = [] }
    history = Array.isArray(parsed) ? parsed : []
    historyLoaded = true
  }

  function recordHistoryPoint() {
    if (!historyLoaded || !initialized) return
    var last = history.length > 0 ? history[history.length - 1] : null
    var now = Date.now()
    if (last && now - new Date(last.t).getTime() < historyMinIntervalMs) return
    history = SentryModel.appendHistoryPoint(
      history, { t: new Date(now).toISOString(), badgeCount: badgeCount, kevCount: kevCount }, historyMaxPoints)
    historyFile.setText(JSON.stringify(history) + "\n")
  }

  // --- cve.org detail on demand ---------------------------------------------
  function openCveDetail(row) {
    cveDetailFix = SentryModel.archFixState(row)

    // OSV findings already carry their full description/severity/references
    // straight from osv-fetch's one-shot /v1/query call — no on-demand
    // cve.org lookup needed (and OSV ids like GHSA-/PYSEC-/RUSTSEC- aren't
    // CVE ids cve-fetch could look up anyway).
    if (row && row.type === "osv") {
      cveDetailTitle = row.ecosystem + " · " + row.packages + " " + row.version + " · " + row.id
      var refText = (row.references && row.references.length > 0)
        ? "\n\nReferences:\n" + row.references.join("\n") : ""
      cveDetailText = (row.description || "No description available.")
        + "\n\nSeverity: " + (row.severity || "UNKNOWN") + refText
      cveDetailError = false
      cveDetailOpen = true
      cveProcess.running = false
      return
    }

    var cve = SentryModel.firstCve(row)

    if (!cve) {
      cveDetailTitle = (row && row.id) ? row.id : "No CVE"
      cveDetailText = "No CVE ID is associated with this advisory."
      cveDetailError = false
      cveDetailOpen = true
      cveProcess.running = false
      return
    }

    cveDetailTitle = row.type === "arch" ? (row.id + " · " + cve) : cve
    cveDetailText = "Loading " + cve + "…"
    cveDetailError = false
    cveDetailOpen = true

    cveProcess.running = false
    cveProcess.command = [cvePath, cve]
    cveProcess.running = true
  }

  function copyToClipboard(value) {
    if (!value) return
    Util.execDetached("printf %s " + Util.shellQuote(value) + " | wl-copy")
  }

  function applyCveDetail(exitCode, out, err) {
    var parsed = null
    if (exitCode === 0) {
      try { parsed = JSON.parse(String(out || "")) } catch (e) { parsed = null }
    }
    if (!parsed || parsed.ok !== true) {
      var detail = String(err || "").replace(/\s+/g, " ").replace(/^\s+|\s+$/g, "")
      cveDetailText = detail !== "" ? detail : "Could not load details (exit " + exitCode + ")"
      cveDetailError = true
      return
    }
    cveDetailError = false
    cveDetailText = String(parsed.description || "No description available.") + "\n\n"
      + (parsed.severity ? "Severity: " + parsed.severity + (parsed.score ? " (" + parsed.score + ")" : "") + "\n" : "")
      + (parsed.references && parsed.references.length > 0
          ? "\nReferences:\n" + parsed.references.join("\n") : "")
  }

  // --- lifecycle ------------------------------------------------------------
  Component.onCompleted: {
    configFile.reload()
    notifyStateFile.reload()
    historyFile.reload()
    // Absolute path, not ambient-PATH "pacman" — this drives the same
    // installed-package correlation the fetch scripts' security checks
    // depend on; a shadowed pacman would silently poison it.
    installedProcess.command = ["/usr/bin/pacman", "-Q"]
    installedProcess.running = true
    aurProcess.command = ["/usr/bin/pacman", "-Qm"]
    aurProcess.running = true
    refreshTimer.start()
    refresh()
  }

  onPausedChanged: {
    if (paused) refreshTimer.stop()
    else {
      refreshTimer.restart()
      refresh()
    }
  }

  onOpenedChanged: {
    if (opened) {
      if (!initialized) refresh()
      refreshTimer.restart()
    }
  }

  onNotifyOnAffectedChanged: saveNotifyState()
  onNotifyOnKevChanged: saveNotifyState()

  // --- persistence ----------------------------------------------------------
  FileView {
    id: configFile
    path: root.configPath
    watchChanges: false
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyUserConfig(text())
    onLoadFailed: root.applyUserConfig("{}")
  }

  FileView {
    id: notifyStateFile
    path: root.notifyStatePath
    watchChanges: false
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyNotifyState(text())
    onLoadFailed: root.applyNotifyState("{}")
  }

  FileView {
    id: historyFile
    path: root.historyPath
    watchChanges: false
    atomicWrites: true
    printErrors: false
    onLoaded: root.applyHistory(text())
    onLoadFailed: root.applyHistory("[]")
  }

  // --- background processes ---------------------------------------------------
  Process {
    id: archProcess
    running: false
    command: []
    stdout: StdioCollector { id: archStdout; waitForEnd: true }
    stderr: StdioCollector { id: archStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyArch(exitCode, archStdout.text, archStderr.text) }
  }

  Process {
    id: kevProcess
    running: false
    command: []
    stdout: StdioCollector { id: kevStdout; waitForEnd: true }
    stderr: StdioCollector { id: kevStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyKev(exitCode, kevStdout.text, kevStderr.text) }
  }

  Process {
    id: nvdProcess
    running: false
    command: []
    stdout: StdioCollector { id: nvdStdout; waitForEnd: true }
    stderr: StdioCollector { id: nvdStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyNvd(exitCode, nvdStdout.text, nvdStderr.text) }
  }

  Process {
    id: alertsProcess
    running: false
    command: []
    stdout: StdioCollector { id: alertsStdout; waitForEnd: true }
    stderr: StdioCollector { id: alertsStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyAlerts(exitCode, alertsStdout.text, alertsStderr.text) }
  }

  Process {
    id: epssProcess
    running: false
    command: []
    stdout: StdioCollector { id: epssStdout; waitForEnd: true }
    stderr: StdioCollector { id: epssStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyEpss(exitCode, epssStdout.text, epssStderr.text) }
  }

  Process {
    id: exploitdbProcess
    running: false
    command: []
    stdout: StdioCollector { id: exploitdbStdout; waitForEnd: true }
    stderr: StdioCollector { id: exploitdbStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyExploitdb(exitCode, exploitdbStdout.text, exploitdbStderr.text) }
  }

  Process {
    id: osvProcess
    running: false
    command: []
    stdout: StdioCollector { id: osvStdout; waitForEnd: true }
    stderr: StdioCollector { id: osvStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyOsv(exitCode, osvStdout.text, osvStderr.text) }
  }

  Process {
    id: cveProcess
    running: false
    command: []
    stdout: StdioCollector { id: cveStdout; waitForEnd: true }
    stderr: StdioCollector { id: cveStderr; waitForEnd: true }
    onExited: function(exitCode) { root.applyCveDetail(exitCode, cveStdout.text, cveStderr.text) }
  }

  Process {
    id: installedProcess
    running: false
    command: []
    stdout: StdioCollector { id: installedStdout; waitForEnd: true }
    onExited: {
      var map = ({})
      var list = SentryModel.parsePackageList(installedStdout.text)
      for (var i = 0; i < list.length; i++) map[list[i].name] = list[i].version
      root.installedMap = map
    }
  }

  // Foreign/AUR packages: `pacman -Qm` is the exact set Arch Security
  // Tracker's per-package/per-version correlation can never cover, since it
  // only tracks official [core]/[extra] repo packages.
  Process {
    id: aurProcess
    running: false
    command: []
    stdout: StdioCollector { id: aurStdout; waitForEnd: true }
    onExited: {
      root.aurPackages = SentryModel.sortByName(SentryModel.parsePackageList(aurStdout.text))
    }
  }

  Process {
    id: notificationProcess
    running: false
    command: []
    stdout: StdioCollector { id: notificationStdout; waitForEnd: true }
    onExited: {
      if (String(notificationStdout.text).replace(/\s+/g, "") === "default") root.open()
    }
  }

  Timer {
    id: refreshTimer
    interval: root.refreshIntervalMs
    repeat: true
    onTriggered: root.refresh()
  }

  // --- bar button + badge ----------------------------------------------------
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.shieldGlyph
    dimmed: !root.initialized || root.paused || (root.archEnabled && root.archParsed !== null && !SentryModel.sourceOk(root.archParsed))
    active: root.badgeVisible
    activeColor: root.urgent
    tooltipText: root.summary

    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) {
        root.refresh()
        return
      }
      root.toggle()
    }

    Rectangle {
      id: badge
      visible: root.badgeVisible
      anchors.horizontalCenter: parent.horizontalCenter
      anchors.verticalCenter: parent.verticalCenter
      anchors.horizontalCenterOffset: button.opticalSize / 2 - Style.space(1)
      anchors.verticalCenterOffset: -(button.opticalSize / 2 - Style.space(2))
      height: badgeLabel.implicitHeight + Style.spaceReal(1)
      width: Math.max(height, badgeLabel.implicitWidth + Style.spaceReal(3))
      radius: height / 2
      color: root.urgent
      border.width: 1
      border.color: Color.bar.background

      Text {
        id: badgeLabel
        anchors.centerIn: parent
        text: String(root.totalBadge)
        color: Color.background
        font.family: root.fontFamily
        font.pixelSize: Math.max(7, Math.round(Style.font.caption * 0.78))
        font.bold: true
      }
    }
  }

  // --- panel -------------------------------------------------------------------
  KeyboardPanel {
    id: popup
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    padding: Style.spacing.popupPadding
    contentWidth: popup.fittedContentWidth(Style.space(480))
    contentHeight: popup.fittedContentHeight(column.implicitHeight, Style.space(580))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) {
        if (direction > 0) root.activeTab = Math.min(5, root.activeTab + 1)
        else root.activeTab = Math.max(0, root.activeTab - 1)
      }
      onTextKey: function(text) {
        var key = text.toLowerCase()
        if (key === "r") root.refresh()
        else if (key === "p") root.saveConfig({ paused: !root.paused })
        else if (key === "1") root.activeTab = 0
        else if (key === "2") root.activeTab = 1
        else if (key === "3") root.activeTab = 2
        else if (key === "4") root.activeTab = 3
        else if (key === "5") root.activeTab = 4
        else if (key === "6") root.activeTab = 5
        else if (key === "q" && root.cveDetailOpen) root.cveDetailOpen = false
      }

      Flickable {
        id: scroll
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.y + column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height

        Column {
          id: column
          y: 0
          width: scroll.width
          spacing: Style.space(12)

          PanelHero {
            title: "Threat Sentry"
            meta: root.summary
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconOpacity: 1
            iconComponent: Component {
              Text {
                text: root.shieldGlyph
                color: root.badgeVisible ? root.urgent : root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }
            }
            trailingControl: Component {
              ToggleSwitch {
                id: pauseSwitch
                checked: root.paused
                foreground: root.foreground
                accent: root.urgent
                onToggled: root.saveConfig({ paused: !root.paused })
                PanelToolTip {
                  visible: pauseSwitch.containsMouse
                  text: root.paused ? "Resume sentry" : "Pause sentry"
                  fontFamily: root.fontFamily
                }
              }
            }
          }

          Sparkline {
            id: trendSparkline
            visible: root.showTrend && root.history.length >= 2
            width: parent.width
            height: Style.space(28)
            points: SentryModel.sparklinePoints(root.history, width, height, 3)
            lineColor: root.accentColor
            PanelToolTip {
              visible: trendSparklineArea.containsMouse
              text: "Affected-package count over time"
              fontFamily: root.fontFamily
            }
            MouseArea {
              id: trendSparklineArea
              anchors.fill: parent
              hoverEnabled: true
            }
          }

          // Source status pills
          Row {
            width: parent.width
            spacing: Style.space(6)

            StatusPill { pillLabel: "ARCH"; pillState: root.archStatusLabel }
            StatusPill { pillLabel: "KEV"; pillState: root.kevStatusLabel }
            StatusPill { pillLabel: "NVD"; pillState: root.nvdStatusLabel }
            StatusPill { pillLabel: "EPSS"; pillState: root.epssStatusLabel }

            Item { width: 1; height: 1 }

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: root.initialized ? ("checked " + root.lastUpdatedText) : ""
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }

          Row {
            width: parent.width
            spacing: Style.space(6)

            StatusPill { pillLabel: "EDB"; pillState: root.exploitdbStatusLabel }
            StatusPill { pillLabel: "ALERT"; pillState: root.alertsStatusLabel }
            StatusPill { pillLabel: "OSV"; pillState: root.osvStatusLabel }
          }

          Text {
            width: parent.width
            visible: root.aurCount > 0
            wrapMode: Text.Wrap
            text: root.aurCount + " AUR/foreign package" + (root.aurCount === 1 ? "" : "s")
              + " not tracked by Arch Security Tracker — see the AUR tab"
            color: "#ffb020"
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.activeTab = 4
            }
          }

          // Tab row
          Row {
            id: tabRow
            width: parent.width
            spacing: Style.space(4)

            TabButton {
              tabLabel: "System (" + SentryModel.archRows(root.enrichedRows).length + ")"
              tabActive: root.activeTab === 0
              onClicked: root.activeTab = 0
            }
            TabButton {
              tabLabel: "Exploited (" + root.kevCount + ")"
              tabActive: root.activeTab === 1
              onClicked: root.activeTab = 1
            }
            TabButton {
              tabLabel: "Recent (" + root.nvdRows.length + ")"
              tabActive: root.activeTab === 2
              onClicked: root.activeTab = 2
            }
            TabButton {
              tabLabel: "Alerts (" + root.alertRows.length + ")"
              tabActive: root.activeTab === 3
              onClicked: root.activeTab = 3
            }
            TabButton {
              tabLabel: "AUR (" + root.aurCount + ")"
              tabActive: root.activeTab === 4
              onClicked: root.activeTab = 4
            }
            TabButton {
              tabLabel: "Dev (" + root.osvRows.length + ")"
              tabActive: root.activeTab === 5
              onClicked: root.activeTab = 5
            }
          }

          // --- System tab ----------------------------------------------------
          Rectangle {
            id: systemView
            width: parent.width
            visible: root.activeTab === 0
            height: root.activeTab === 0 ? Style.space(340) : 0
            radius: Style.space(6)
            color: "transparent"

            Column {
              id: fixBanner
              visible: root.fixSummary.fixable > 0
              width: parent.width
              spacing: Style.space(2)

              Row {
                width: parent.width
                spacing: Style.space(6)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.fixSummary.fixable + " of " + root.fixSummary.total
                    + " affected packages are cleared by running:"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }
              }

              Row {
                width: parent.width
                spacing: Style.space(6)

                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  text: "sudo pacman -Syu"
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                }

                Button {
                  text: "Copy"
                  tooltipText: "Copy command to clipboard"
                  bordered: true
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.copyToClipboard("sudo pacman -Syu")
                }

                Button {
                  visible: root.bar !== null
                  text: "Run in terminal"
                  tooltipText: "Open a floating terminal to run it"
                  bordered: true
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  fontSize: Style.font.caption
                  onClicked: root.bar.run("omarchy-launch-floating-terminal-with-presentation "
                    + Util.shellQuote("sudo pacman -Syu"))
                }
              }
            }

            ListView {
              id: systemList
              anchors.top: fixBanner.visible ? fixBanner.bottom : parent.top
              anchors.topMargin: fixBanner.visible ? Style.space(6) : 0
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.bottom: parent.bottom
              clip: true
              model: root.systemRows
              spacing: Style.space(3)
              cacheBuffer: Style.space(60)

              delegate: ArchRowDelegate {
                width: systemList.width
                onSelected: root.openCveDetail(modelData)
              }
            }

            Text {
              anchors.centerIn: parent
              visible: !root.archEnabled
              text: "Arch feed is disabled in settings"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              anchors.centerIn: parent
              visible: root.archEnabled && root.archParsed !== null && !SentryModel.sourceOk(root.archParsed)
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: "Arch feed unavailable: " + SentryModel.sourceError(root.archParsed)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }

            Text {
              anchors.centerIn: parent
              visible: root.archEnabled && (root.archParsed === null || SentryModel.sourceOk(root.archParsed))
                && systemList.count === 0 && root.initialized
              text: root.initialized ? "No affected advisories on your installed packages — you are up to date" : "Loading…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // --- Exploited tab ---------------------------------------------------
          Rectangle {
            id: kevView
            width: parent.width
            visible: root.activeTab === 1
            height: root.activeTab === 1 ? Style.space(340) : 0
            radius: Style.space(6)
            color: "transparent"

            ListView {
              id: kevList
              anchors.fill: parent
              clip: true
              model: root.kevFiltered
              spacing: Style.space(3)
              cacheBuffer: Style.space(60)

              delegate: KevRowDelegate {
                width: kevList.width
                onSelected: root.openCveDetail(modelData)
              }
            }

            Text {
              anchors.centerIn: parent
              visible: !root.kevEnabled
              text: "KEV feed is disabled in settings"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              anchors.centerIn: parent
              visible: root.kevEnabled && root.kevParsed !== null && !SentryModel.sourceOk(root.kevParsed)
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: "KEV feed unavailable: " + SentryModel.sourceError(root.kevParsed)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }

            Text {
              anchors.centerIn: parent
              visible: root.kevEnabled && (root.kevParsed === null || SentryModel.sourceOk(root.kevParsed))
                && kevList.count === 0 && root.initialized
              text: root.initialized ? "No exploited vulnerabilities matching filters" : "Loading…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // --- Recent (NVD) tab -----------------------------------------------
          Rectangle {
            id: nvdView
            width: parent.width
            visible: root.activeTab === 2
            height: root.activeTab === 2 ? Style.space(340) : 0
            radius: Style.space(6)
            color: "transparent"

            ListView {
              id: nvdList
              anchors.fill: parent
              clip: true
              model: root.nvdRows
              spacing: Style.space(3)
              cacheBuffer: Style.space(60)

              delegate: NvdRowDelegate {
                width: nvdList.width
                onSelected: root.openCveDetail(modelData)
              }
            }

            Text {
              anchors.centerIn: parent
              visible: !root.nvdEnabled
              text: "NVD feed is disabled in settings"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              anchors.centerIn: parent
              visible: root.nvdEnabled && root.nvdParsed !== null && !SentryModel.sourceOk(root.nvdParsed)
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: "NVD feed unavailable: " + SentryModel.sourceError(root.nvdParsed)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }

            Text {
              anchors.centerIn: parent
              visible: root.nvdEnabled && (root.nvdParsed === null || SentryModel.sourceOk(root.nvdParsed))
                && nvdList.count === 0 && root.initialized
              text: root.initialized ? "No recent High/Critical CVEs" : "Loading…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // --- Alerts tab ------------------------------------------------------
          Rectangle {
            id: alertsView
            width: parent.width
            visible: root.activeTab === 3
            height: root.activeTab === 3 ? Style.space(340) : 0
            radius: Style.space(6)
            color: "transparent"

            ListView {
              id: alertsList
              anchors.fill: parent
              clip: true
              model: root.alertRows
              spacing: Style.space(3)
              cacheBuffer: Style.space(60)

              delegate: AlertRowDelegate {
                width: alertsList.width
              }
            }

            Text {
              anchors.centerIn: parent
              visible: !root.alertsEnabled
              text: "Alerts feed is disabled in settings"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              anchors.centerIn: parent
              visible: root.alertsEnabled && root.alertsParsed !== null && !SentryModel.sourceOk(root.alertsParsed)
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: "Alerts feed unavailable: " + SentryModel.sourceError(root.alertsParsed)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }

            Text {
              anchors.centerIn: parent
              visible: root.alertsEnabled && (root.alertsParsed === null || SentryModel.sourceOk(root.alertsParsed))
                && alertsList.count === 0 && root.initialized
              text: root.initialized ? "No recent vendor advisories" : "Loading…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // --- AUR tab ---------------------------------------------------------
          Rectangle {
            id: aurView
            readonly property real panelHeight: Style.space(340)

            width: parent.width
            visible: root.activeTab === 4
            height: root.activeTab === 4 ? panelHeight : 0
            radius: Style.space(6)
            color: "transparent"

            Column {
              width: parent.width
              spacing: Style.space(6)

              Text {
                id: aurHeader
                width: parent.width
                wrapMode: Text.Wrap
                text: "Installed from the AUR or a foreign repo — Arch Security Tracker only tracks official [core]/[extra] packages, so these aren't covered by its per-package correlation. Check each package's AUR page or upstream project for advisories."
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              ListView {
                id: aurList
                width: parent.width
                height: aurView.panelHeight - aurHeader.implicitHeight - Style.space(6)
                clip: true
                model: root.aurPackages
                spacing: Style.space(3)
                cacheBuffer: Style.space(60)

                delegate: AurRowDelegate {
                  width: aurList.width
                }
              }
            }

            Text {
              anchors.centerIn: parent
              visible: root.aurCount === 0
              text: "No AUR or foreign packages installed"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // --- Dev tab (OSV.dev: pip/npm/cargo/go global installs) -----------
          Rectangle {
            id: osvView
            width: parent.width
            visible: root.activeTab === 5
            height: root.activeTab === 5 ? Style.space(340) : 0
            radius: Style.space(6)
            color: "transparent"

            ListView {
              id: osvList
              anchors.fill: parent
              clip: true
              model: root.osvRows
              spacing: Style.space(3)
              cacheBuffer: Style.space(60)

              delegate: OsvRowDelegate {
                width: osvList.width
                onSelected: root.openCveDetail(modelData)
              }
            }

            Text {
              anchors.centerIn: parent
              visible: !root.osvEnabled
              text: "OSV feed is disabled in settings"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              anchors.centerIn: parent
              visible: root.osvEnabled && root.osvParsed !== null && !SentryModel.sourceOk(root.osvParsed)
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: "OSV feed unavailable: " + SentryModel.sourceError(root.osvParsed)
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }

            Text {
              anchors.centerIn: parent
              visible: root.osvEnabled && (root.osvParsed === null || SentryModel.sourceOk(root.osvParsed))
                && osvList.count === 0 && root.initialized
              width: parent.width - Style.space(24)
              horizontalAlignment: Text.AlignHCenter
              text: root.initialized
                ? "No vulnerabilities found in your global pip/npm/cargo/go packages"
                : "Loading…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }
          }

          PanelSeparator {
            foreground: root.foreground
          }

          Row {
            width: parent.width
            spacing: Style.space(6)

            Button {
              text: root.refreshGlyph
              tooltipText: "Refresh now (R)"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.refresh()
            }

            Text {
              anchors.verticalCenter: parent.verticalCenter
              text: root.paused ? "Sentry paused" : ("Refresh every " + Math.round(root.refreshIntervalMs / 60000) + " min · "
                + "threshold " + root.severityThreshold + " · " + "cooldown "
                + Math.round(root.notifyCooldownMs / 60000) + " min")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
          }
        }
      }

      // --- cve.org detail overlay ---------------------------------------------
      Rectangle {
        id: cveOverlay
        anchors.fill: parent
        visible: root.cveDetailOpen
        radius: Style.space(8)
        color: Color.popups.background

        Column {
          anchors.fill: parent
          anchors.margins: Style.space(12)
          spacing: Style.space(8)

          Row {
            width: parent.width
            spacing: Style.space(6)

            Text {
              width: parent.width - closeButton.implicitWidth - Style.space(6)
              anchors.verticalCenter: parent.verticalCenter
              text: root.cveDetailTitle
              elide: Text.ElideRight
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
            }

            Button {
              id: closeButton
              text: root.closeGlyph
              tooltipText: "Close (Q)"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              fontSize: Style.font.caption
              onClicked: root.cveDetailOpen = false
            }
          }

          Column {
            id: fixSection
            visible: root.cveDetailFix !== null
            width: parent.width
            spacing: Style.space(4)

            Text {
              width: parent.width
              wrapMode: Text.Wrap
              text: fixSection.visible
                ? "Fix available: " + root.cveDetailFix.packages + " — updated in " + root.cveDetailFix.version
                : ""
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            Text {
              width: parent.width
              wrapMode: Text.Wrap
              text: "Arch doesn't support upgrading a single package in isolation — this runs a full system update."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }

            Row {
              width: parent.width
              spacing: Style.space(6)

              Text {
                anchors.verticalCenter: parent.verticalCenter
                text: fixSection.visible ? root.cveDetailFix.command : ""
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
              }

              Button {
                text: "Copy"
                tooltipText: "Copy command to clipboard"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.copyToClipboard(root.cveDetailFix.command)
              }

              Button {
                visible: root.bar !== null
                text: "Run in terminal"
                tooltipText: "Open a floating terminal to run it"
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                fontSize: Style.font.caption
                onClicked: root.bar.run("omarchy-launch-floating-terminal-with-presentation "
                  + Util.shellQuote(root.cveDetailFix.command))
              }
            }
          }

          Flickable {
            width: parent.width
            height: parent.height - closeButton.implicitHeight - Style.space(8)
              - (fixSection.visible ? fixSection.implicitHeight + Style.space(8) : 0)
            contentWidth: width
            contentHeight: detailText.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            Text {
              id: detailText
              width: parent.width
              text: root.cveDetailText
              color: root.cveDetailError ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.Wrap
            }
          }
        }
      }
    }
  }

  // --- inline components ----------------------------------------------------

  component StatusPill: Rectangle {
    property string pillLabel: ""
    property string pillState: "idle"

    implicitWidth: pillText.implicitWidth + Style.space(10)
    implicitHeight: pillText.implicitHeight + Style.space(4)
    radius: Style.cornerRadius
    color: "transparent"
    border.width: 1
    border.color: pillState === "ok"
      ? Qt.rgba(0.3, 0.85, 0.4, 0.6)
      : (pillState === "error"
        ? Qt.rgba(1, 0.35, 0.35, 0.6)
        : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.3))

    Text {
      id: pillText
      anchors.centerIn: parent
      text: parent.pillLabel + " · " + parent.pillState
      color: parent.pillState === "ok" ? "#4cc38a"
        : (parent.pillState === "error" ? root.urgent
          : (parent.pillState === "syncing" ? "#ffb020" : root.dim))
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: true
    }
  }

  component TabButton: Rectangle {
    property string tabLabel: ""
    property bool tabActive: false
    signal clicked()

    implicitWidth: tabBtnLabel.implicitWidth + Style.space(16)
    implicitHeight: tabBtnLabel.implicitHeight + Style.space(6)
    radius: Style.space(4)
    color: tabActive
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.14)
      : "transparent"
    border.width: 1
    border.color: tabActive
      ? root.foreground
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.25)

    MouseArea { anchors.fill: parent; onClicked: parent.clicked() }

    Text {
      id: tabBtnLabel
      anchors.centerIn: parent
      text: parent.tabLabel
      color: parent.tabActive ? root.foreground : root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.caption
      font.bold: parent.tabActive
    }
  }

  component Sparkline: Canvas {
    id: sparklineCanvas
    property var points: []
    property color lineColor: root.accentColor

    onPointsChanged: requestPaint()
    onLineColorChanged: requestPaint()
    onWidthChanged: requestPaint()
    onHeightChanged: requestPaint()

    onPaint: {
      var ctx = getContext("2d")
      ctx.reset()
      if (points.length < 2) return
      ctx.strokeStyle = lineColor
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.moveTo(points[0].x, points[0].y)
      for (var i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y)
      ctx.stroke()
    }
  }

  // Pin/unpin toggle for the CVE watchlist. Shown on rows that carry a CVE
  // id; hidden entirely (via `visible`, set by the caller) where there's
  // nothing to watch.
  component WatchStar: Text {
    id: watchStar
    property bool watched: false
    signal toggled()

    text: watched ? "★" : "☆"
    color: watched ? root.urgent : root.dim
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption

    MouseArea {
      anchors.fill: parent
      anchors.margins: -Style.space(3)
      cursorShape: Qt.PointingHandCursor
      onClicked: watchStar.toggled()
    }
  }

  component EpssBadge: Rectangle {
    property string epssValue: ""
    visible: root.epssEnabled && epssValue !== ""
    implicitWidth: epssBadgeText.implicitWidth + Style.space(6)
    implicitHeight: epssBadgeText.implicitHeight + Style.space(2)
    radius: Style.space(3)
    color: SentryModel.epssColor(epssValue)
    opacity: 0.9

    Text {
      id: epssBadgeText
      anchors.centerIn: parent
      text: SentryModel.epssLabel(epssValue)
      color: "white"
      font.family: root.fontFamily
      font.pixelSize: Math.max(7, Math.round(Style.font.caption * 0.72))
      font.bold: true
    }
  }

  component ExploitTag: Rectangle {
    property var titles: []
    visible: titles && titles.length > 0
    implicitWidth: exploitTagText.implicitWidth + Style.space(6)
    implicitHeight: exploitTagText.implicitHeight + Style.space(2)
    radius: Style.space(3)
    color: "#e5484d"

    Text {
      id: exploitTagText
      anchors.centerIn: parent
      text: "EXPLOIT"
      color: "white"
      font.family: root.fontFamily
      font.pixelSize: Math.max(7, Math.round(Style.font.caption * 0.72))
      font.bold: true
    }
  }

  component InstalledTag: Rectangle {
    property bool isInstalled: false
    visible: isInstalled
    implicitWidth: installedTagText.implicitWidth + Style.space(6)
    implicitHeight: installedTagText.implicitHeight + Style.space(2)
    radius: Style.space(3)
    color: "#f76b15"

    Text {
      id: installedTagText
      anchors.centerIn: parent
      text: "INSTALLED"
      color: "white"
      font.family: root.fontFamily
      font.pixelSize: Math.max(7, Math.round(Style.font.caption * 0.72))
      font.bold: true
    }
  }

  component ArchRowDelegate: Rectangle {
    required property var modelData
    signal selected()

    implicitHeight: Style.space(62)
    radius: Style.space(5)
    color: archRowArea.containsMouse
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Rectangle {
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.margins: Style.space(4)
      width: 4
      radius: 2
      color: root.severityColor(parent.modelData.severity)
    }

    MouseArea {
      id: archRowArea
      anchors.fill: parent
      hoverEnabled: true
      onClicked: function() { parent.selected() }
    }

    Column {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(1)

      Row {
        width: parent.width
        spacing: Style.space(8)

        Text {
          width: parent.width - archSevLabel.implicitWidth - archEdbTag.implicitWidth - archEpssBadge.implicitWidth - archWatchStar.implicitWidth - Style.space(20)
          elide: Text.ElideRight
          text: modelData.id
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          id: archSevLabel
          anchors.verticalCenter: parent.verticalCenter
          text: modelData.severity
          color: root.severityColor(modelData.severity)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        EpssBadge {
          id: archEpssBadge
          anchors.verticalCenter: parent.verticalCenter
          epssValue: modelData.epss || ""
        }

        ExploitTag {
          id: archEdbTag
          anchors.verticalCenter: parent.verticalCenter
          titles: modelData.exploitTitles || []
        }

        WatchStar {
          id: archWatchStar
          anchors.verticalCenter: parent.verticalCenter
          watched: SentryModel.isWatched(modelData, root.watchlist)
          onToggled: root.toggleWatch(SentryModel.firstCve(modelData))
        }
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.packages
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: {
          var parts = []
          if (modelData.unfixed) parts.push("no fix released")
          else if (modelData.fixed) parts.push("fix " + modelData.fixed)
          if (modelData.typeName) parts.push(modelData.typeName)
          if (modelData.date) parts.push(SentryModel.shortDate(modelData.date))
          return parts.join(" · ")
        }
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component KevRowDelegate: Rectangle {
    required property var modelData
    signal selected()

    implicitHeight: Style.space(62)
    radius: Style.space(5)
    color: kevRowArea.containsMouse
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Rectangle {
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.margins: Style.space(4)
      width: 4
      radius: 2
      color: parent.modelData.ransomware ? root.urgent : (parent.modelData.installed ? "#f76b15" : "#e87a45")
    }

    MouseArea {
      id: kevRowArea
      anchors.fill: parent
      hoverEnabled: true
      onClicked: function() { parent.selected() }
    }

    Column {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(1)

      Row {
        width: parent.width
        spacing: Style.space(6)

        Text {
          width: parent.width - kevRansomLabel.implicitWidth - kevInstalledTag.implicitWidth - kevEpssBadge.implicitWidth - kevEdbTag.implicitWidth - kevWatchStar.implicitWidth - Style.space(16)
          elide: Text.ElideRight
          text: modelData.id
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          id: kevRansomLabel
          anchors.verticalCenter: parent.verticalCenter
          visible: modelData.ransomware
          text: "RANSOM"
          color: root.urgent
          font.family: root.fontFamily
          font.pixelSize: Math.max(7, Math.round(Style.font.caption * 0.78))
          font.bold: true
        }

        InstalledTag {
          id: kevInstalledTag
          anchors.verticalCenter: parent.verticalCenter
          isInstalled: modelData.installed
        }

        EpssBadge {
          id: kevEpssBadge
          anchors.verticalCenter: parent.verticalCenter
          epssValue: modelData.epss || ""
        }

        ExploitTag {
          id: kevEdbTag
          anchors.verticalCenter: parent.verticalCenter
          titles: modelData.exploitTitles || []
        }

        WatchStar {
          id: kevWatchStar
          anchors.verticalCenter: parent.verticalCenter
          watched: SentryModel.isWatched(modelData, root.watchlist)
          onToggled: root.toggleWatch(SentryModel.firstCve(modelData))
        }
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: {
          var parts = []
          if (modelData.vendor) parts.push(modelData.vendor)
          if (modelData.product) parts.push(modelData.product)
          return parts.join(" ") + (modelData.name ? " — " + modelData.name : "")
        }
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: {
          var parts = []
          if (modelData.date) parts.push("added " + SentryModel.shortDate(modelData.date))
          if (modelData.due) parts.push("due " + SentryModel.shortDate(modelData.due))
          return parts.join(" · ")
        }
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component NvdRowDelegate: Rectangle {
    required property var modelData
    signal selected()

    implicitHeight: Style.space(62)
    radius: Style.space(5)
    color: nvdRowArea.containsMouse
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Rectangle {
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.margins: Style.space(4)
      width: 4
      radius: 2
      color: root.severityColor(parent.modelData.severity)
    }

    MouseArea {
      id: nvdRowArea
      anchors.fill: parent
      hoverEnabled: true
      onClicked: function() { parent.selected() }
    }

    Column {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(1)

      Row {
        width: parent.width
        spacing: Style.space(8)

        Text {
          width: parent.width - nvdSevLabel.implicitWidth - nvdScoreLabel.implicitWidth - nvdEpssBadge.implicitWidth - nvdEdbTag.implicitWidth - nvdWatchStar.implicitWidth - Style.space(20)
          elide: Text.ElideRight
          text: modelData.id
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          id: nvdSevLabel
          anchors.verticalCenter: parent.verticalCenter
          text: modelData.severity
          color: root.severityColor(modelData.severity)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        Text {
          id: nvdScoreLabel
          anchors.verticalCenter: parent.verticalCenter
          visible: modelData.score !== null
          text: modelData.score !== null ? String(modelData.score) : ""
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }

        EpssBadge {
          id: nvdEpssBadge
          anchors.verticalCenter: parent.verticalCenter
          epssValue: modelData.epss || ""
        }

        ExploitTag {
          id: nvdEdbTag
          anchors.verticalCenter: parent.verticalCenter
          titles: modelData.exploitTitles || []
        }

        WatchStar {
          id: nvdWatchStar
          anchors.verticalCenter: parent.verticalCenter
          watched: SentryModel.isWatched(modelData, root.watchlist)
          onToggled: root.toggleWatch(SentryModel.firstCve(modelData))
        }
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: (modelData.description || "").slice(0, 100)
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.date ? SentryModel.shortDate(modelData.date) : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component OsvRowDelegate: Rectangle {
    required property var modelData
    signal selected()

    implicitHeight: Style.space(62)
    radius: Style.space(5)
    color: osvRowArea.containsMouse
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Rectangle {
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.margins: Style.space(4)
      width: 4
      radius: 2
      color: root.severityColor(parent.modelData.severity)
    }

    MouseArea {
      id: osvRowArea
      anchors.fill: parent
      hoverEnabled: true
      onClicked: function() { parent.selected() }
    }

    Column {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(1)

      Row {
        width: parent.width
        spacing: Style.space(8)

        Text {
          width: parent.width - osvSevLabel.implicitWidth - osvEpssBadge.implicitWidth - osvEdbTag.implicitWidth - osvWatchStar.implicitWidth - Style.space(16)
          elide: Text.ElideRight
          text: modelData.ecosystem + " · " + modelData.packages + " " + modelData.version
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          id: osvSevLabel
          anchors.verticalCenter: parent.verticalCenter
          text: modelData.severity
          color: root.severityColor(modelData.severity)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        EpssBadge {
          id: osvEpssBadge
          anchors.verticalCenter: parent.verticalCenter
          epssValue: modelData.epss || ""
        }

        ExploitTag {
          id: osvEdbTag
          anchors.verticalCenter: parent.verticalCenter
          titles: modelData.exploitTitles || []
        }

        WatchStar {
          id: osvWatchStar
          anchors.verticalCenter: parent.verticalCenter
          watched: SentryModel.isWatched(modelData, root.watchlist)
          onToggled: root.toggleWatch(SentryModel.firstCve(modelData))
        }
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.id + (modelData.description ? " — " + modelData.description : "")
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component AlertRowDelegate: Rectangle {
    required property var modelData
    signal selected()

    implicitHeight: Style.space(62)
    radius: Style.space(5)
    color: alertRowArea.containsMouse
      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.1)
      : Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Rectangle {
      anchors.top: parent.top
      anchors.bottom: parent.bottom
      anchors.left: parent.left
      anchors.margins: Style.space(4)
      width: 4
      radius: 2
      color: "#0091ff"
    }

    MouseArea {
      id: alertRowArea
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: {
        Qt.openUrlExternally(modelData.link)
      }
    }

    Column {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(1)

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.title || modelData.id
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.link ? modelData.link.replace(/^https?:\/\//, "").slice(0, 60) : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }

      Text {
        width: parent.width
        elide: Text.ElideRight
        text: modelData.date ? SentryModel.timeAgo(modelData.date, Date.now()) : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component AurRowDelegate: Rectangle {
    required property var modelData

    implicitHeight: Style.space(40)
    radius: Style.space(5)
    color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)

    Row {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        width: parent.width - aurVersionLabel.implicitWidth - Style.space(8)
        elide: Text.ElideRight
        text: modelData.name
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
      }

      Text {
        id: aurVersionLabel
        anchors.verticalCenter: parent.verticalCenter
        text: modelData.version
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }
}
