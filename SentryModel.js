// SentryModel.js — pure-data layer for cyber.sentry.
//
// Takes the JSON emitted by the bash fetchers and turns it into rows the
// panel can render, plus the filtering/sorting/format helpers the panel
// needs. No QML or Quickshell imports: keep it testable.
//
// Sources: arch-fetch, kev-fetch, epss-fetch, exploitdb-fetch, nvd-fetch,
//          alerts-fetch

.pragma library

var SEVERITIES = ["Critical", "High", "Medium", "Low", "Unknown"]

function clamp(value, min, max, fallback) {
  var v = parseFloat(value)
  if (isNaN(v)) return fallback
  return Math.min(max, Math.max(min, v))
}

function severityRank(sev) {
  var s = String(sev || "").toLowerCase()
  if (s.indexOf("critical") >= 0) return 3
  if (s.indexOf("high") >= 0) return 2
  if (s.indexOf("medium") >= 0) return 1
  if (s.indexOf("low") >= 0) return 0
  return -1
}

function severityKey(sev) {
  var r = severityRank(sev)
  if (r >= 3) return "critical"
  if (r === 2) return "high"
  if (r === 1) return "medium"
  if (r === 0) return "low"
  return "unknown"
}

function meetsThreshold(sev, threshold) {
  var t = severityRank(threshold)
  return t < 0 || severityRank(sev) >= t
}

// Single point of truth for "does this row pass the severity threshold" so
// the badge count, the visible lists, and notifications can never disagree.
function filterByThreshold(rows, threshold) {
  return rows.filter(function(r) { return meetsThreshold(r.severity, threshold) })
}

function affectedCount(archParsed, threshold) {
  var list = archParsed && archParsed.advisories ? archParsed.advisories : []
  return filterByThreshold(list, threshold).length
}

// True if this row's primary CVE is in the user's watchlist. Rows with no
// CVE (alerts) are never watchable.
function isWatched(row, watchlist) {
  if (!watchlist || watchlist.length === 0) return false
  var cve = firstCve(row)
  return !!cve && watchlist.indexOf(cve) >= 0
}

// Like filterByThreshold, but a watchlisted row is always kept regardless of
// severity — pinning a CVE means "always show me this," not "show me this
// if it's also otherwise severe enough." Only used for the visible System/
// Recent lists; the badge count and notifications intentionally keep using
// plain filterByThreshold since those are about "what needs attention now."
function filterByThresholdOrWatched(rows, threshold, watchlist) {
  return rows.filter(function(r) {
    return meetsThreshold(r.severity, threshold) || isWatched(r, watchlist)
  })
}

// --- Row builders ----------------------------------------------------------

function archRow(a) {
  return {
    type: "arch",
    id: String(a.name || ""),
    severity: String(a.severity || ""),
    packages: String(a.packages || ""),
    fixed: String(a.fixed || ""),
    unfixed: a.unfixed === true,
    cves: Array.isArray(a.cves) ? a.cves : [],
    date: String(a.date || ""),
    reference: String(a.reference || ""),
    typeName: String(a.type || "")
  }
}

function kevRow(k) {
  return {
    type: "kev",
    id: String(k.cveID || ""),
    severity: "",
    packages: "",
    fixed: "",
    unfixed: false,
    cves: [String(k.cveID || "")],
    date: String(k.dateAdded || ""),
    reference: "",
    vendor: String(k.vendorProject || ""),
    product: String(k.product || ""),
    name: String(k.vulnerabilityName || ""),
    description: String(k.shortDescription || ""),
    action: String(k.requiredAction || ""),
    due: String(k.dueDate || ""),
    ransomware: String(k.knownRansomwareCampaignUse || "").toLowerCase() === "known",
    installed: false
  }
}

function nvdRow(a) {
  return {
    type: "nvd",
    id: String(a.id || ""),
    severity: String(a.severity || ""),
    packages: "",
    fixed: "",
    unfixed: false,
    cves: [String(a.id || "")],
    date: String(a.published || ""),
    reference: "",
    description: String(a.description || ""),
    score: a.score !== undefined ? a.score : null,
    vector: String(a.vector || ""),
    references: Array.isArray(a.references) ? a.references : []
  }
}

function alertRow(a) {
  return {
    type: "alert",
    id: String(a.title || "").split(" ")[0] || "",
    severity: "",
    packages: "",
    fixed: "",
    unfixed: false,
    cves: [],
    date: String(a.date || ""),
    reference: String(a.link || ""),
    title: String(a.title || ""),
    link: String(a.link || "")
  }
}

// --- Build combined rows ---------------------------------------------------

function buildRows(archParsed, kevParsed, nvdParsed, alertsParsed) {
  var rows = []
  var archList = archParsed && archParsed.advisories ? archParsed.advisories : []
  for (var i = 0; i < archList.length; i++) rows.push(archRow(archList[i]))
  var kevList = kevParsed && kevParsed.vulnerabilities ? kevParsed.vulnerabilities : []
  for (var j = 0; j < kevList.length; j++) rows.push(kevRow(kevList[j]))
  var nvdList = nvdParsed && nvdParsed.cves ? nvdParsed.cves : []
  for (var k = 0; k < nvdList.length; k++) rows.push(nvdRow(nvdList[k]))
  var alertList = alertsParsed && alertsParsed.advisories ? alertsParsed.advisories : []
  for (var l = 0; l < alertList.length; l++) rows.push(alertRow(alertList[l]))
  return rows
}

// --- Merge enrichment data into rows --------------------------------------

function epssMerge(rows, epssParsed) {
  if (!epssParsed || !epssParsed.scores) return rows
  var scores = epssParsed.scores
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i]
    var first = firstCve(row)
    if (first && scores[first]) {
      row.epss = String(scores[first].epss || "")
      row.epssPercentile = String(scores[first].percentile || "")
    }
  }
  return rows
}

function exploitMerge(rows, exploitdbParsed) {
  if (!exploitdbParsed || !exploitdbParsed.matches) return rows
  var matches = exploitdbParsed.matches
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i]
    var first = firstCve(row)
    if (first && matches[first]) {
      row.exploitTitles = matches[first]
    }
  }
  return rows
}

function installMerge(rows, installedMap) {
  if (!installedMap) return rows
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i]
    if (row.type !== "kev") continue
    row.installed = kevMatchesInstalled(row.vendor, row.product, installedMap)
  }
  return rows
}

// Fuzzy match: check if vendor+product tokens appear in any installed package
// name. Handles cases like vendor="Acme" product="Widget" matching package
// "acme-widget" or just "widget".
function kevMatchesInstalled(vendor, product, installedMap) {
  var v = String(vendor || "").toLowerCase()
  var p = String(product || "").toLowerCase()
  if (!v && !p) return false

  var names = Object.keys(installedMap)
  for (var i = 0; i < names.length; i++) {
    var pkg = String(names[i]).toLowerCase()
    // Direct product match
    if (p && pkg.indexOf(p) >= 0) return true
    // Compound: vendor-product
    if (v && p && pkg.indexOf(v) >= 0 && pkg.indexOf(p) >= 0) return true
    // Vendor-only match for short vendor names (avoid false positives on "a")
    if (v && v.length >= 4 && pkg.indexOf(v) >= 0) return true
  }
  return false
}

// --- Filtering -------------------------------------------------------------

function kevRecentFilter(rows, days) {
  if (!days || days <= 0) return rows
  var cutoff = new Date()
  cutoff.setDate(cutoff.getDate() - days)
  var cutoffStr = cutoff.toISOString().slice(0, 10)
  return rows.filter(function(r) {
    return String(r.date || "") >= cutoffStr
  })
}

function archRows(rows) {
  return rows.filter(function(r) { return r.type === "arch" })
}

function kevRows(rows) {
  return rows.filter(function(r) { return r.type === "kev" })
}

function nvdRows(rows) {
  return rows.filter(function(r) { return r.type === "nvd" })
}

function alertRows(rows) {
  return rows.filter(function(r) { return r.type === "alert" })
}

// --- Sorting ---------------------------------------------------------------

function sortBySeverity(rows) {
  var copy = rows.slice()
  copy.sort(function(x, y) {
    var d = severityRank(y.severity) - severityRank(x.severity)
    if (d !== 0) return d
    return String(y.date).localeCompare(String(x.date))
  })
  return copy
}

function sortByDateDesc(rows) {
  var copy = rows.slice()
  copy.sort(function(x, y) { return String(y.date).localeCompare(String(x.date)) })
  return copy
}

function sortByEpssDesc(rows) {
  var copy = rows.slice()
  copy.sort(function(x, y) {
    var ex = parseFloat(x.epss || "0")
    var ey = parseFloat(y.epss || "0")
    if (ey !== ex) return ey - ex
    return String(y.date).localeCompare(String(x.date))
  })
  return copy
}

function sortByName(rows) {
  var copy = rows.slice()
  copy.sort(function(x, y) { return String(x.name).localeCompare(String(y.name)) })
  return copy
}

// --- Helpers ---------------------------------------------------------------

// Parses `pacman -Q`/`pacman -Qm`-style "name version" lines. Shared by
// installedProcess and aurProcess so the two pacman-output parsers can't
// silently drift apart.
function parsePackageList(text) {
  var out = []
  var lines = String(text || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var parts = lines[i].split(" ")
    if (parts.length >= 2 && parts[0]) out.push({ name: parts[0], version: parts[1] })
  }
  return out
}

function firstCve(row) {
  // Deliberately duck-typed rather than Array.isArray(): rows read back out
  // of a ListView delegate's `modelData` marshal `cves` into a QML sequence
  // type that fails Array.isArray() even though it's a real, indexable,
  // non-empty list — Array.isArray() here silently treated every on-screen
  // row as CVE-less.
  if (row && row.cves && row.cves.length > 0) return String(row.cves[0])
  return ""
}

function hasExploit(row) {
  return !!(row && row.exploitTitles && row.exploitTitles.length > 0)
}

// Remediation is only ever a full-system update (never a per-package install) —
// Arch does not support upgrading one package in isolation from a stale sync
// state without risking a partial-upgrade break. The command is therefore a
// fixed constant; packages/version are for display only, never interpolated
// into a shell command.
function archFixState(row) {
  if (!row || row.type !== "arch" || row.unfixed || !row.fixed) return null
  return { command: "sudo pacman -Syu", packages: row.packages || "", version: row.fixed }
}

function epssColor(epss) {
  var v = parseFloat(epss || "0")
  if (v >= 0.9) return "#e5484d"  // critical red
  if (v >= 0.7) return "#f76b15"  // high orange
  if (v >= 0.4) return "#ffb020"  // medium yellow
  if (v >= 0.1) return "#0091ff"  // low blue
  return ""
}

function epssLabel(epss) {
  var v = parseFloat(epss || "0")
  if (v <= 0) return ""
  return Math.round(v * 100) + "%"
}

// --- Notification helpers --------------------------------------------------

function newNotifiable(rows, notified, now, cooldownMs) {
  var out = []
  for (var i = 0; i < rows.length; i++) {
    var last = notified[rows[i].id] || 0
    if (now - last >= cooldownMs) out.push(rows[i])
  }
  return out
}

function markAllSeen(rows, notified, now) {
  for (var i = 0; i < rows.length; i++) {
    notified[rows[i].id] = now
  }
}

function notificationText(row) {
  if (row.type === "arch") {
    var headline = "Affected: " + row.id + " (" + row.severity + ")"
    var body = row.packages + (row.fixed ? " — fix " + row.fixed : " — no fix released")
    if (row.typeName) body += " · " + row.typeName
    return { headline: headline, body: body }
  }
  if (row.type === "nvd") {
    return {
      headline: "Recent CVE: " + row.id + " (" + row.severity + " " + (row.score || "") + ")",
      body: (row.description || "").slice(0, 120)
    }
  }
  if (row.type === "alert") {
    return {
      headline: "Alert: " + (row.title || row.id),
      body: row.link || ""
    }
  }
  // KEV
  var kevHeadline = "Exploited in the wild: " + row.id
  var kevBody = (row.vendor ? row.vendor + " " : "") + (row.product ? row.product + " — " : "") + row.name
  if (row.ransomware) kevBody += " · ransomware"
  if (row.installed) kevBody += " · INSTALLED"
  return { headline: kevHeadline, body: kevBody }
}

// --- Formatting ------------------------------------------------------------

function timeAgo(iso, now) {
  if (!iso) return ""
  var t = new Date(iso).getTime()
  if (isNaN(t)) return iso
  var sec = Math.max(0, Math.round((now - t) / 1000))
  if (sec < 60) return sec + "s ago"
  var min = Math.round(sec / 60)
  if (min < 60) return min + "m ago"
  var hr = Math.round(min / 60)
  if (hr < 24) return hr + "h ago"
  return Math.round(hr / 24) + "d ago"
}

function shortDate(iso) {
  if (!iso) return ""
  return String(iso).slice(0, 10)
}

// --- State management ------------------------------------------------------

function pruneNotified(notified, maxAgeMs) {
  var now = Date.now()
  var keys = Object.keys(notified)
  for (var i = 0; i < keys.length; i++) {
    if (now - notified[keys[i]] > maxAgeMs) delete notified[keys[i]]
  }
}

function sourceOk(parsed) {
  return parsed ? parsed.ok === true : false
}

function sourceError(parsed) {
  return parsed && parsed.error ? String(parsed.error) : ""
}

function sourceCount(parsed) {
  if (!parsed) return 0
  if (parsed.ok === true) return parsed.count || 0
  return 0
}

function checkedAt(parsed) {
  return parsed && parsed.checkedAt ? String(parsed.checkedAt) : ""
}

// --- Trend history -----------------------------------------------------

// Appends a snapshot point and caps the array length, dropping the oldest
// points first. History is a flat array of {t, badgeCount, kevCount}.
function appendHistoryPoint(history, point, maxPoints) {
  var next = Array.isArray(history) ? history.slice() : []
  next.push(point)
  if (maxPoints > 0 && next.length > maxPoints) next = next.slice(next.length - maxPoints)
  return next
}

// Converts history's badgeCount series into pixel coordinates scaled to fit
// width x height (with padding so the line never touches the edges), for a
// Canvas to stroke as a polyline. A flat (all-equal) series renders as a
// centered horizontal line rather than dividing by zero.
function sparklinePoints(history, width, height, padding) {
  var pts = Array.isArray(history) ? history : []
  if (pts.length === 0) return []
  var values = pts.map(function(p) { return Number(p.badgeCount) || 0 })
  var min = Math.min.apply(null, values)
  var max = Math.max.apply(null, values)
  var pad = padding || 0
  var innerW = Math.max(1, width - pad * 2)
  var innerH = Math.max(1, height - pad * 2)
  var range = max - min
  return values.map(function(v, i) {
    var x = pad + (values.length === 1 ? innerW / 2 : (i / (values.length - 1)) * innerW)
    var y = range === 0 ? pad + innerH / 2 : pad + innerH - ((v - min) / range) * innerH
    return { x: x, y: y }
  })
}

// --- Do-not-disturb ------------------------------------------------------

// "HH:MM" -> minutes since midnight, or null if unparsable so callers can
// fail open (treat as "not in DND") rather than misbehave on a bad setting.
function parseHm(hm) {
  var m = /^(\d{1,2}):(\d{2})$/.exec(String(hm || "").trim())
  if (!m) return null
  var h = parseInt(m[1], 10), mm = parseInt(m[2], 10)
  if (h < 0 || h > 23 || mm < 0 || mm > 59) return null
  return h * 60 + mm
}

// True if `now` falls within the [start, end) window, handling both a
// same-day window and one that spans midnight (e.g. 22:00-07:00).
function isWithinDnd(start, end, now) {
  var s = parseHm(start)
  var e = parseHm(end)
  if (s === null || e === null || s === e) return false
  var nowMinutes = now.getHours() * 60 + now.getMinutes()
  if (s < e) return nowMinutes >= s && nowMinutes < e
  return nowMinutes >= s || nowMinutes < e
}
