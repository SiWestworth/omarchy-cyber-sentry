// SentryModel.js — pure-data layer for cyber.sentry.
//
// Takes the JSON emitted by the bash fetchers and turns it into rows the
// panel can render, plus the filtering/sorting/format helpers the panel
// needs. No QML or Quickshell imports: keep it testable.
//
// Sources: arch-fetch, kev-fetch, epss-fetch, exploitdb-fetch, nvd-fetch,
//          alerts-fetch, osv-fetch

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

// True if this row's primary CVE has been dismissed ("I've assessed this
// and don't need to see it again"). Unlike the watchlist, dismissal isn't
// threshold-scoped — a dismissed row is hidden from every tab it could
// appear in, not just System/Recent/Dev.
function isDismissed(row, dismissedList) {
  if (!dismissedList || dismissedList.length === 0) return false
  var cve = firstCve(row)
  return !!cve && dismissedList.indexOf(cve) >= 0
}

// Drops dismissed rows entirely, independent of severity threshold or
// watchlist status — dismissing is a stronger, more specific signal than
// "always show me this," so it takes precedence if a CVE is somehow both.
function filterOutDismissed(rows, dismissedList) {
  if (!dismissedList || dismissedList.length === 0) return rows
  return rows.filter(function(r) { return !isDismissed(r, dismissedList) })
}

// Free-text filter shared by every tab, including the plain {name, version}
// objects the AUR tab uses (not a "row" at all). Deliberately defensive
// about field presence rather than switching on row.type, since each
// source's row shape carries a different subset of these fields (a KEV row
// has vendor/product/name, an arch row has packages, an OSV row has
// ecosystem, etc.) — checking whichever exist is simpler and safer than
// keeping a type-to-fields map in sync as new sources get added.
var SEARCH_FIELDS = ["id", "packages", "description", "vendor", "product", "name", "title", "ecosystem", "version"]

function matchesSearch(row, query) {
  var q = String(query || "").trim().toLowerCase()
  if (!q || !row) return true
  for (var i = 0; i < SEARCH_FIELDS.length; i++) {
    var v = row[SEARCH_FIELDS[i]]
    if (v && String(v).toLowerCase().indexOf(q) >= 0) return true
  }
  return false
}

function filterBySearch(rows, query) {
  var q = String(query || "").trim()
  if (!q) return rows
  return rows.filter(function(r) { return matchesSearch(r, q) })
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

// GHSA advisory. Field-shape-compatible with nvdRow() on purpose so both
// can share the same row delegate in the Recent tab. The ecosystem/package
// (and a "+N more" suffix when an advisory affects several packages) is
// folded into the description text rather than a new UI field, to avoid
// touching the shared delegate for a merged-in source.
function ghsaRow(g) {
  var pkgTag = g.package
    ? "[" + (g.ecosystem || "?") + " · " + g.package + (g.packageCount > 1 ? " +" + (g.packageCount - 1) + " more" : "") + "] "
    : ""
  return {
    type: "ghsa",
    id: String(g.id || g.cve_id || ""),
    severity: String(g.severity || "").toUpperCase(),
    packages: String(g.package || ""),
    fixed: "",
    unfixed: false,
    cves: g.cve_id ? [String(g.cve_id)] : [],
    date: String(g.published || ""),
    reference: "",
    description: pkgTag + String(g.summary || ""),
    score: (g.score !== undefined && g.score !== null) ? g.score : null,
    vector: "",
    references: g.references || []
  }
}

// Combine NVD and GHSA recent-advisory rows into one feed, dropping a GHSA
// entry whose CVE already has an NVD row — NVD is the "official" record for
// a CVE that both sources happen to cover, so it's kept and the GHSA
// duplicate is dropped rather than showing the same CVE twice. GHSA entries
// with no CVE (or a CVE NVD hasn't picked up) always pass through — that's
// exactly the coverage GHSA adds that NVD alone doesn't have.
function mergeNvdAndGhsa(nvdRowsList, ghsaRowsList) {
  var nvdCves = {}
  for (var i = 0; i < nvdRowsList.length; i++) {
    var cve = firstCve(nvdRowsList[i])
    if (cve) nvdCves[cve] = true
  }
  var extraGhsa = ghsaRowsList.filter(function(r) {
    var cve = firstCve(r)
    return !cve || !nvdCves[cve]
  })
  return nvdRowsList.concat(extraGhsa)
}

// OSV.dev finding for a globally-installed pip/npm/cargo/go package. Unlike
// the KEV/NVD rows, the description/severity/references are already fully
// populated by osv-fetch itself (no on-demand cve.org lookup needed) since
// OSV's /v1/query returns full vulnerability details in one round trip.
function osvRow(o) {
  return {
    type: "osv",
    id: String(o.id || ""),
    severity: String(o.severity || ""),
    packages: String(o.package || ""),
    fixed: "",
    unfixed: false,
    cves: (o.aliases && o.aliases.length > 0) ? o.aliases : [],
    date: "",
    reference: "",
    ecosystem: String(o.ecosystem || ""),
    version: String(o.version || ""),
    description: String(o.summary || ""),
    references: o.references || []
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

function buildRows(archParsed, kevParsed, nvdParsed, alertsParsed, osvParsed, ghsaParsed) {
  var rows = []
  var archList = archParsed && archParsed.advisories ? archParsed.advisories : []
  for (var i = 0; i < archList.length; i++) rows.push(archRow(archList[i]))
  var kevList = kevParsed && kevParsed.vulnerabilities ? kevParsed.vulnerabilities : []
  for (var j = 0; j < kevList.length; j++) rows.push(kevRow(kevList[j]))
  var nvdList = nvdParsed && nvdParsed.cves ? nvdParsed.cves : []
  for (var k = 0; k < nvdList.length; k++) rows.push(nvdRow(nvdList[k]))
  var alertList = alertsParsed && alertsParsed.advisories ? alertsParsed.advisories : []
  for (var l = 0; l < alertList.length; l++) rows.push(alertRow(alertList[l]))
  var osvList = osvParsed && osvParsed.findings ? osvParsed.findings : []
  for (var m = 0; m < osvList.length; m++) rows.push(osvRow(osvList[m]))
  var ghsaList = ghsaParsed && ghsaParsed.advisories ? ghsaParsed.advisories : []
  for (var n = 0; n < ghsaList.length; n++) rows.push(ghsaRow(ghsaList[n]))
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

function ghsaRows(rows) {
  return rows.filter(function(r) { return r.type === "ghsa" })
}

function osvRows(rows) {
  return rows.filter(function(r) { return r.type === "osv" })
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

// Headline for the System tab: of the currently-visible affected Arch
// packages, how many are already cleared by one `sudo pacman -Syu` (a
// released fix exists) versus still open (no fix yet, or unfixed/vulnerable
// with no released version). Same "always a full-system update" rule as
// archFixState — this only counts, it never composes a different command.
function fixableSummary(rows) {
  var archOnly = rows.filter(function(r) { return r && r.type === "arch" })
  var fixable = archOnly.filter(function(r) { return !r.unfixed && r.fixed }).length
  return { fixable: fixable, total: archOnly.length }
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
