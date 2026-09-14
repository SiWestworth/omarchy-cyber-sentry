# Cyber Sentry Security Audit

Two audit rounds so far: an automated security-testing skill pack against
the original codebase, and a manual line-by-line pass after this session's
feature additions (OSV, GHSA, needrestart, Trivy, and the QML process/URL
handling that went with them) roughly tripled the attack surface. Findings
from both rounds are kept below in the order they were found.

## Round 2 — manual audit

**Target:** omarchy-cyber-sentry
**Baseline:** `ceffa9d`
**Date:** 2026-09-14

A manual read of all 12 bash scripts (`_sentry-lib.sh` + 11 fetch scripts),
Panel.qml's subprocess and URL-handling code, and SentryModel.js — prompted
by the amount of new subprocess-spawning and network-parsing code this
session added, none of which had a dedicated second pass looking
specifically for injection or trust-boundary issues. No tooling/skill pack
run this round — direct code reading plus live verification of every fix.

| | |
|---|---|
| Confirmed & fixed | 3 |
| Found & fixed (functional, not security) | 1 |
| Checked, clean | 2 |

### 🟡 Unvalidated URL scheme opened on a single click — Confirmed · fixed

**Where:** `Panel.qml`, Alerts tab row `onClicked`

Every Alerts-tab row called `Qt.openUrlExternally(modelData.link)` with no
check that `link` was actually `http(s)://`. `link` comes straight from the
NCSC-NL RSS feed's `<link>` element (network-sourced, `alerts-fetch`). A
compromised or hijacked feed could serve a custom URI scheme — a
registered app handler, `file://`, etc. — and one click would hand it to
the OS's default handler unchecked.

**Fix:** only call `openUrlExternally` when `modelData.link` matches
`^https?://`. Committed and pushed to `origin/main` (`3ca6034`).

### 🟡 Notification sender resolved via ambient `$PATH` — Confirmed · fixed

**Where:** `Panel.qml`, `sendNotification()`

`notificationProcess.command` invoked `"omarchy-notification-send"` with no
absolute path — the one place in the codebase that didn't follow the
hardened-path rule `_sentry-lib.sh` documents and every fetch script
applies to curl/jq/pacman (a poisoned `$PATH` entry runs with the user's
session privileges). Worse than the click-gated finding above because it
fires unattended on every alert.

**Fix:** hardcoded to the confirmed real path, `/usr/bin/omarchy-notification-send`.
Committed and pushed to `origin/main` (`3ca6034`).

### 🟢 Same ambient-`$PATH` gap for the optional `flatpak` check — Confirmed · fixed

**Where:** `Panel.qml`, `flatpakProcess.command`

`/bin/sh -c "command -v flatpak ... && flatpak list ... || true"` resolved
both the existence check and the actual invocation via ambient `$PATH`,
inconsistent with the `sentry_find_optional_bin()` fixed-candidate-path
pattern already used for pip/npm/cargo/go in `osv-fetch`. Lower severity
than the notification finding — runs once at startup, output is only
displayed — but same root cause.

**Fix:** both the `test -x` check and the invocation now use the fixed
`/usr/bin/flatpak` path. Verified live: with flatpak genuinely absent on
the test machine, the Foreign tab still correctly reports its AUR-only
count with no Process errors in the Quickshell log. Committed and pushed
to `origin/main` (`3ca6034`).

### ⚙️ Notifications silently failing to send — Found & fixed (functional, not security)

**Where:** `Panel.qml`, `sendNotification()`

Found while manually verifying the fix above: this build of
`omarchy-notification-send` has no `-a` flag (only `--app-name`), and the
call passed both. Confirmed directly — running the real command with `-a`
present eats the following arguments and exits 1; without it, exit 0. This
means every desktop notification (new-advisory alerts, KEV alerts, the
weekly digest) has been silently failing to send since the plugin's first
commit. Not a vulnerability, but found during this pass and fixed in the
same place. Committed and pushed to `origin/main` (`ed33bf4`).

### 🟢 Clipboard/fix-command shell construction — Checked · clean

**Check:** `copyToClipboard()` and the CVE-detail "Run in terminal" action

Both build a shell command string from data and looked worth tracing
closely. `copyToClipboard` uses the framework's `Util.shellQuote()` (correct
single-quote escaping — verified by reading its implementation, not
assumed) before interpolating arbitrary CVE-description text pulled from
NVD/GHSA/OSV. The "Run in terminal" fix action only ever operates on the
hardcoded literal `"sudo pacman -Syu"` (`SentryModel.archFixState()`) —
never on anything feed-derived — so there's nothing for the quoting to get
wrong in the first place.

### 🟢 Argument injection via enumerated container image names — Checked · clean (defense-in-depth note)

**Check:** `trivy-fetch`'s per-image scan

Locally-enumerated Docker/Podman image names are passed as a single quoted
argv element to `trivy image ... "$img"` — not shell-interpolated, so not
classic injection. Docker/Podman's own tag-naming rules block a leading
`-`, so a flag-injection attempt isn't practically constructible through
normal `docker pull`/`docker build` usage. No fix applied; noted as a
zero-cost hardening opportunity (a `--` separator before the image arg, if
Trivy supports one) rather than a real finding.

## Round 1 — automated skill pack

**Target:** omarchy-cyber-sentry
**Baseline:** `5e8d567`
**Date:** 2026-09-11

A security-testing skill pack run against cyber.sentry itself. 10 of the
skills checked were relevant to its actual attack surface; the rest were
excluded with a stated reason (see "Not applicable" below). Of the 10 run:

| | |
|---|---|
| Confirmed & fixed | 1 |
| Documented, unproven | 1 |
| Checked, clean | 9 |
| Blocked — no tooling | 0 |

### 🔴 Local file disclosure via XXE in the RSS parser — Confirmed · fixed

**Check:** XXE exploitation → `alerts-fetch`

`xmlstarlet sel` resolves local `file://` external entities by default.
`--net` is the only related flag it exposes, and it gates network-fetched
entities only — not local ones. A compromised or hijacked feed could
disclose any file the plugin's user can read into the cached advisory
title, which then renders in the panel and can be sent in a notification.
Proven with a real payload against the exact command the script runs, not
inferred from documentation.

```
$ xmlstarlet sel -t -m "//item" -v "title" -n malicious.xml
Leak: XXE_SECRET_MARKER_12345

— after the fix, same payload served over HTTP through the real fetch path —
$ alerts-fetch --force
{"ok":false,"error":"NCSC-NL advisory feed is unavailable or unparseable"}
✓ no cache file written · no leak · live feed (25 advisories) unaffected
```

**Fix:** reject any downloaded feed containing a `DOCTYPE` before it ever
reaches xmllint/xmlstarlet — a legitimate RSS feed never declares one.
Committed and pushed to `origin/main` (`5e8d567`).

### 🟡 Redirects are restricted to HTTPS, not to a specific host — Documented · unproven

**Check:** SSRF exploitation → all 7 fetch scripts

`curl -fsSL` follows redirects, restricted only to `https://` — not to the
origin host. `arch-fetch` genuinely needs this (its endpoint issues a
legitimate same-host 308). If an upstream host were ever compromised or
DNS-hijacked, it could theoretically redirect to an internal target
instead.

Not fixed: this can't be ethically demonstrated without compromising a
real third-party host, and the mitigation (validate the final request host
after each fetch) adds real complexity for a threat that requires the
legitimate upstream to already be compromised. Documented as a
recommendation rather than a proven finding.

### 🟢 Command injection via CVE-id argument — Checked · clean

**Check:** injection fuzzing → `cve-fetch`, `epss-fetch`, `exploitdb-fetch`

19 shell-metacharacter and command-injection payloads (`; && || |` backtick
substitution, `$(…)`, newline injection, path traversal) against all 3
scripts that take a CVE id argument — 57 invocations total, with a canary
file embedded in each payload.

```
$ ls FUZZ_CANARY
No such file or directory
✓ canary never created — no injection occurred across any payload
```

### 🟢 Hardcoded secrets or credentials — Checked · clean

**Check:** secret-pattern scan → full repo

Keyword scan hits every file, as expected for a CVE/security tool — "key",
"token", "CVE" appear legitimately throughout. A targeted scan for actual
credential-*shaped values* (AWS keys, PEM headers, `key/token/secret = "…"`
assignments) found nothing — only `manifest.json`'s own JSON schema field
literally named `"key"`.

### 🟢 Unsafe deserialization — Checked · clean

**Check:** deserialization exploitation → `JSON.parse`, `new Function()`

`JSON.parse` can only ever produce plain data — no attacker-chosen types or
constructors, structurally unlike pickle/Java-serialization/unsafe YAML.
The test harness's `new Function()` module loader executes only the
plugin's own source file from a fixed local path, never network or
attacker-controlled content.

### 🟢 SSRF via attacker-controlled input — Checked · clean

**Check:** SSRF exploitation → URL construction

Every request host is a fixed constant. The only external input reaching a
URL at all (a CVE id) is regex-validated to `CVE-[0-9]+-[0-9]+` — a
character set that cannot contain scheme, host, or authority-breaking
characters, closing off every classic bypass. Day-count inputs are
transformed through `date` into a machine-generated timestamp before ever
reaching a URL.

### 🟢 Local privilege escalation via one-click remediation — Checked · clean

**Check:** Linux privilege escalation → `sudo pacman -Syu` action

Re-read the live code directly rather than from memory: the executed
command is a hardcoded string literal. Feed-derived data (affected
packages, fixed version) lands in structurally separate display-only
fields, never concatenated into it. `Util.shellQuote()` wraps the command
before it reaches the terminal-launch shell context regardless of that
guarantee.

### 🟢 Local storage / thick-client exposure — Checked · clean

**Check:** thick-client testing → local config & state files

Settings, watchlist, notification state, and trend history are plain JSON
at `0644` (umask default, not world-writable) — fine, since the content is
confirmed non-secret. Most thick-client concerns don't transfer here: no
two/three-tier backend to leak credentials for, no native binary to
DLL-hijack, no client-only authorization check to bypass.

### 🟢 General SAST — Semgrep — Checked · 1 false positive

**Check:** Semgrep static analysis → full repo

Baseline (`p/security-audit`, `p/secrets`) + `p/javascript` + the Trail of
Bits third-party ruleset, important-only mode. 1 finding:
`curl-unencrypted-url` flagged in `_sentry-lib.sh` — read the actual lines
and it's a comment documenting the HTTPS-only hardening
(`--proto '=https'`), not a real unencrypted curl call. No code change
needed.

### 🟢 General SAST — CodeQL — Checked · clean

**Check:** CodeQL static analysis → `SentryModel.js`

Scoped to `SentryModel.js` — CodeQL has no bash or QML extractor. Its
`.pragma library` directive (QML syntax, not valid JS) broke extraction on
the first attempt; fixed by scanning a sanitized copy with just that line
stripped, the same technique the test suite's own module loader already
uses. Ran the official `javascript-queries` pack, 126 queries,
important-only mode. 0 findings — verified genuine (not a broken scan) via
a clean database-quality check, a verified non-zero query suite, and
successful invocation metadata against the right file.

### Coverage — every skill checked

| Skill | Relevant | Result |
|---|---|---|
| Semgrep static analysis | Yes | 1 finding, false positive |
| CodeQL static analysis | Yes | Clean (0 findings, verified genuine) |
| SARIF parsing | Only as a follow-up to the above | Not needed — both scans resolved directly |
| Secret-pattern scan | Yes | Clean |
| Injection fuzzing | Yes | Clean (57 payloads) |
| XXE exploitation | Yes | Vulnerability found & fixed |
| SSRF exploitation | Yes | Clean, one documented residual |
| Deserialization exploitation | Yes | Clean |
| Thick-client testing | Yes | Clean |
| Linux privilege escalation | Yes | Clean |

### Not applicable (checked, not run)

**No login / auth / uploads**
Password/username/webshell/payload-focused checks

**No LLM component**
LLM-specific testing

**Not our own code's threat model**
Malware-detection signature authoring

**Zero blockchain / smart-contract code**
Smart-contract vulnerability scanners

**No matching attack surface**
Checks tied to Active Directory, cloud infrastructure,
GraphQL/gRPC/JWT/OAuth/SAML/Kerberos, mobile apps, wireless/BLE, hardware,
ICS/OT, containers, serverless, social engineering & recon, or generic
web-app pentesting (no web server exists here to test) — plus CI/CD OIDC
abuse, ruled out directly: no `.github/workflows` exist in this repo.
