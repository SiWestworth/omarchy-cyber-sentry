# Cyber Sentry Security Audit

**Target:** omarchy-cyber-sentry
**Baseline:** `5e8d567`
**Date:** 2026-09-11

Results of running a security-testing skill pack against cyber.sentry
itself — an Omarchy threat-intel bar widget that fetches and parses
external CVE/KEV/advisory feeds. 10 of the skills checked were relevant to
its actual attack surface; the rest were excluded with a stated reason. Of
the 10 run:

| | |
|---|---|
| Confirmed & fixed | 1 |
| Documented, unproven | 1 |
| Checked, clean | 9 |
| Blocked — no tooling | 0 |

## Findings

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

## Coverage — every skill checked

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

## Not applicable (checked, not run)

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
