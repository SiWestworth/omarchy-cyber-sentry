# Cyber Sentry

A [Quickshell](https://quickshell.outfoxxed.me/) / [Omarchy](https://omarchy.org/) bar widget that answers the one question every developer asks after reading a headline about a CVE: **does this affect my machine?**

It correlates live security data against the packages actually installed on this machine (`pacman -Q`) and shows you what matters — not noise.

## What it watches

| Source | What it tells you |
|---|---|
| **Arch Security Tracker** | Advisories for your installed packages — only those with a version *below* the fixed version, or with no fix released yet. Stale/"past vulnerable" entries that no longer apply are silently excluded. |
| **CISA KEV** | Every vulnerability the U.S. government's CISA knows is being actively exploited in the wild, updated as new entries are added. Cross-checked against your installed packages with a fuzzy vendor/product match. |
| **NVD (recent)** | Recently published High/Critical CVEs from the National Vulnerability Database's REST API. |
| **EPSS** | Exploit-probability scores enriching every CVE-bearing row, so you can tell "technically vulnerable" from "actually likely to be exploited." |
| **ExploitDB** | Flags rows that have a known public exploit on file. |
| **NCSC-NL Alerts** | Vendor security advisories from the Dutch National Cyber Security Centre. |
| **cve.org** | On-demand detail lookup: click any row to pull the full CVE description, severity score, and references. |

## AUR / foreign-package coverage

Arch Security Tracker only tracks official `[core]`/`[extra]` repo packages — it
has no per-package/per-version correlation for anything installed from the AUR
or another foreign repo. Cyber Sentry surfaces that gap explicitly with a
dedicated **AUR** tab listing every foreign package installed (`pacman -Qm`), so
you know exactly which packages fall outside the Arch tracker's precise
coverage rather than assuming they're silently "clean." These packages are
never counted toward the affected-package badge — they're not detected
threats, just uncovered ones.

## One-click remediation

When an Arch Security Tracker advisory has a released fix, its CVE detail view
shows the affected package(s), the fixed version, and a ready-to-run
`sudo pacman -Syu` command with **Copy** and **Run in terminal** buttons. The
command is always a full system update, never a per-package install — Arch
doesn't support safely upgrading a single package in isolation from a stale
sync state — and nothing ever runs without you explicitly clicking it; "Run in
terminal" opens a floating terminal so you confirm and enter your own `sudo`
password interactively.

## Install

```
omarchy plugin add https://github.com/SiWestworth/omarchy-cyber-sentry.git --enable
```

Reload the shell (`Ctrl+Shift+R` in Hyprland) and the shield icon appears in your bar.

Alternatively, clone or copy this repo's contents directly into
`~/.config/omarchy/plugins/cyber.sentry` and run
`omarchy plugin enable cyber.sentry right`.

## Uninstall

```
omarchy plugin remove cyber.sentry
```

This disables the widget and removes the plugin folder. It does not delete
your saved settings or notification history under
`~/.local/state/omarchy/settings/` — remove those manually if you want a
completely clean uninstall.

## How it works

- **Every 30 minutes** (configurable) the fetch scripts run. They are plain Bash — no Python, no Node, no network dependencies beyond `curl` and `jq`.
- The correlation logic runs in the bash script itself, not in QML or JavaScript. This keeps the panel lightweight and the logic auditable.
- `vercmp` (from `pacman`) handles Arch's epoch and pkgrel conventions correctly.
- The panel renders rows sorted by severity (highest first) in the System tab, by date added (newest first) in the Exploited/Recent/Alerts tabs, and alphabetically in the AUR tab.

## Settings

Open the Omarchy settings UI and configure these under the **Cyber Sentry** section:

| Setting | Default | What it does |
|---|---|---|
| Poll interval (minutes) | 30 | How often feeds are re-fetched |
| Lowest severity shown | Medium | Threshold for badge count and notifications |
| Watch Arch advisories | on | Toggle the Arch Security Tracker feed |
| Watch KEV catalog | on | Toggle the CISA KEV feed |
| Watch NVD recent CVEs | on | Toggle the NVD recent-CVE feed |
| Watch NCSC-NL alerts | on | Toggle the vendor-advisory feed |
| Show EPSS scores | on | Toggle exploit-probability scores on CVE-bearing rows |
| Check ExploitDB | on | Toggle the public-exploit lookup |
| Notify on affected | on | Desktop notification when a new advisory affects an installed package |
| Notify on KEV | on | Desktop notification when a new KEV entry is added |
| Notify on NVD | off | Desktop notification on new High/Critical NVD CVEs |
| Notify on alerts | off | Desktop notification on new vendor advisories |
| Cooldown (minutes) | 60 | Minimum time before re-notifying about the same item |
| Max list rows | 50 | Rows per tab (scroll if more) |
| Show badge | on | Show the red affected-count badge on the bar icon |
| Include KEV in badge | off | Whether the badge count also includes KEV entries |
| KEV recent window (days) | 90 | How far back the KEV tab looks |
| KEV: installed only | off | KEV tab shows only entries matching installed packages |

## Keyboard shortcuts (while panel is open)

| Key | Action |
|---|---|
| `r` | Force refresh |
| `p` | Pause / resume the scheduler |
| `1` | Switch to System tab |
| `2` | Switch to Exploited tab |
| `3` | Switch to Recent (NVD) tab |
| `4` | Switch to Alerts tab |
| `5` | Switch to AUR tab |
| `q` | Close CVE detail overlay (if open) |
| `Esc` | Close the panel |

## Notification state

Notification history is persisted at `~/.local/state/omarchy/settings/cyber-sentry-state.json` so that a shell reload doesn't re-fire alerts for items already seen.

## Requirements

- `pacman` (Arch Linux)
- `jq` (JSON processing)
- `curl` (feed fetching)
- A Nerd Font (for the shield and status glyphs on the bar)

## Testing

```
cd tests && ./run-tests.sh
```

Runs unit tests for every fetch script and the `SentryModel.js` data layer
against fixtures and a mocked `pacman`, plus live checks against `cve.org`,
EPSS, and ExploitDB when reachable.

## License

MIT
