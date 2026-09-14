# Shared security helpers for the cyber.sentry fetch scripts. Sourced only —
# not an entry point, not referenced in manifest.json.
#
# Threat model: ${XDG_RUNTIME_DIR:-/tmp} can fall back to world-writable
# /tmp, so a cache directory or file path can be pre-positioned by another
# local user before this plugin ever runs. These helpers make sure a path is
# actually private and actually a plain file/directory before it's trusted,
# and that temp files can't be guessed ahead of time.
#
# Every external tool used here and by the fetch scripts that source this
# file is invoked by a hardcoded absolute path, never bare (ambient-PATH)
# lookup. These scripts process and validate automatically-downloaded
# security-feed content; a same-named executable earlier in $PATH (a
# prepended malicious directory, a compromised package installing an
# earlier-resolving wrapper) would run with the user's session privileges
# and could silently defeat every check below. Arch's merged-/usr layout
# means every one of these genuinely lives at /usr/bin — confirmed via
# `command -v` on this target platform, not guessed.
readonly SENTRY_BIN_CURL=/usr/bin/curl
readonly SENTRY_BIN_JQ=/usr/bin/jq
readonly SENTRY_BIN_STAT=/usr/bin/stat
readonly SENTRY_BIN_ID=/usr/bin/id
readonly SENTRY_BIN_MKTEMP=/usr/bin/mktemp
readonly SENTRY_BIN_MKDIR=/usr/bin/mkdir
readonly SENTRY_BIN_CHMOD=/usr/bin/chmod
readonly SENTRY_BIN_DATE=/usr/bin/date
# The one exception: an explicit, distinctly-named test seam (not ambient
# PATH) so the test suite can point arch-fetch at a mock pacman without
# weakening the production default. Defaults to the real absolute path.
# Residual, disclosed tradeoff: an env var is inheritable the same way a
# poisoned PATH is (.bashrc, systemd environment.d, direnv), so this isn't a
# fully closed hole against an attacker who already has code-execution-
# adjacent access to set it — it just can't be triggered as cheaply as
# dropping a file in a writable directory, which is the realistic threat.
readonly SENTRY_BIN_PACMAN="${SENTRY_TEST_PACMAN:-/usr/bin/pacman}"
readonly SENTRY_BIN_VERCMP=/usr/bin/vercmp
readonly SENTRY_BIN_GREP=/usr/bin/grep
readonly SENTRY_BIN_SED=/usr/bin/sed
readonly SENTRY_BIN_CUT=/usr/bin/cut
readonly SENTRY_BIN_TR=/usr/bin/tr
readonly SENTRY_BIN_SORT=/usr/bin/sort
readonly SENTRY_BIN_HEAD=/usr/bin/head
readonly SENTRY_BIN_WC=/usr/bin/wc
readonly SENTRY_BIN_MV=/usr/bin/mv
readonly SENTRY_BIN_RM=/usr/bin/rm
readonly SENTRY_BIN_CAT=/usr/bin/cat
readonly SENTRY_BIN_PASTE=/usr/bin/paste
readonly SENTRY_BIN_XMLSTARLET=/usr/bin/xmlstarlet
readonly SENTRY_BIN_XMLLINT=/usr/bin/xmllint
readonly SENTRY_BIN_SLEEP=/usr/bin/sleep
readonly SENTRY_BIN_TPUT=/usr/bin/tput
readonly SENTRY_BIN_TIMEOUT=/usr/bin/timeout

# Fixed, non-varying curl hardening: restrict to https for both the request
# and any redirect target, so a compromised or hijacked feed can't downgrade
# the transfer to a scheme like http:// or file:// via a redirect. Shared
# so every fetch script enforces the same policy instead of repeating it —
# and so a future new fetch script can't forget it.
SENTRY_CURL_HTTPS_ONLY=(--proto '=https' --proto-redir '=https')

# Finds the first usable path for an optional dev-ecosystem tool (pip, npm,
# cargo, go). Unlike pacman/curl/jq — which always live at one trusted system
# path — these commonly live under the user's own home directory (rustup's
# ~/.cargo/bin, pip's ~/.local/bin), so there's no single correct absolute
# path to hardcode. Still never resolves via ambient $PATH: $1 is a test-only
# override (empty in production), and every other arg is a fixed, literal
# candidate path. Prints the first one that exists and is executable: return
# 1 with no output if none match, so the caller can skip that ecosystem.
sentry_find_optional_bin() {
  local test_path=$1; shift
  if [[ -n $test_path ]]; then
    [[ -x $test_path ]] && { printf '%s' "$test_path"; return 0; }
    return 1
  fi
  local candidate
  for candidate in "$@"; do
    [[ -x $candidate ]] && { printf '%s' "$candidate"; return 0; }
  done
  return 1
}

# True if $1 is owned by the current effective user.
sentry_owned_by_us() {
  [[ $("$SENTRY_BIN_STAT" -c %u "$1" 2>/dev/null) == "$("$SENTRY_BIN_ID" -u)" ]]
}

# True if $1 (a directory) protects its children from being renamed/replaced
# by another local user: either it has the sticky bit (like /tmp normally
# does) or it isn't group/other-writable at all (like a systemd-managed
# $XDG_RUNTIME_DIR). Without one of these, a cache dir we've already
# validated could still be swapped out from under us by another UID between
# validation and use.
sentry_parent_is_protected() {
  local mode
  mode=$("$SENTRY_BIN_STAT" -c %A "$1" 2>/dev/null) || return 1
  [[ ${mode: -1} == t || ${mode: -1} == T ]] && return 0
  [[ ${mode:5:1} == - && ${mode:8:1} == - ]] && return 0
  return 1
}

# Create (if needed) and validate that $1 is safe to use as a private cache
# directory: not a symlink, a real directory, owned by us, and sitting in a
# parent that itself can't be tampered with by another user. Only chmod's it
# to 0700 after all of that is confirmed — never stat/chmod a path before
# ruling out a symlink there, or the check itself becomes the vulnerability.
sentry_prepare_cache_dir() {
  local dir=$1
  "$SENTRY_BIN_MKDIR" -p "$dir" 2>/dev/null

  [[ -L $dir ]] && { echo "refusing symlinked cache dir: $dir" >&2; return 1; }
  [[ -d $dir ]] || { echo "cache dir is not a directory: $dir" >&2; return 1; }
  sentry_owned_by_us "$dir" ||
    { echo "cache dir not owned by current user: $dir" >&2; return 1; }
  sentry_parent_is_protected "${dir%/*}" ||
    { echo "cache dir's parent does not protect against cross-user tampering: $dir" >&2; return 1; }

  "$SENTRY_BIN_CHMOD" 700 "$dir" 2>/dev/null
  return 0
}

# Print the path of a securely-named temp file created in $1 (same
# directory as the eventual cache file, so the caller's `mv -f` stays an
# atomic same-filesystem rename). Random suffix via mktemp — no PID-based
# guessable names.
sentry_mktemp() {
  local dir=$1
  "$SENTRY_BIN_MKTEMP" "$dir/.tmp.XXXXXXXXXX" 2>/dev/null
}

# Validate that $1 is safe to read and parse: exists, is a regular file, is
# not a symlink, and is owned by us.
sentry_safe_regular_file() {
  local path=$1
  [[ -e $path ]] || return 1
  [[ -L $path ]] && return 1
  [[ -f $path ]] || return 1
  sentry_owned_by_us "$path" || return 1
  return 0
}
