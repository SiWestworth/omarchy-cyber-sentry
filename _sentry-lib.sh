# Shared security helpers for the cyber.sentry fetch scripts. Sourced only —
# not an entry point, not referenced in manifest.json.
#
# Threat model: ${XDG_RUNTIME_DIR:-/tmp} can fall back to world-writable
# /tmp, so a cache directory or file path can be pre-positioned by another
# local user before this plugin ever runs. These helpers make sure a path is
# actually private and actually a plain file/directory before it's trusted,
# and that temp files can't be guessed ahead of time.

# Fixed, non-varying curl hardening: restrict to https for both the request
# and any redirect target, so a compromised or hijacked feed can't downgrade
# the transfer to a scheme like http:// or file:// via a redirect. Shared
# so every fetch script enforces the same policy instead of repeating it —
# and so a future new fetch script can't forget it.
SENTRY_CURL_HTTPS_ONLY=(--proto '=https' --proto-redir '=https')

# True if $1 is owned by the current effective user.
sentry_owned_by_us() {
  [[ $(stat -c %u "$1" 2>/dev/null) == "$(id -u)" ]]
}

# True if $1 (a directory) protects its children from being renamed/replaced
# by another local user: either it has the sticky bit (like /tmp normally
# does) or it isn't group/other-writable at all (like a systemd-managed
# $XDG_RUNTIME_DIR). Without one of these, a cache dir we've already
# validated could still be swapped out from under us by another UID between
# validation and use.
sentry_parent_is_protected() {
  local mode
  mode=$(stat -c %A "$1" 2>/dev/null) || return 1
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
  mkdir -p "$dir" 2>/dev/null

  [[ -L $dir ]] && { echo "refusing symlinked cache dir: $dir" >&2; return 1; }
  [[ -d $dir ]] || { echo "cache dir is not a directory: $dir" >&2; return 1; }
  sentry_owned_by_us "$dir" ||
    { echo "cache dir not owned by current user: $dir" >&2; return 1; }
  sentry_parent_is_protected "$(dirname -- "$dir")" ||
    { echo "cache dir's parent does not protect against cross-user tampering: $dir" >&2; return 1; }

  chmod 700 "$dir" 2>/dev/null
  return 0
}

# Print the path of a securely-named temp file created in $1 (same
# directory as the eventual cache file, so the caller's `mv -f` stays an
# atomic same-filesystem rename). Random suffix via mktemp — no PID-based
# guessable names.
sentry_mktemp() {
  local dir=$1
  mktemp "$dir/.tmp.XXXXXXXXXX" 2>/dev/null
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
