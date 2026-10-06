#!/usr/bin/env bash
# Applies the Splunk detection rules ArcRadar committed to the rules repository onto this Splunk server.
#
# ArcRadar never reaches into this host: it only commits rule files (splunk/arcradar_<key>.conf) to a
# Git repository. This script, run here, pulls that repository and installs the saved searches into the
# arcradar_rules app. It checks every file before installing anything (only the keys and the search
# commands ArcRadar itself generates are accepted, so a file edited by hand on GitHub cannot add an
# action or a command that changes anything), asks Splunk to parse the result, and puts the previous
# file back if that fails. Splunk is not restarted: the saved searches are reloaded.
#
# Usage (as root):  arcradar-apply-splunk-rules            apply if the repository changed
#                   arcradar-apply-splunk-rules --check    show what would change, install nothing
#
# Settings (environment variables, all optional):
#   ARCRADAR_RULES_REPO    Git URL of the rules repository   (default: https://github.com/aqsin1337/wazuh_rules.git)
#   ARCRADAR_RULES_BRANCH  branch to follow                  (default: main)
#   ARCRADAR_RULES_DIR     where the clone is kept           (default: /var/lib/arcradar-splunk-rules)
#   SPLUNK_HOME            the Splunk installation           (default: /opt/splunk)
#   SPLUNK_USER            the account Splunk runs as        (default: splunk)
#   ARCRADAR_SPLUNK_AUTH   file holding "user:password" of a Splunk admin, used only to reload the saved
#                          searches                          (default: /etc/arcradar/splunk-admin)
set -euo pipefail

REPO_URL="${ARCRADAR_RULES_REPO:-https://github.com/aqsin1337/wazuh_rules.git}"
BRANCH="${ARCRADAR_RULES_BRANCH:-main}"
WORK="${ARCRADAR_RULES_DIR:-/var/lib/arcradar-splunk-rules}"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_USER="${SPLUNK_USER:-splunk}"
AUTH_FILE="${ARCRADAR_SPLUNK_AUTH:-/etc/arcradar/splunk-admin}"
APP="arcradar_rules"
TARGET="$SPLUNK_HOME/etc/apps/$APP/local/savedsearches.conf"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { printf '%s arcradar-splunk-rules: %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
# One run at a time: the cron job and a manual run (or two slow runs) must not touch the clone together.
exec 9>/var/lock/arcradar-splunk-rules.lock
flock -n 9 || die "another run is in progress"
command -v git >/dev/null || die "git is not installed"
command -v python3 >/dev/null || die "python3 is not installed"
[ -d "$SPLUNK_HOME/etc/apps/$APP" ] || die "the $APP app is not installed in $SPLUNK_HOME/etc/apps"

# 1. Get the repository to exactly what the remote branch holds (a local edit here is discarded).
mkdir -p "$WORK"
if [ ! -d "$WORK/repo/.git" ]; then
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$WORK/repo" || die "could not clone $REPO_URL"
else
  git -C "$WORK/repo" fetch --quiet --depth 1 origin "$BRANCH" || die "could not fetch $REPO_URL"
  git -C "$WORK/repo" reset --quiet --hard "origin/$BRANCH"
fi
COMMIT="$(git -C "$WORK/repo" rev-parse --short HEAD)"

# 2. Check every candidate file before anything is installed.
SRC="$WORK/repo/splunk"
mapfile -t FILES < <(find "$SRC" -maxdepth 1 -type f -name 'arcradar_*.conf' 2>/dev/null | sort)

check_file() {
  python3 - "$1" <<'PY'
import re, sys

path = sys.argv[1]
name = path.rsplit("/", 1)[-1]
m = re.fullmatch(r"arcradar_([A-Za-z0-9_-]{1,60})\.conf", name)
if not m:
    sys.exit("unexpected file name")
key = m.group(1)

ALLOWED_KEYS = {
    "description", "search", "enableSched", "cron_schedule", "dispatch.earliest_time",
    "dispatch.latest_time", "alert_type", "alert_comparator", "alert_threshold", "alert.severity",
    "alert.track", "alert.digest_mode", "alert.suppress", "alert.suppress.period",
    "alert.suppress.fields", "action.arcradar_forward", "action.arcradar_forward.param.rule_key",
    "action.arcradar_forward.param.name", "action.arcradar_forward.param.severity",
    "action.arcradar_forward.param.mitre",
}
# The only shapes a segment of the search can have (the same as assertSafeSplunkConf in ArcRadar). The base
# search has no leading `search` command: Splunk adds it, and a second one would search for the word "search".
FIELD = r"[A-Za-z_][A-Za-z0-9_.]{0,79}"
BASE_SHAPE = re.compile(r"index=[a-z0-9_][a-z0-9_-]{0,59}( sourcetype=[A-Za-z0-9_:./-]{1,80})?")
STEP_SHAPES = [
    re.compile(r'regex %s="(?:[^"\\]|\\.)*"' % FIELD),
    re.compile(r"stats count( by %s(, %s){0,2})?" % (FIELD, FIELD)),
    re.compile(r"where count >= [0-9]{1,4}"),
]


def split_pipeline(text):
    """Splits on | outside quoted strings (a backslash escapes the next character inside one)."""
    segments, current, quoted, i = [], "", False, 0
    while i < len(text):
        ch = text[i]
        if quoted:
            current += ch
            if ch == "\\":
                current += text[i + 1] if i + 1 < len(text) else ""
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            current += ch
        elif ch == "|":
            segments.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    segments.append(current.strip())
    return segments


stanzas = 0
with open(path, encoding="utf-8") as handle:
    data = handle.read()
if "\r" in data or "\x00" in data:
    sys.exit("carriage returns or NUL characters are not allowed")
for line in data.split("\n"):
    if line == "" or line.startswith("# "):
        continue
    if line.startswith("["):
        if line != "[arcradar_%s]" % key:
            sys.exit("unexpected stanza %r" % line[:60])
        stanzas += 1
        continue
    parts = re.fullmatch(r"([A-Za-z0-9_.]+) = (.*)", line)
    if not parts or parts.group(1) not in ALLOWED_KEYS:
        sys.exit("unexpected setting %r" % line.split(" = ")[0][:60])
    if parts.group(2).endswith("\\"):
        sys.exit("a setting cannot end with a backslash")
    if parts.group(1) == "search":
        first, *rest = split_pipeline(parts.group(2))
        if not BASE_SHAPE.fullmatch(first):
            sys.exit("the search must start with index=<name>")
        for segment in rest:
            if not any(shape.fullmatch(segment) for shape in STEP_SHAPES):
                command = segment.split(None, 1)[0] if segment else ""
                sys.exit("command %r is not allowed in a rule" % command)
if stanzas != 1:
    sys.exit("a rule file has exactly one stanza")
PY
}

for file in "${FILES[@]}"; do
  reason="$(check_file "$file" 2>&1)" || die "$(basename "$file"): $reason"
done

# 3. Build what the app's local/savedsearches.conf should hold, and compare.
NEW="$WORK/savedsearches.conf.new"
{
  echo "# Generated by arcradar-apply-splunk-rules from repository commit $COMMIT. Do not edit: change the rule in ArcRadar."
  for file in "${FILES[@]}"; do echo; grep -v '^# ArcRadar rule' "$file" | sed '/^$/d'; done
} >"$NEW"
# The header names the commit; compare the rules only.
strip() { grep -v '^# Generated by' "$1" 2>/dev/null || true; }
if [ -f "$TARGET" ] && [ "$(strip "$NEW")" = "$(strip "$TARGET")" ]; then
  log "up to date (repository commit $COMMIT, ${#FILES[@]} rule file(s))"
  exit 0
fi
if [ "$CHECK_ONLY" -eq 1 ]; then log "changes pending (repository commit $COMMIT); nothing installed (--check)"; exit 0; fi

# 4. Install, keeping a copy of the previous file.
BACKUP="$WORK/backup/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP" "$(dirname "$TARGET")"
[ -f "$TARGET" ] && cp -p "$TARGET" "$BACKUP/savedsearches.conf"
install -o "$SPLUNK_USER" -g "$SPLUNK_USER" -m 0640 "$NEW" "$TARGET"

restore() {
  log "restoring the previous saved searches"
  if [ -f "$BACKUP/savedsearches.conf" ]; then
    install -o "$SPLUNK_USER" -g "$SPLUNK_USER" -m 0640 "$BACKUP/savedsearches.conf" "$TARGET"
  else
    rm -f "$TARGET"
  fi
}

# 5. Let Splunk itself parse the app's saved searches before they are loaded.
if ! sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" btool savedsearches list --app="$APP" >"$WORK/last-test.log" 2>&1; then
  tail -n 5 "$WORK/last-test.log" >&2 || true
  restore
  die "Splunk could not parse the saved searches; nothing was changed (details: $WORK/last-test.log)"
fi

# 6. Reload them (no restart). Needs a Splunk admin login kept in a root-only file.
if [ -r "$AUTH_FILE" ]; then
  if ! sudo -u "$SPLUNK_USER" "$SPLUNK_HOME/bin/splunk" _internal call "/servicesNS/nobody/$APP/saved/searches/_reload" -auth "$(cat "$AUTH_FILE")" >"$WORK/last-reload.log" 2>&1; then
    tail -n 5 "$WORK/last-reload.log" >&2 || true
    restore
    die "Splunk did not reload the saved searches; the previous file was put back (details: $WORK/last-reload.log)"
  fi
  log "applied repository commit $COMMIT: ${#FILES[@]} rule file(s), saved searches reloaded"
else
  log "applied repository commit $COMMIT: ${#FILES[@]} rule file(s); no $AUTH_FILE, so Splunk will pick them up on its next refresh or restart"
fi

# 7. New or changed rules: measure them against past data right away, in the background (backtest), so the result
#    is in ArcRadar within a minute or two of the push instead of at the next scheduled run. The lock is not
#    passed on to it.
if [ -x /usr/local/sbin/arcradar-splunk-sync ]; then
  ( /usr/local/sbin/arcradar-splunk-sync --backtests >>/var/log/arcradar-splunk-sync.log 2>&1 || true ) 9>&- &
fi
