#!/usr/bin/env bash
# Applies the detection rules ArcRadar committed to the rules repository onto this Wazuh Manager.
#
# ArcRadar never reaches into this host: it only commits rule files (rules/arcradar_<id>.xml) to a
# Git repository. This script, run here on the Manager, pulls that repository and installs the files
# as custom rules. It only ever changes files named arcradar_<id>.xml in the rules directory, checks
# every file before installing anything, tests the whole ruleset with Wazuh itself, and puts the
# previous files back if that test fails. Wazuh is restarted only when something changed.
#
# Usage (as root):  arcradar-apply-rules            apply if the repository changed
#                   arcradar-apply-rules --check    show what would change, install nothing
#
# Settings (environment variables, all optional):
#   ARCRADAR_RULES_REPO    Git URL of the rules repository  (default: https://github.com/aqsin1337/wazuh_rules.git)
#   ARCRADAR_RULES_BRANCH  branch to follow                 (default: main)
#   ARCRADAR_RULES_DIR     where the clone is kept          (default: /var/lib/arcradar-rules)
#   WAZUH_RULES_DIR        the Manager's custom rules dir   (default: /var/ossec/etc/rules)
set -euo pipefail

REPO_URL="${ARCRADAR_RULES_REPO:-https://github.com/aqsin1337/wazuh_rules.git}"
BRANCH="${ARCRADAR_RULES_BRANCH:-main}"
WORK="${ARCRADAR_RULES_DIR:-/var/lib/arcradar-rules}"
RULES_DIR="${WAZUH_RULES_DIR:-/var/ossec/etc/rules}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { printf '%s arcradar-rules: %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v git >/dev/null || die "git is not installed"
[ -d "$RULES_DIR" ] || die "$RULES_DIR does not exist (is this a Wazuh Manager?)"

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
SRC="$WORK/repo/rules"
mapfile -t FILES < <(find "$SRC" -maxdepth 1 -type f -name 'arcradar_*.xml' 2>/dev/null | sort)
for file in "${FILES[@]}"; do
  base="$(basename "$file")"
  [[ "$base" =~ ^arcradar_([0-9]{6})\.xml$ ]] || die "$base: unexpected file name"
  id="${BASH_REMATCH[1]}"
  # ArcRadar renders only detection elements. Anything that can act on the host is refused outright.
  if grep -Eqi '<(active-response|command|ossec_config|integration|localfile|global|remote|rootcheck|syscheck)\b' "$file"; then
    die "$base: contains an element ArcRadar never generates"
  fi
  grep -q "<rule id=\"$id\"" "$file" || die "$base: rule id does not match the file name"
  [ "$(grep -c '<rule ' "$file")" -eq 1 ] || die "$base: expected exactly one rule"
  if command -v xmllint >/dev/null; then xmllint --noout "$file" 2>/dev/null || die "$base: not well-formed XML"; fi
done

# 3. Compare with what is installed.
mapfile -t INSTALLED < <(find "$RULES_DIR" -maxdepth 1 -type f -name 'arcradar_*.xml' 2>/dev/null | sort)
CHANGED=0
for file in "${FILES[@]}"; do
  target="$RULES_DIR/$(basename "$file")"
  if [ ! -f "$target" ] || ! cmp -s "$file" "$target"; then CHANGED=1; log "would install $(basename "$file")"; fi
done
for target in "${INSTALLED[@]}"; do
  [ -f "$SRC/$(basename "$target")" ] || { CHANGED=1; log "would remove $(basename "$target")"; }
done

if [ "$CHANGED" -eq 0 ]; then log "up to date (repository commit $COMMIT, ${#FILES[@]} rule file(s))"; exit 0; fi
if [ "$CHECK_ONLY" -eq 1 ]; then log "changes pending (repository commit $COMMIT); nothing installed (--check)"; exit 0; fi

# 4. Install, keeping a copy of the previous files.
BACKUP="$WORK/backup/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP"
for target in "${INSTALLED[@]}"; do cp -p "$target" "$BACKUP/"; done
for target in "${INSTALLED[@]}"; do [ -f "$SRC/$(basename "$target")" ] || rm -f "$target"; done
for file in "${FILES[@]}"; do
  install -o root -g wazuh -m 0660 "$file" "$RULES_DIR/$(basename "$file")"
done

restore() {
  log "restoring the previous rule files"
  find "$RULES_DIR" -maxdepth 1 -type f -name 'arcradar_*.xml' -delete
  for old in "$BACKUP"/arcradar_*.xml; do
    [ -f "$old" ] && install -o root -g wazuh -m 0660 "$old" "$RULES_DIR/$(basename "$old")"
  done
}

# 5. Let Wazuh itself test the whole ruleset before it is restarted.
if ! /var/ossec/bin/wazuh-analysisd -t >"$WORK/last-test.log" 2>&1; then
  tail -n 5 "$WORK/last-test.log" >&2 || true
  restore
  die "Wazuh rejected the ruleset; nothing was changed (details: $WORK/last-test.log)"
fi

systemctl restart wazuh-manager || { restore; systemctl restart wazuh-manager || true; die "wazuh-manager did not restart"; }
log "applied repository commit $COMMIT: ${#FILES[@]} rule file(s) installed, wazuh-manager restarted"
