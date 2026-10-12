#!/bin/bash
# Owner-initiated V3-only Mac operator/fleet/witness LaunchAgent upgrade.
# Source only. No automatic rollback on a native unknown outcome; never touches V2.
set -euo pipefail
umask 077
[[ $# == 1 && "$1" == '--upgrade' ]]
[[ "$(uname -s)" == 'Darwin' && "$(hostname)" == 'amirs-MacBook-Pro.local' ]]
[[ "$(id -un)" == 'amirsheikhzadeh' ]]
: "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
: "$RADLINA_V3_FINAL4_MAC_PREVIOUS_SHA256"
NEXT="$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
PREV="$RADLINA_V3_FINAL4_MAC_PREVIOUS_SHA256"
[[ "$NEXT" =~ ^[a-f0-9]{64}$ && "$PREV" =~ ^[a-f0-9]{64}$ && "$NEXT" != "$PREV" ]]
BASE="$HOME/.local/share/radlina/v3-beta/macbook-main-agent"
RELEASES="$BASE/releases"
OLD="$RELEASES/$PREV"
NEW="$RELEASES/$NEXT"
for dir in "$BASE" "$OLD" "$NEW" "$HOME/Library/LaunchAgents"; do
  [[ -d "$dir" && ! -L "$dir" ]]
done
for id in "$PREV" "$NEXT"; do
  manifest="$RELEASES/$id/RELEASE_MANIFEST.json"
  [[ -f "$manifest" && ! -L "$manifest" ]]
  [[ "$(shasum -a 256 "$manifest" | awk '{print $1}')" == "$id" ]]
done
for script in v3-mac-operator-cycle.ts v3-mac-fleet-cycle.ts v3-s03-mac-witness-daemon.ts; do
  [[ -f "$NEW/scripts/operations/$script" ]]
done
[[ -f "$NEW/node_modules/tsx/dist/cli.mjs" ]]
LABELS='com.radlina.remote-mcp.v3.mac-operator com.radlina.remote-mcp.v3.mac-fleet-agent com.radlina.remote-mcp.v3.mac-s03-witness'
LAUNCH="$HOME/Library/LaunchAgents"
STATE="$BASE/release-upgrades"
mkdir -p -m 700 "$STATE"
chmod 700 "$STATE"
[[ ! -L "$STATE" ]]
# Never repeat a partially applied migration without independent reconciliation.
for oldstate in "$STATE"/*/state; do
  [[ ! -f "$oldstate" ]] && continue
  [[ "$(cat "$oldstate")" == 'native-start-returned' ]] ||
    { echo 'Unreconciled V3 Mac LaunchAgent upgrade exists' >&2; exit 19; }
done
ID="$(/usr/bin/uuidgen)"
SESSION="$STATE/$ID"
mkdir -m 700 "$SESSION"
printf '%s' 'prepared' > "$SESSION/state"
# Preflight all exact version pointers and stage all copies before stopping.
for label in $LABELS; do
  plist="$LAUNCH/$label.plist"
  [[ -f "$plist" && ! -L "$plist" && "$(stat -f '%Lp' "$plist")" == '600' ]]
  /usr/bin/grep -Fq "<string>$label</string>" "$plist"
  refs="$(/usr/bin/grep -oE '/releases/[a-f0-9]{64}' "$plist" | wc -l | tr -d ' ')"
  [[ "$refs" == '3' ]]
  [[ "$(/usr/bin/grep -oE '/releases/[a-f0-9]{64}' "$plist" | sort -u)" == "/releases/$PREV" ]]
  /bin/cp -p "$plist" "$SESSION/$label.plist.before"
  /usr/bin/sed "s|/releases/$PREV|/releases/$NEXT|g" "$plist" > "$SESSION/$label.plist.next"
  chmod 600 "$SESSION/$label.plist.next"
  refs_new="$(/usr/bin/grep -oE '/releases/[a-f0-9]{64}' "$SESSION/$label.plist.next" | wc -l | tr -d ' ')"
  [[ "$refs_new" == '3' ]]
  [[ "$(/usr/bin/grep -oE '/releases/[a-f0-9]{64}' "$SESSION/$label.plist.next" | sort -u)" == "/releases/$NEXT" ]]
done
DOMAIN="gui/$(id -u)"
if ! launchctl print "$DOMAIN" >/dev/null 2>&1; then DOMAIN="user/$(id -u)"; fi
printf '%s' 'stopping' > "$SESSION/state"
for label in $LABELS; do
  launchctl bootout "$DOMAIN/$label"
done
printf '%s' 'stopped' > "$SESSION/state"
for label in $LABELS; do
  /bin/mv "$SESSION/$label.plist.next" "$LAUNCH/$label.plist"
done
printf '%s' 'pointers-replaced' > "$SESSION/state"
for label in $LABELS; do
  launchctl bootstrap "$DOMAIN" "$LAUNCH/$label.plist"
done
# A successful launchctl return is not independently verified device health.
printf '%s' 'native-start-returned' > "$SESSION/state"
echo "V3_MAC_RELEASE_UPGRADE_RECORDED id=$ID next=$NEXT acceptance=deferred"
