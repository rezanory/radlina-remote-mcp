#!/bin/bash
# Restore an existing owner-pinned V3 P08 LaunchAgent after a macOS user-session
# restart. This is independent of S03/F01 secrets, Cloudflare and Tailscale.
# It never creates/replaces a plist or accesses V2.
set -euo pipefail
umask 077
[[ $# -eq 1 && "$1" == "--reconcile-existing" ]] || exit 64
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "x86_64" ]]
[[ "$(hostname)" == "amirs-MacBook-Pro.local" ]]
[[ "$(id -un)" == "amirsheikhzadeh" ]]
readonly SHA='de625477bbbc60d37adcc690c082df53fe5e6d6f'
readonly LABEL='com.radlina.remote-mcp.v3.mac-heartbeat'
readonly STATE="$HOME/.local/share/radlina/v3-beta/macbook-main-agent"
readonly PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
readonly TSX="$STATE/signer-$SHA/node_modules/tsx/dist/cli.mjs"
readonly SENDER="$STATE/v3-mac-heartbeat-sender.ts"
[[ -f "$PLIST" && ! -L "$PLIST" && "$(stat -f '%Lp' "$PLIST")" == '600' ]]
[[ -f "$TSX" && ! -L "$TSX" && -f "$SENDER" && ! -L "$SENDER" ]]
[[ ! -L "$STATE" ]]
/usr/bin/plutil -lint "$PLIST" >/dev/null
read_property() { /usr/libexec/PlistBuddy -c "Print :$1" "$PLIST"; }
[[ "$(read_property Label)" == "$LABEL" ]]
[[ "$(read_property ProgramArguments:1)" == "$TSX" ]]
[[ "$(read_property ProgramArguments:2)" == "$SENDER" ]]
[[ "$(read_property EnvironmentVariables:RADLINA_V3_MAC_AGENT_SOURCE_SHA)" == "$SHA" ]]
readonly USER_ID="$(id -u)"
for domain in "gui/$USER_ID" "user/$USER_ID"; do
  if /bin/launchctl print "$domain/$LABEL" >/dev/null 2>&1; then
    echo "V3_P08_EXISTING_AGENT_ALREADY_REGISTERED domain=$domain"
    exit 0
  fi
done
domain="gui/$USER_ID"
/bin/launchctl print "$domain" >/dev/null 2>&1 || domain="user/$USER_ID"
/bin/launchctl bootstrap "$domain" "$PLIST"
/bin/launchctl print "$domain/$LABEL" >/dev/null
echo "V3_P08_EXISTING_AGENT_REREGISTERED domain=$domain"
echo "Registration only; signed heartbeat ingress and I01 acceptance require independent live receipts"
