#!/bin/bash
# P08 owner-authorized installation entrypoint. Source only; not run in this turn.
# Per-user headless launchd heartbeat; no inbound sockets and no remote shell.
set -euo pipefail
umask 077
PINNED_SHA='de625477bbbc60d37adcc690c082df53fe5e6d6f'
LABEL='com.radlina.remote-mcp.v3.mac-heartbeat'
[[ "$(uname -s)" == 'Darwin' && "$(uname -m)" == 'x86_64' ]]
[[ "$(hostname)" == 'amirs-MacBook-Pro.local' ]]
[[ "$(id -un)" == 'amirsheikhzadeh' ]]
[[ "$(node --version)" == 'v24.20.0' ]]
[[ "$1" == '--install' && "$#" -eq 1 ]]
STATE="$HOME/.local/share/radlina/v3-beta/macbook-main-agent"
SOURCE="$STATE/signer-$PINNED_SHA"
LAUNCH_DIR="$HOME/Library/LaunchAgents"
PLIST="$LAUNCH_DIR/$LABEL.plist"
SCRIPT_IN_REPO="$(cd "$(dirname "$0")" && pwd)/v3-mac-heartbeat-sender.ts"
NODE="$(command -v node)"
[[ -f "$SCRIPT_IN_REPO" && -x "$NODE" ]]
if [[ -L "$STATE" || -L "$SOURCE" ]]; then
  echo 'P08: symbolic links are not permitted' >&2; exit 15
fi
mkdir -p -m 700 "$STATE" "$LAUNCH_DIR" "$STATE/receipts"
chmod 700 "$STATE" "$STATE/receipts"
[[ "$(stat -f '%Lp' "$STATE")" == '700' ]]
if [[ -e "$PLIST" || -e "$STATE/v3-mac-heartbeat-sender.ts" ]]; then
  echo 'P08: existing agent not overwritten; reconcile manually' >&2; exit 16
fi
if [[ ! -e "$SOURCE" ]]; then
  git clone --no-checkout --filter=blob:none --branch fix/v3-p08-headless-identity-20261011 \
    'https://github.com/rezanory/radlina-remote-mcp.git' "$SOURCE"
  git -C "$SOURCE" fetch --quiet --no-tags origin "$PINNED_SHA"
  git -C "$SOURCE" checkout --quiet --detach "$PINNED_SHA"
fi
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$PINNED_SHA" ]]
[[ -f "$SOURCE/scripts/enrollment/v3-p08-headless-identity.ts" ]]
chmod 700 "$SOURCE"
if [[ ! -e "$SOURCE/node_modules/tsx/dist/cli.mjs" ]]; then
  (cd "$SOURCE"; npm ci --ignore-scripts --no-fund)
fi
cp -n "$SCRIPT_IN_REPO" "$STATE/v3-mac-heartbeat-sender.ts"
chmod 600 "$STATE/v3-mac-heartbeat-sender.ts"
xml_escape() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
NODE_XML="$(xml_escape "$NODE")"
STATE_XML="$(xml_escape "$STATE")"
SOURCE_XML="$(xml_escape "$SOURCE")"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>Label</key><string>$LABEL</string>
 <key>ProgramArguments</key><array>
  <string>$NODE_XML</string>
  <string>$SOURCE_XML/node_modules/tsx/dist/cli.mjs</string>
  <string>$STATE_XML/v3-mac-heartbeat-sender.ts</string>
 </array>
 <key>EnvironmentVariables</key><dict>
  <key>RADLINA_V3_MAC_AGENT_SOURCE_SHA</key><string>$PINNED_SHA</string>
 </dict>
 <key>RunAtLoad</key><true/>
 <key>StartInterval</key><integer>45</integer>
 <key>KeepAlive</key><false/>
 <key>ProcessType</key><string>Background</string>
 <key>StandardOutPath</key><string>$STATE_XML/launchd-out.log</string>
 <key>StandardErrorPath</key><string>$STATE_XML/launchd-err.log</string>
</dict></plist>
EOF
chmod 600 "$PLIST"
DOMAIN="gui/$(id -u)"
if ! launchctl print "$DOMAIN" >/dev/null 2>&1; then
  DOMAIN="user/$(id -u)"
fi
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "P08_LAUNCHAGENT_INSTALLED domain=$DOMAIN label=$LABEL source_sha=$PINNED_SHA"
