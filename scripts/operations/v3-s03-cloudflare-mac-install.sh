#!/bin/bash
# Independent Mac V3 S03 Cloudflare ingress (source only, not executed here).
# Requires existing remote-managed Tunnel, DNS route, private token and binary.
set -euo pipefail
umask 077
[[ "$#" == 1 && "$1" == '--install' ]]
[[ "$(uname -s)" == 'Darwin' && "$(uname -m)" == 'x86_64' ]]
[[ "$(hostname)" == 'amirs-MacBook-Pro.local' ]]
[[ "$(id -un)" == 'amirsheikhzadeh' ]]
: "$RADLINA_V3_S03_CLOUDFLARE_TOKEN_FILE"
: "$RADLINA_V3_S03_CLOUDFLARED_BIN"
: "$RADLINA_V3_S03_TUNNEL_ID"
[[ "$RADLINA_V3_S03_TUNNEL_ID" =~ ^[0-9a-f-]{36}$ ]]
TOKEN="$RADLINA_V3_S03_CLOUDFLARE_TOKEN_FILE"
BIN="$RADLINA_V3_S03_CLOUDFLARED_BIN"
[[ -f "$TOKEN" && ! -L "$TOKEN" && "$(stat -f '%Lp' "$TOKEN")" == '600' ]]
[[ -x "$BIN" ]]
LAUNCH="$HOME/Library/LaunchAgents"
mkdir -p -m 700 "$LAUNCH"
LABEL='com.radlina.remote-mcp.v3.mac-s03-cloudflare'
PLIST="$LAUNCH/$LABEL.plist"
[[ ! -e "$PLIST" ]] || { echo 'Existing V3 S03 tunnel LaunchAgent cannot be overwritten' >&2; exit 16; }
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
BIN_XML="$(esc "$BIN")"
TOKEN_XML="$(esc "$TOKEN")"
BASE_XML="$(esc "$HOME/.local/share/radlina/v3-beta/macbook-main-s03")"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>Label</key><string>$LABEL</string>
 <key>ProgramArguments</key><array>
  <string>$BIN_XML</string>
  <string>tunnel</string>
  <string>--no-autoupdate</string>
  <string>run</string>
  <string>--token-file</string>
  <string>$TOKEN_XML</string>
 </array>
 <key>RunAtLoad</key><true/>
 <key>KeepAlive</key><true/>
 <key>ProcessType</key><string>Background</string>
 <key>StandardOutPath</key><string>$BASE_XML/cloudflare-out.log</string>
 <key>StandardErrorPath</key><string>$BASE_XML/cloudflare-err.log</string>
</dict></plist>
EOF
chmod 600 "$PLIST"
DOMAIN="gui/$(id -u)"
if ! launchctl print "$DOMAIN" >/dev/null 2>&1; then DOMAIN="user/$(id -u)"; fi
launchctl bootstrap "$DOMAIN" "$PLIST"
echo 'V3_INDEPENDENT_MAC_S03_CLOUDFLARE_TUNNEL_INSTALLED'
echo 'Required private Cloudflare ingress: v3-audit.radlina.com -> http://127.0.0.1:7444'
