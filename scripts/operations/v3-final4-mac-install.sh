#!/bin/bash
# Radlina V3 final-four physical Mac installer; not invoked in code-only phase.
# Installs separately scoped LaunchAgents, never changes V2 or Tailscale settings.
set -euo pipefail
umask 077
[[ "$#" == 1 && ( "$1" == "--install" || "$1" == "--install-i01" ) ]]
# I01 can be installed independently. Never activate F01 Fleet as a side effect
# of the earlier cross-device integration gate.
INSTALL_MODE="$1"
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "x86_64" ]]
[[ "$(hostname)" == "amirs-MacBook-Pro.local" ]]
[[ "$(id -un)" == "amirsheikhzadeh" ]]
[[ "$(node --version)" == "v24.20.0" ]]
: "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
: "$RADLINA_V3_MAC_OPERATOR_POLICY_PATH"
: "$RADLINA_V3_S03_WITNESS_POLICY_PATH"
: "$RADLINA_V3_S03_WITNESS_POLICY_SHA256"
: "$RADLINA_V3_S03_WRITER_TOKEN_FILE"
: "$RADLINA_V3_S03_HMAC_KEY_FILE"
: "$RADLINA_V3_S03_EXPECTED_WITNESS_KEY_FINGERPRINT"
[[ "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$RADLINA_V3_S03_WITNESS_POLICY_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$RADLINA_V3_S03_EXPECTED_WITNESS_KEY_FINGERPRINT" =~ ^[a-f0-9]{64}$ ]]
BASE="$HOME/.local/share/radlina/v3-beta/macbook-main-agent"
RELEASE="$BASE/releases/$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
LAUNCH="$HOME/Library/LaunchAgents"
NODE="$(command -v node)"
TSX="$RELEASE/node_modules/tsx/dist/cli.mjs"
POLICY="$RADLINA_V3_MAC_OPERATOR_POLICY_PATH"
S03POLICY="$RADLINA_V3_S03_WITNESS_POLICY_PATH"
TOKEN="$RADLINA_V3_S03_WRITER_TOKEN_FILE"
HMAC="$RADLINA_V3_S03_HMAC_KEY_FILE"
[[ -d "$RELEASE" && ! -L "$RELEASE" && -f "$TSX" ]]
# Verify EVERY release artifact before touching staged credentials or creating
# any LaunchAgent. A correct manifest SHA alone does not prove that a file in
# the already-staged release directory has not changed since initial staging.
VERIFIER="$RELEASE/scripts/operations/verify-release.mjs"
[[ -f "$VERIFIER" && ! -L "$VERIFIER" ]]
node "$VERIFIER" "$RELEASE" "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
echo 'V3_MAC_I01_FULL_NATIVE_RELEASE_PREINSTALL_VERIFIED'
# Only explicitly pre-provisioned owner Keychain credentials may stage missing files.
# Never generate, log or embed S03 secrets into LaunchAgent XML.
if [[ ! -f "$TOKEN" || ! -f "$HMAC" ]]; then
  [[ "${RADLINA_V3_S03_ALLOW_KEYCHAIN_STAGE:-0}" == '1' ]]
  [[ -f "$RELEASE/scripts/operations/v3-final4-s03-mac-secret-stage.sh" ]]
  bash "$RELEASE/scripts/operations/v3-final4-s03-mac-secret-stage.sh" --stage
fi
for file in "$POLICY" "$S03POLICY" "$TOKEN" "$HMAC"; do
  [[ -f "$file" && ! -L "$file" && "$(stat -f '%Lp' "$file")" == '600' ]]
done
MANIFEST="$RELEASE/RELEASE_MANIFEST.json"
[[ -f "$MANIFEST" && ! -L "$MANIFEST" ]]
[[ "$(shasum -a 256 "$MANIFEST" | awk '{print $1}')" == "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256" ]]
REQUIRED_SCRIPTS=(v3-mac-operator-cycle.ts v3-s03-mac-witness-daemon.ts)
if [[ "$INSTALL_MODE" == "--install" ]]; then
  REQUIRED_SCRIPTS+=(v3-mac-fleet-cycle.ts)
fi
for script in "${REQUIRED_SCRIPTS[@]}"; do
  [[ -f "$RELEASE/scripts/operations/$script" ]]
done
mkdir -p -m 700 "$BASE" "$BASE/receipts" "$LAUNCH"
chmod 700 "$BASE" "$BASE/receipts"
if [[ "$INSTALL_MODE" == "--install" ]]; then
  mkdir -p -m 700 "$BASE/fleet"
  chmod 700 "$BASE/fleet"
fi
# P08 is a separate signed-health LaunchAgent, always installed before work agents.
# Existing P08 is preserved rather than overwritten or re-enrolled.
P08_LABEL='com.radlina.remote-mcp.v3.mac-heartbeat'
P08_PLIST="$LAUNCH/$P08_LABEL.plist"
if [[ -L "$P08_PLIST" ]]; then
  echo 'V3 P08 LaunchAgent symlink refused' >&2; exit 16
fi
if [[ ! -f "$P08_PLIST" ]]; then
  [[ -f "$RELEASE/scripts/operations/v3-mac-launchagent-install.sh" ]]
  [[ -f "$RELEASE/scripts/operations/v3-mac-heartbeat-sender.ts" ]]
  bash "$RELEASE/scripts/operations/v3-mac-launchagent-install.sh" --install
else
  # A valid plist may remain after a macOS user-session restart even though
  # launchctl no longer has a registered job. Restore only its pinned owner
  # identity, without overwriting the plist or touching S03 credentials.
  P08_RECOVERY="$RELEASE/scripts/operations/v3-p08-mac-reconcile-existing.sh"
  [[ -f "$P08_RECOVERY" && ! -L "$P08_RECOVERY" ]]
  bash "$P08_RECOVERY" --reconcile-existing
fi

esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
NODE_XML="$(esc "$NODE")"
TSX_XML="$(esc "$TSX")"
RELEASE_XML="$(esc "$RELEASE")"
BASE_XML="$(esc "$BASE")"
POLICY_XML="$(esc "$POLICY")"
S03_POLICY_XML="$(esc "$S03POLICY")"
TOKEN_XML="$(esc "$TOKEN")"
HMAC_XML="$(esc "$HMAC")"
install_agent() {
 local label="$1" script="$2" seconds="$3" fleet="$4" witness="$5"
 local out="$LAUNCH/$label.plist"
 local script_xml="$(esc "$RELEASE/scripts/operations/$script")"
 if [[ -e "$out" ]]; then
   echo "V3 existing LaunchAgent must be reconciled; no overwrite: $label" >&2
   exit 16
 fi
 cat > "$out" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>Label</key><string>$label</string>
 <key>ProgramArguments</key><array>
  <string>$NODE_XML</string><string>$TSX_XML</string><string>$script_xml</string>
 </array>
 <key>EnvironmentVariables</key><dict>
  <key>RADLINA_V3_RELEASE_ROOT</key><string>$RELEASE_XML</string>
  <key>RADLINA_V3_MAC_OPERATOR_POLICY_PATH</key><string>$POLICY_XML</string>
EOF
 if [[ "$fleet" == '1' ]]; then
   echo '  <key>RADLINA_V3_FLEET_SUPERVISOR</key><string>1</string>' >> "$out"
 fi
 if [[ "$witness" == '1' ]]; then
 cat >> "$out" <<EOF
  <key>RADLINA_V3_S03_WITNESS_MODE</key><string>isolated-macos</string>
  <key>RADLINA_V3_S03_WITNESS_POLICY_PATH</key><string>$S03_POLICY_XML</string>
  <key>RADLINA_V3_S03_WITNESS_POLICY_SHA256</key><string>$RADLINA_V3_S03_WITNESS_POLICY_SHA256</string>
  <key>RADLINA_V3_S03_WRITER_TOKEN_FILE</key><string>$TOKEN_XML</string>
  <key>RADLINA_V3_S03_HMAC_KEY_FILE</key><string>$HMAC_XML</string>
  <key>RADLINA_V3_S03_EXPECTED_WITNESS_KEY_FINGERPRINT</key><string>$RADLINA_V3_S03_EXPECTED_WITNESS_KEY_FINGERPRINT</string>
EOF
 fi
 cat >> "$out" <<EOF
 </dict>
 <key>RunAtLoad</key><true/>
 <key>ProcessType</key><string>Background</string>
 <key>StandardOutPath</key><string>$BASE_XML/$label.out.log</string>
 <key>StandardErrorPath</key><string>$BASE_XML/$label.err.log</string>
EOF
 if [[ "$witness" == '1' ]]; then
   echo ' <key>KeepAlive</key><true/>' >> "$out"
 else
   echo " <key>StartInterval</key><integer>$seconds</integer>" >> "$out"
   echo ' <key>KeepAlive</key><false/>' >> "$out"
 fi
 echo '</dict></plist>' >> "$out"
 chmod 600 "$out"
}
I01_LABELS=(com.radlina.remote-mcp.v3.mac-s03-witness com.radlina.remote-mcp.v3.mac-operator)
AGENT_LABELS=("${I01_LABELS[@]}")
if [[ "$INSTALL_MODE" == "--install" ]]; then
  AGENT_LABELS+=(com.radlina.remote-mcp.v3.mac-fleet-agent)
fi
# Fail closed before creating ANY new I01 LaunchAgent, including on a rerun.
for label in "${AGENT_LABELS[@]}"; do
  [[ ! -e "$LAUNCH/$label.plist" && ! -L "$LAUNCH/$label.plist" ]] || {
    echo "V3 LaunchAgent already exists; reconcile explicitly: $label" >&2; exit 16;
  }
done
# The independent S03 listener must be started BEFORE the command operator.
install_agent 'com.radlina.remote-mcp.v3.mac-s03-witness' \
  'v3-s03-mac-witness-daemon.ts' 0 0 1
install_agent 'com.radlina.remote-mcp.v3.mac-operator' \
  'v3-mac-operator-cycle.ts' 15 0 0
if [[ "$INSTALL_MODE" == "--install" ]]; then
  install_agent 'com.radlina.remote-mcp.v3.mac-fleet-agent' \
    'v3-mac-fleet-cycle.ts' 45 1 0
fi
DOMAIN="gui/$(id -u)"
if ! launchctl print "$DOMAIN" >/dev/null 2>&1; then DOMAIN="user/$(id -u)"; fi
for label in "${AGENT_LABELS[@]}"; do
  launchctl bootstrap "$DOMAIN" "$LAUNCH/$label.plist"
done
if [[ "$INSTALL_MODE" == "--install-i01" ]]; then
  echo "V3_MAC_I01_AGENTS_INSTALLED_FLEET_UNTOUCHED $RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
else
  echo "V3_MAC_FINAL4_AGENTS_INSTALLED $RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"
fi
echo "Source installed; acceptance still requires later authorized real-world tests."
