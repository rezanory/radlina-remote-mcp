#!/bin/bash
# Code-only V3 S03 Mac secret importer; run only in later authorized install.
# Existing owner-managed macOS Keychain entries are mandatory. Values never
# travel via CLI arguments or repository files, and are never echoed.
set -euo pipefail
umask 077
[[ $# -eq 1 && "$1" == '--stage' ]]
[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "x86_64" ]]
[[ "$(hostname)" == "amirs-MacBook-Pro.local" ]]
[[ "$(id -un)" == 'amirsheikhzadeh' ]]
STATE="$HOME/.local/share/radlina/v3-beta/macbook-main-s03"
[[ ! -L "$STATE" ]]
mkdir -p -m 700 "$STATE"
chmod 700 "$STATE"
TOKEN="$STATE/s03-writer-token.secret"
HMAC="$STATE/s03-writer-hmac.b64"
if [[ -e "$TOKEN" || -e "$HMAC" ]]; then
  echo 'S03 private writer secrets already staged; refuse overwrite' >&2
  exit 16
fi
# These Keychain entries must be populated separately by the owner before
# installation. If either is missing, abort without generating weaker keys.
# The real S03 daemon uses the existing dedicated V3 owner Keychain,
# NOT the default login Keychain (unavailable to headless LaunchAgents).
# The native importer receives no private values via argv, stdout or env.
# It will fail closed until the legitimate owner has provisioned both items
# into that SAME encrypted Keychain. No credential generation or rotation.
HELPER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/v3-final4-s03-dedicated-keychain-import.swift"
[[ -f "$HELPER" && ! -L "$HELPER" ]]
/usr/bin/swift "$HELPER" --stage
[[ -f "$TOKEN" && -f "$HMAC" && ! -L "$TOKEN" && ! -L "$HMAC" ]]
[[ "$(stat -f '%Lp' "$TOKEN")" == 600 && "$(stat -f '%Lp' "$HMAC")" == 600 ]]
echo "V3_MAC_S03_WRITER_FILES_STAGED token=$TOKEN hmac=$HMAC"
echo 'Keychain values not printed, no service started, no acceptance claimed'
