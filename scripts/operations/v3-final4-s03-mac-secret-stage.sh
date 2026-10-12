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
TOKEN_VALUE="$(/usr/bin/security find-generic-password -w \
  -s 'com.radlina.remote-mcp.v3.s03-writer-token' -a 'amirsheikhzadeh')"
HMAC_VALUE="$(/usr/bin/security find-generic-password -w \
  -s 'com.radlina.remote-mcp.v3.s03-writer-hmac-base64' -a 'amirsheikhzadeh')"
[[ "$(printf '%s' "$TOKEN_VALUE" | wc -c | tr -d ' ')" -ge 32 ]]
[[ "$(printf '%s' "$TOKEN_VALUE" | wc -c | tr -d ' ')" -le 512 ]]
[[ "$TOKEN_VALUE" != *$'\n'* && "$TOKEN_VALUE" != *' '* ]]
[[ "$HMAC_VALUE" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
[[ "$(printf '%s' "$HMAC_VALUE" | wc -c | tr -d ' ')" -ge 44 ]]
[[ "$(printf '%s' "$HMAC_VALUE" | wc -c | tr -d ' ')" -le 172 ]]
TMP_TOKEN="$TOKEN.tmp.$$"
TMP_HMAC="$HMAC.tmp.$$"
trap 'rm -f "$TMP_TOKEN" "$TMP_HMAC"' EXIT
( umask 077; printf '%s' "$TOKEN_VALUE" > "$TMP_TOKEN" )
( umask 077; printf '%s' "$HMAC_VALUE" > "$TMP_HMAC" )
chmod 600 "$TMP_TOKEN" "$TMP_HMAC"
mv -n "$TMP_TOKEN" "$TOKEN"
mv -n "$TMP_HMAC" "$HMAC"
unset TOKEN_VALUE HMAC_VALUE
echo "V3_MAC_S03_WRITER_FILES_STAGED token=$TOKEN hmac=$HMAC"
echo 'Keychain values not printed, no service started, no acceptance claimed'
