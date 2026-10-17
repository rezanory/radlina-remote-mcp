#!/bin/bash
# Read-only PRE-INSTALL preflight for the physical V3 I01 Mac path.
# Reads only public metadata, existence, permissions and LaunchAgent state.
# Never reads credential contents, queries Keychain, installs, signs, starts,
# stops or changes any service. In particular it never touches V2.
set -euo pipefail
[[ $# -eq 1 && "$1" == "--check-i01" ]] || {
  echo 'Usage: v3-final4-mac-i01-readiness.sh --check-i01' >&2
  exit 64
}

missing=()
add() { missing+=("$1"); }
private_metadata() {
  local file="$1"
  [[ -f "$file" && ! -L "$file" ]] || return 1
  [[ "$(stat -f '%Lp' "$file" 2>/dev/null)" == "600" ]] || return 1
}
safe_hash() {
  [[ "$1" =~ ^[a-f0-9]{64}$ ]]
}
readonly MAC_BASE="$HOME/.local/share/radlina/v3-beta/macbook-main-agent"
readonly S03_BASE="$HOME/.local/share/radlina/v3-beta/macbook-main-s03"
readonly LAUNCH="$HOME/Library/LaunchAgents"

if [[ "$(uname -s)" != 'Darwin' || "$(uname -m)" != 'x86_64' ||
      "$(hostname)" != 'amirs-MacBook-Pro.local' ||
      "$(id -un)" != 'amirsheikhzadeh' ]]; then
  add "physical_mac_owner_context_missing"
fi

release_sha="${RADLINA_V3_FINAL4_MAC_RELEASE_SHA256:-}"
if ! safe_hash "$release_sha"; then
  add "pinned_mac_release_sha256_missing"
else
  release="$MAC_BASE/releases/$release_sha"
  manifest="$release/RELEASE_MANIFEST.json"
  if [[ ! -d "$release" || -L "$release" || ! -f "$manifest" ||
        -L "$manifest" ]] ||
     [[ "$(shasum -a 256 "$manifest" 2>/dev/null | awk '{print $1}')" != "$release_sha" ]]; then
    add "verified_native_mac_release_missing"
  else
    for script in v3-mac-operator-cycle.ts v3-s03-mac-witness-daemon.ts; do
      [[ -f "$release/scripts/operations/$script" ]] ||
        add "native_i01_runtime_script_missing"
    done
    [[ -f "$release/node_modules/tsx/dist/cli.mjs" ]] ||
      add "native_mac_dependencies_missing"
  fi
fi

if ! command -v node >/dev/null 2>&1 ||
   [[ "$(node --version 2>/dev/null)" != "v24.20.0" ]]; then
  add "pinned_native_node_missing"
fi

owner_policy="${RADLINA_V3_MAC_OPERATOR_POLICY_PATH:-}"
owner_policy_sha="${RADLINA_V3_MAC_OPERATOR_POLICY_SHA256:-}"
if [[ -z "$owner_policy" ]] || ! safe_hash "$owner_policy_sha" ||
   ! private_metadata "$owner_policy" ||
   [[ "$(shasum -a 256 "$owner_policy" 2>/dev/null | awk '{print $1}')" != "$owner_policy_sha" ]]; then
  add "owner_signed_mac_operator_policy_missing_or_changed"
fi

witness_policy="${RADLINA_V3_S03_WITNESS_POLICY_PATH:-}"
witness_policy_sha="${RADLINA_V3_S03_WITNESS_POLICY_SHA256:-}"
if [[ -z "$witness_policy" ]] || ! safe_hash "$witness_policy_sha" ||
   ! private_metadata "$witness_policy" ||
   [[ "$(shasum -a 256 "$witness_policy" 2>/dev/null | awk '{print $1}')" != "$witness_policy_sha" ]]; then
  add "owner_pinned_s03_witness_policy_missing_or_changed"
fi

# File existence/0600 checks ONLY. Never read Keychain, bearer, HMAC or
# cloudflared token bytes or values from process environment.
token="$S03_BASE/s03-writer-token.secret"
hmac="$S03_BASE/s03-writer-hmac.b64"
private_metadata "$token" || add "mac_s03_writer_token_not_staged"
private_metadata "$hmac" || add "mac_s03_writer_hmac_not_staged"

p08_label='com.radlina.remote-mcp.v3.mac-heartbeat'
witness_label='com.radlina.remote-mcp.v3.mac-s03-witness'
operator_label='com.radlina.remote-mcp.v3.mac-operator'
cloudflare_label='com.radlina.remote-mcp.v3.mac-s03-cloudflare'
domain="gui/$(id -u)"
launchctl print "$domain" >/dev/null 2>&1 || domain="user/$(id -u)"
for label in "$p08_label" "$witness_label" "$operator_label" "$cloudflare_label"; do
  private_metadata "$LAUNCH/$label.plist" || add "mac_launchagent_plist_missing:$label"
  launchctl print "$domain/$label" >/dev/null 2>&1 ||
    add "mac_launchagent_not_registered:$label"
done

# This script never grants acceptance or performs an HTTP write/execute call.
# LaunchAgent registration alone is not proof of health, S03 ACK or I01 receipt.
if (( ${#missing[@]} == 0 )); then
  printf '%s\n' '{"schema":"radlina.v3.i01.mac-readonly-preflight/v1","status":"PREREQUISITES_PRESENT_NOT_ACCEPTED","realI01ExecutionVerified":false,"v2Touched":false,"missing":[]}'
  exit 0
fi
printf '%s' '{"schema":"radlina.v3.i01.mac-readonly-preflight/v1","status":"BLOCKED","realI01ExecutionVerified":false,"v2Touched":false,"missing":['
for i in "${!missing[@]}"; do
  (( i == 0 )) || printf ','
  printf '"%s"' "${missing[$i]}"
done
printf '%s\n' ']}'
exit 3
