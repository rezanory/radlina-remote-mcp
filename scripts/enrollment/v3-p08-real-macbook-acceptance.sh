#!/usr/bin/env bash
set -euo pipefail

# This script proves Mac-local readiness only. It DOES NOT grant production
# acceptance or write a trusted device record to the V3 device registry.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

blocked() {
  printf '%s\n' '{"readiness":"BLOCKED","productionAcceptance":"NOT_GRANTED","reason":"REAL_ENROLLED_MACBOOK_REQUIRED"}'
  exit 2
}

[[ "$(uname -s)" == "Darwin" ]] || blocked
[[ -n "${RADLINA_APPROVED_MAC_TAILSCALE_NODE_ID:-}" ]] || blocked

for cmd in node npm git security tailscale rg; do
  command -v "$cmd" >/dev/null 2>&1 || {
    printf 'Missing required MacBook command: %s\n' "$cmd" >&2
    exit 2
  }
done

EXPECTED_NODE="${RADLINA_EXPECTED_NODE:-v24.20.0}"
[[ "$(node --version)" == "$EXPECTED_NODE" ]] || {
  printf 'Expected Node %s, found %s\n' "$EXPECTED_NODE" "$(node --version)" >&2
  exit 2
}

# Dependencies are installed only after the Mac host and owner-pinned node ID
# have passed basic prerequisites. The TS runner performs the full live check.
npm ci
npm run typecheck
node node_modules/vitest/vitest.mjs run \
  tests/unit/v3/macos-agent.test.ts \
  tests/unit/v3/macbook-readiness-policy.test.ts
node node_modules/eslint/bin/eslint.js \
  src/v3/device/macos-agent.ts \
  tests/unit/v3/macos-agent.test.ts \
  scripts/enrollment/macbook-readiness-policy.ts \
  scripts/acceptance/v3-p08-real-macbook.ts \
  tests/unit/v3/macbook-readiness-policy.test.ts
node node_modules/prettier/bin/prettier.cjs --check \
  src/v3/device/macos-agent.ts \
  tests/unit/v3/macos-agent.test.ts \
  scripts/acceptance/v3-p08-macos-agent.ts \
  scripts/enrollment/macbook-readiness-policy.ts \
  scripts/acceptance/v3-p08-real-macbook.ts \
  tests/unit/v3/macbook-readiness-policy.test.ts

node node_modules/tsx/dist/cli.mjs scripts/acceptance/v3-p08-real-macbook.ts
