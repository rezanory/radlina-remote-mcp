#!/bin/bash
set -euo pipefail

EXPECTED_TAILNET="${RADLINA_EXPECTED_TAILNET:-rezanory.github}"
EXPECTED_MAGICDNS="${RADLINA_EXPECTED_MAGICDNS:-taile17c9e.ts.net}"
DEVICE_ID="${RADLINA_DEVICE_ID:-macbook-main}"
EXPECTED_NODE="${RADLINA_EXPECTED_NODE:-v24.20.0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

fail() {
  printf '{"acceptance":"FAIL","stage":"preflight","reason":%q}\n' "$1" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || fail "P08 real acceptance must run on macOS"

for cmd in security tailscale node npm npx git rg; do
  command -v "$cmd" >/dev/null 2>&1 || fail "missing required command: $cmd"
done

NODE_VERSION="$(node --version)"
[[ "$NODE_VERSION" == "$EXPECTED_NODE" ]] || fail "Node version mismatch: expected $EXPECTED_NODE got $NODE_VERSION"

TAILSCALE_JSON="$(tailscale status --json)"
TAILCHECK="$(
  printf '%s' "$TAILSCALE_JSON" |     RADLINA_EXPECTED_TAILNET="$EXPECTED_TAILNET"     RADLINA_EXPECTED_MAGICDNS="$EXPECTED_MAGICDNS"     node -e '
      let s="";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", c => s += c);
      process.stdin.on("end", () => {
        const j = JSON.parse(s);
        const tailnet = j.CurrentTailnet?.Name ?? null;
        const suffix = j.MagicDNSSuffix ?? j.CurrentTailnet?.MagicDNSSuffix ?? null;
        const self = j.Self ?? {};
        const ok =
          j.BackendState === "Running" &&
          self.Online === true &&
          String(self.OS || "").toLowerCase() === "macos" &&
          tailnet === process.env.RADLINA_EXPECTED_TAILNET &&
          suffix === process.env.RADLINA_EXPECTED_MAGICDNS;
        process.stdout.write(JSON.stringify({
          ok,
          backendState: j.BackendState ?? null,
          tailnet,
          magicDnsSuffix: suffix,
          hostname: self.HostName ?? null,
          dnsName: self.DNSName ?? null,
          os: self.OS ?? null,
          online: self.Online ?? null,
          tailscaleIps: self.TailscaleIPs ?? []
        }));
      });
    '
)"

TAIL_OK="$(printf '%s' "$TAILCHECK" | node -e '
  let s=""; process.stdin.on("data", c => s += c); process.stdin.on("end", () => process.stdout.write(JSON.parse(s).ok ? "yes" : "no"));
')"
[[ "$TAIL_OK" == "yes" ]] || fail "Tailscale identity/tailnet preflight failed: $TAILCHECK"

npm ci
npm run typecheck
npx vitest run tests/unit/v3/macos-agent.test.ts
npx eslint src/v3/device/macos-agent.ts tests/unit/v3/macos-agent.test.ts
npx prettier --check src/v3/device/macos-agent.ts tests/unit/v3/macos-agent.test.ts scripts/acceptance/v3-p08-macos-agent.ts

RUNTIME_JSON="$(npx tsx scripts/acceptance/v3-p08-macos-agent.ts)"
RUNTIME_OK="$(printf '%s' "$RUNTIME_JSON" | node -e '
  let s=""; process.stdin.on("data", c => s += c); process.stdin.on("end", () => process.stdout.write(JSON.parse(s).acceptance === "PASS" ? "yes" : "no"));
')"
[[ "$RUNTIME_OK" == "yes" ]] || fail "P08 runtime acceptance returned FAIL"

COMMIT="$(git rev-parse HEAD)"
TREE="$(git rev-parse HEAD^{tree})"
HOSTNAME="$(hostname)"

node - "$DEVICE_ID" "$COMMIT" "$TREE" "$HOSTNAME" "$TAILCHECK" "$RUNTIME_JSON" <<'NODE'
const [
  deviceId,
  commit,
  tree,
  hostname,
  tailscaleJson,
  runtimeJson,
] = process.argv.slice(2);

const evidence = {
  schema_version: "radlina.v3.real-device-acceptance/v1",
  component: { id: "P08", name: "device.agent.macos" },
  status: "REAL_MACBOOK_ACCEPTANCE_PASS",
  device: {
    logicalDeviceId: deviceId,
    hostname,
    platform: "macos",
  },
  source: { commit, tree },
  tailscale: JSON.parse(tailscaleJson),
  runtime: JSON.parse(runtimeJson),
  acceptance: "PASS",
  acceptedAt: new Date().toISOString(),
};
process.stdout.write(JSON.stringify(evidence));
NODE
