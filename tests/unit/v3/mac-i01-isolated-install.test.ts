import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Source guardrails for the physical Mac installer. A passing test never
 * substitutes for real Mac installation, consent or signed S03 evidence.
 */
const script = readFileSync(
  resolve(process.cwd(), "scripts/operations/v3-final4-mac-install.sh"),
  "utf8",
);

describe("I01-only Mac installer isolation", () => {
  it("has an explicit scoped I01 install mode, retaining the full install mode", () => {
    expect(script).toContain('"$1" == "--install-i01"');
    expect(script).toContain('"$1" == "--install"');
    expect(script).toContain('INSTALL_MODE="$1"');
  });

  it("requires authentic private S03 files and owner-pinned policy before agents", () => {
    expect(script).toContain('RADLINA_V3_S03_WRITER_TOKEN_FILE');
    expect(script).toContain('RADLINA_V3_S03_HMAC_KEY_FILE');
    expect(script).toContain('RADLINA_V3_S03_WITNESS_POLICY_SHA256');
    expect(script).toContain('v3-final4-s03-mac-secret-stage.sh');
    expect(script).toContain('for file in "$POLICY" "$S03POLICY" "$TOKEN" "$HMAC"');
    expect(script).toContain('stat -f \'%Lp\'');
  });

  it("installs S03 first and never activates F01 Fleet in I01-only mode", () => {
    expect(script).toContain('I01_LABELS=(com.radlina.remote-mcp.v3.mac-s03-witness com.radlina.remote-mcp.v3.mac-operator)');
    expect(script).toContain('AGENT_LABELS=("${I01_LABELS[@]}")');
    expect(script).toMatch(/if \[\[ "\$INSTALL_MODE" == "--install" \]\]; then\s+AGENT_LABELS\+=\(com\.radlina\.remote-mcp\.v3\.mac-fleet-agent\)/);
    const witnessInstall = script.indexOf("install_agent 'com.radlina.remote-mcp.v3.mac-s03-witness'");
    const operatorInstall = script.indexOf("install_agent 'com.radlina.remote-mcp.v3.mac-operator'");
    const fleetInstall = script.indexOf("install_agent 'com.radlina.remote-mcp.v3.mac-fleet-agent'");
    const bootstrap = script.indexOf('for label in "${AGENT_LABELS[@]}"; do\n  launchctl bootstrap');
    expect(witnessInstall).toBeGreaterThan(-1);
    expect(operatorInstall).toBeGreaterThan(witnessInstall);
    expect(fleetInstall).toBeGreaterThan(operatorInstall);
    expect(bootstrap).toBeGreaterThan(fleetInstall);
    expect(script).toContain("V3_MAC_I01_AGENTS_INSTALLED_FLEET_UNTOUCHED");
  });

  it("refuses existing LaunchAgents before creating any new agent", () => {
    const preflight = script.indexOf('for label in "${AGENT_LABELS[@]}"; do\n  [[ ! -e');
    const installer = script.indexOf("install_agent 'com.radlina.remote-mcp.v3.mac-s03-witness'");
    expect(preflight).toBeGreaterThan(-1);
    expect(preflight).toBeLessThan(installer);
    expect(script).toContain("reconcile explicitly");
  });
});
