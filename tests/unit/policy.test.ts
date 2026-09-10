import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";

import { PolicyEngine } from "../../src/policy/engine.js";
import { testConfig } from "../helpers/config.js";

const auth: AuthInfo = {
  token: "test-token",
  clientId: "test-client",
  scopes: ["filesystem:read"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

describe("PolicyEngine", () => {
  it("fails closed for missing identity and missing scope", () => {
    const policy = new PolicyEngine(testConfig("C:\\workspace"), {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    expect(policy.decide(undefined, "read_file", "filesystem:read").allowed).toBe(false);
    expect(policy.decide(auth, "write_file", "filesystem:write").reason).toContain("scope");
  });

  it("applies kill switch and emergency read-only independently", () => {
    const config = testConfig("C:\\workspace");
    const killed = new PolicyEngine(config, {
      killSwitch: () => true,
      emergencyReadOnly: () => false,
    });
    expect(killed.decide(auth, "read_file", "filesystem:read").allowed).toBe(false);
    expect(killed.decide(auth, "health", "filesystem:read").allowed).toBe(true);
    const readonly = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => true,
    });
    const admin = { ...auth, scopes: ["admin"] };
    expect(readonly.decide(admin, "write_file", "filesystem:write").allowed).toBe(false);
  });

  it("treats allowShell as trusted-owner direct executable access", () => {
    const config = testConfig("C:\\workspace");
    config.profiles["test"]!.allowShell = true;
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    expect(
      policy.commandAllowed(config.profiles["test"]!, "C:\\Tools\\anything.exe", ["--ok"]).allowed,
    ).toBe(true);
    expect(
      policy.commandAllowed(config.profiles["test"]!, "C:\\Tools\\anything.exe", ["bad\0arg"])
        .allowed,
    ).toBe(false);
    expect(
      policy.commandAllowed(config.profiles["test"]!, "C:\\Tools\\anything.exe", ["x".repeat(4097)])
        .allowed,
    ).toBe(false);
  });

  it("keeps explicit executable allowlisting when trusted-owner shell mode is disabled", () => {
    const config = testConfig("C:\\workspace");
    const policy = new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    });
    expect(
      policy.commandAllowed(config.profiles["test"]!, "C:\\Tools\\anything.exe", []).allowed,
    ).toBe(false);
  });
});
