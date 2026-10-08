import { describe, expect, it } from "vitest";
import {
  assessMacReadiness,
  type MacReadinessRequirements,
  type TailscaleMacStatus,
} from "../../../scripts/enrollment/macbook-readiness-policy.js";

const requirements: MacReadinessRequirements = {
  platform: "darwin",
  expectedTailnet: "rezanory.github",
  expectedMagicDnsSuffix: "taile17c9e.ts.net",
  approvedMacNodeId: "n-approved-real-mac",
  windowsPingSucceeded: true,
};

const mac: TailscaleMacStatus = {
  BackendState: "Running",
  CurrentTailnet: { Name: "rezanory.github", MagicDNSSuffix: "taile17c9e.ts.net" },
  Self: {
    ID: "n-approved-real-mac",
    OS: "macOS",
    Online: true,
    DNSName: "macbook-main.taile17c9e.ts.net.",
    HostName: "macbook-main",
  },
};

describe("P08 enrolled-Mac readiness fail-closed guard", () => {
  it("accepts an approved matching Mac on the correct tailnet with verified Windows ping", () => {
    const result = assessMacReadiness(mac, requirements);
    expect(result.ready).toBe(true);
    expect(result.failedChecks).toEqual([]);
  });

  it("does not trust a logical deviceId without a pinned Tailscale node identity", () => {
    const result = assessMacReadiness(mac, { ...requirements, approvedMacNodeId: "" });
    expect(result.ready).toBe(false);
    expect(result.failedChecks).toContain("approvedNodeIdPresent");
    expect(result.failedChecks).toContain("nodeIdMatchesApproval");
  });

  it("rejects an unknown node even with identical logical hostname", () => {
    const result = assessMacReadiness(
      { ...mac, Self: { ...mac.Self, ID: "n-impostor" } },
      requirements,
    );
    expect(result.failedChecks).toContain("nodeIdMatchesApproval");
  });

  it("rejects GitHub-hosted Mac that is not enrolled in the expected tailnet", () => {
    const result = assessMacReadiness(
      { ...mac, CurrentTailnet: { Name: "different-tailnet" } },
      requirements,
    );
    expect(result.ready).toBe(false);
    expect(result.failedChecks).toContain("correctTailnet");
  });

  it("rejects Windows pretending to be macOS", () => {
    const result = assessMacReadiness(mac, { ...requirements, platform: "win32" });
    expect(result.failedChecks).toContain("darwinHost");
  });

  it("rejects offline or non-macOS identity", () => {
    const result = assessMacReadiness(
      { ...mac, Self: { ...mac.Self, OS: "linux", Online: false } },
      requirements,
    );
    expect(result.failedChecks).toEqual(expect.arrayContaining(["actualMacOs", "macOnline"]));
  });

  it("requires real reachability to Windows, not just a matching local tailnet", () => {
    const result = assessMacReadiness(mac, {
      ...requirements,
      windowsPingSucceeded: false,
    });
    expect(result.failedChecks).toContain("windowsReachable");
  });

  it("rejects mismatched MagicDNS and DNS outside the tailnet", () => {
    const result = assessMacReadiness(
      {
        ...mac,
        MagicDNSSuffix: "other.example.net",
        Self: { ...mac.Self, DNSName: "macbook-main.other.example.net" },
      },
      requirements,
    );
    expect(result.failedChecks).toEqual(
      expect.arrayContaining(["correctMagicDnsSuffix", "macDnsInTailnet"]),
    );
  });

  it("rejects missing Tailscale identity and stopped backend", () => {
    const result = assessMacReadiness(
      { BackendState: "Stopped", Self: { ID: "n-approved-real-mac", OS: "macos" } },
      requirements,
    );
    expect(result.ready).toBe(false);
    expect(result.failedChecks).toContain("tailscaleRunning");
    expect(result.failedChecks).toContain("macOnline");
  });
});
