import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { resolveFinalFourProvisionMode } from "../../../src/v3/integration/final4-development-gating.js";

const ownerScript = readFileSync(
  resolve(process.cwd(), "scripts/operations/v3-final4-owner-policies.ts"),
  "utf8",
);
const serviceScript = readFileSync(
  resolve(process.cwd(), "scripts/operations/v3-final4-gateway-stage.ps1"),
  "utf8",
);
const physicalRuntime = readFileSync(
  resolve(process.cwd(), "src/v3/integration/final4-physical-bootstrap.ts"),
  "utf8",
);

describe("V3 deferred reviewer gate for development, not deployment", () => {
  it("permits development preparation without external reviewer identity", () => {
    expect(resolveFinalFourProvisionMode("--prepare-development")).toEqual({
      name: "development",
      schema: "radlina.v3.final-four-development-binding/v1",
      deployable: false,
    });
  });

  it("retains the independent signing requirement for actual production binding", () => {
    expect(() => resolveFinalFourProvisionMode("--prepare")).toThrow(/genuine reviewer/u);
    expect(resolveFinalFourProvisionMode("--prepare", "E:\\real-reviewer-public.pem")).toEqual({
      name: "production",
      schema: "radlina.v3.final-four-production-binding/v1",
      deployable: true,
    });
  });

  it("does not silently downgrade production review to development", () => {
    expect(() => resolveFinalFourProvisionMode("--prepare-development", "public.pem"))
      .toThrow(/cannot accept production reviewer input/u);
    expect(() => resolveFinalFourProvisionMode("--unsafe")).toThrow(/explicit/u);
  });

  it("emits only nondeployable development config to its own directory", () => {
    expect(ownerScript).toContain("const DEV_OUT=path.win32.join(ROOT,");
    expect(ownerScript).toContain('"development-only-owner-policies"');
    expect(ownerScript).toContain("const outputRoot=mode.deployable?OUT:DEV_OUT");
    expect(ownerScript).toContain("productionActivationPermitted:false as const");
    expect(ownerScript).toContain("gateAcceptancePermitted:false as const");
    expect(ownerScript).toContain("V3_FINAL4_DEVELOPMENT_ONLY_PUBLIC_POLICIES_PREPARED_NOT_DEPLOYABLE");
    expect(ownerScript).toContain("V3WindowsProtectedOwnerSigner.open()");
    expect(ownerScript).toContain("trusted(registry,\"macbook-main\")");
  });

  it("refuses deployment or binding with development-only schema", () => {
    expect(serviceScript).toContain("if ($binding.schema -cne 'radlina.v3.final-four-production-binding/v1'");
    expect(serviceScript).toContain("$binding.PSObject.Properties['developmentOnly']");
    expect(serviceScript).toContain("Development-only or unreviewed V3 configuration cannot be staged or applied");
    expect(physicalRuntime).toContain('schema:z.literal("radlina.v3.final-four-production-binding/v1")');
    expect(physicalRuntime).toContain("independentReviewerPublicKeyPem:z.string()");
  });

  it("keeps real independent S03 and target-local consent requirements in production", () => {
    expect(physicalRuntime).toContain("I01SqliteTargetLocalConsentMailbox");
    expect(physicalRuntime).toContain("S03ExternalAuditClient");
    expect(physicalRuntime).toContain("V3IndependentPhysicalAcceptanceLedger");
  });
});
