import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const script = readFileSync(
  resolve(process.cwd(), "scripts/operations/v3-final4-gateway-stage.ps1"),
  "utf8",
);

describe("V3 final-four Stage → Apply contract", () => {
  it("requires a separately staged candidate before Apply", () => {
    expect(script).toContain("elseif ($Apply) {");
    expect(script).toContain("Apply requires a prior separately staged owner-pinned candidate");
    expect(script).toMatch(/else\s*\{\s*\$doc\.Save\(\$candidate\)/u);
  });

  it("rejects tampered, symlinked or mismatched candidates before deployment", () => {
    expect(script).toContain("$existing.Attributes -band [IO.FileAttributes]::ReparsePoint");
    expect(script).toContain("$stagedDoc.OuterXml -cne $doc.OuterXml");
    expect(script).toContain("Previously staged V3 candidate does not match current owner-pinned inputs");
    const verify = script.indexOf("$stagedDoc.OuterXml -cne $doc.OuterXml");
    const serviceStop = script.indexOf("Stop-Service -Name 'RadlinaV3OAuthBeta'");
    expect(verify).toBeGreaterThan(0);
    expect(serviceStop).toBeGreaterThan(verify);
  });

  it("allows the exact matching pre-staged candidate to be reused", () => {
    expect(script).toContain("V3_FINAL4_CANDIDATE_VERIFIED");
    expect(script).toContain("V3_FINAL4_CANDIDATE_STAGED");
    expect(script).toContain("if (-not $Apply) {");
  });

  it("retains dedicated V3 service and rollback isolation", () => {
    expect(script).toContain("if ($doc.service.id -cne 'RadlinaV3OAuthBeta')");
    expect(script).toContain("Stop-Service -Name 'RadlinaV3OAuthBeta'");
    expect(script).toContain("Start-Service -Name 'RadlinaV3OAuthBeta'");
    expect(script).toContain("Copy-Item -LiteralPath $backup -Destination $activePath -Force");
    expect(script).toContain("RADLINA_V3_S03_HMAC_DPAPI_FILE");
  });
});
