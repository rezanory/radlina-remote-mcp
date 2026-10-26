import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { bashForTest } from "./bash-test-executable.js";

const scriptPath=path.resolve("scripts/operations/v3-final4-mac-i01-readiness.sh");
const source=readFileSync(scriptPath,"utf8");

describe("Physical Mac I01 readiness is non-mutating and credential-blind",()=>{
  it("parses as a real Bash executable script",()=>{
    expect(()=>execFileSync(bashForTest(),["-n",scriptPath],{
      encoding:"utf8",timeout:10000,
    })).not.toThrow();
  });
  it("requires exact physical Mac identity, operator and release pins",()=>{
    expect(source).toContain("amirs-MacBook-Pro.local");
    expect(source).toContain("amirsheikhzadeh");
    expect(source).toContain("v24.20.0");
    expect(source).toContain("RADLINA_V3_FINAL4_MAC_RELEASE_SHA256");
    expect(source).toContain("RADLINA_V3_MAC_OPERATOR_POLICY_SHA256");
    expect(source).toContain("RADLINA_V3_S03_WITNESS_POLICY_SHA256");
    expect(source).toContain("shasum -a 256");
  });
  it("checks S03 credential files only by path metadata, never their values",()=>{
    expect(source).toContain('private_metadata "$token"');
    expect(source).toContain('private_metadata "$hmac"');
    expect(source).not.toMatch(/security\s+find-generic-password/u);
    expect(source).not.toMatch(/security\s+dump-keychain/u);
    expect(source).not.toMatch(/\b(?:cat|head|tail|less|xxd|base64)\s+["']?\$?(?:token|hmac)/u);
    expect(source).not.toContain("RADLINA_V3_S03_WRITER_TOKEN_VALUE");
  });
  it("never installs, executes, changes permissions, or controls services",()=>{
    expect(source).not.toMatch(/\blaunchctl\s+(?:bootstrap|bootout|kickstart|enable|disable)/u);
    expect(source).not.toMatch(/\b(?:sudo|chmod|chown|mv|cp|rm|touch|curl|wget)\s+/u);
    expect(source).not.toContain("RADLINA_V3_FINAL4_ENABLE");
    expect(source).toContain('launchctl print "$domain/$label" >/dev/null 2>&1');
  });
  it("checks I01 only, without enabling F01 fleet or modifying V2",()=>{
    expect(source).toContain("--check-i01");
    expect(source).toContain("com.radlina.remote-mcp.v3.mac-s03-witness");
    expect(source).toContain("com.radlina.remote-mcp.v3.mac-operator");
    expect(source).toContain("com.radlina.remote-mcp.v3.mac-s03-cloudflare");
    expect(source).toContain("com.radlina.remote-mcp.v3.mac-heartbeat");
    expect(source).not.toContain("com.radlina.remote-mcp.v3.mac-fleet-agent");
    expect(source).toContain('"realI01ExecutionVerified":false');
    expect(source).toContain('"v2Touched":false');
  });
  it("distinguishes prerequisites-present from real I01 gate acceptance",()=>{
    expect(source).toContain("PREREQUISITES_PRESENT_NOT_ACCEPTED");
    expect(source).toContain('"status":"BLOCKED"');
    expect(source).toContain("exit 3");
    expect(source).not.toContain('gateAccepted":true');
  });
});
