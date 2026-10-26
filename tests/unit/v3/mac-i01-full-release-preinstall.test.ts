import {execFileSync} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {describe,expect,it} from "vitest";
import { bashForTest } from "./bash-test-executable.js";

const install=path.resolve("scripts/operations/v3-final4-mac-install.sh");
const source=readFileSync(install,"utf8");

describe("V3 Mac I01 installer validates immutable native release before mutating state",()=>{
  it("is valid bash",()=>{
    expect(()=>execFileSync(bashForTest(),["-n",install],{timeout:10000})).not.toThrow();
  });
  it("verifies all staged release artifacts, not merely manifest SHA",()=>{
    expect(source).toContain('VERIFIER="$RELEASE/scripts/operations/verify-release.mjs"');
    expect(source).toContain('node "$VERIFIER" "$RELEASE" "$RADLINA_V3_FINAL4_MAC_RELEASE_SHA256"');
    expect(source).toContain("V3_MAC_I01_FULL_NATIVE_RELEASE_PREINSTALL_VERIFIED");
  });
  it("checks all artifacts before reading staged credentials or creating LaunchAgents",()=>{
    const verifier=source.indexOf('node "$VERIFIER" "$RELEASE"');
    const stage=source.indexOf('bash "$RELEASE/scripts/operations/v3-final4-s03-mac-secret-stage.sh"');
    const installAgent=source.indexOf("install_agent() {");
    expect(verifier).toBeGreaterThan(-1);
    expect(stage).toBeGreaterThan(verifier);
    expect(installAgent).toBeGreaterThan(stage);
  });
  it("keeps I01-only installation separate from Fleet",()=>{
    expect(source).toContain('"--install-i01"');
    expect(source).toContain('if [[ "$INSTALL_MODE" == "--install" ]]');
    expect(source).toContain("V3_MAC_I01_AGENTS_INSTALLED_FLEET_UNTOUCHED");
  });
  it("does not modify the separate V2 installation",()=>{
    expect(source).not.toMatch(/(?:Stop-Service|Restart-Service|systemctl)/u);
    expect(source).not.toContain("RadlinaRemoteMCP");
  });
});
