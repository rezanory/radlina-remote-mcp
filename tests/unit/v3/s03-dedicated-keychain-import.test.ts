import {execFileSync} from "node:child_process";
import {readFileSync} from "node:fs";
import path from "node:path";
import {describe,expect,it} from "vitest";
import { bashForTest } from "./bash-test-executable.js";

const bash=path.resolve("scripts/operations/v3-final4-s03-mac-secret-stage.sh");
const swift=path.resolve("scripts/operations/v3-final4-s03-dedicated-keychain-import.swift");
const shell=readFileSync(bash,"utf8");
const helper=readFileSync(swift,"utf8");

describe("I01 import of existing writer secrets from physical dedicated Mac Keychain",()=>{
  it("remains a valid explicit --stage Bash entrypoint",()=>{
    expect(()=>execFileSync(bashForTest(),["-n",bash],{timeout:10000})).not.toThrow();
    expect(shell).toContain("'--stage'");
    expect(shell).toContain('[[ "$(id -un)" == \'amirsheikhzadeh\' ]]');
  });
  it("uses same V3 dedicated Keychain file as independently signed S03 daemon",()=>{
    expect(helper).toContain('macbook-main-runner');
    expect(helper).toContain('v3-device.keychain-db');
    expect(helper).toContain('keychain-password.local');
    expect(helper).toContain("SecKeychainOpen");
    expect(helper).toContain("SecKeychainUnlock");
    expect(helper).toContain("SecKeychainFindGenericPassword");
    expect(helper).toContain('macbook-main-s03');
  });
  it("does not try the inaccessible default macOS login Keychain",()=>{
    expect(shell).not.toContain("security find-generic-password");
    expect(helper).not.toMatch(/SecItemAdd|SecKeychainAddGenericPassword|SecKeychainCreate/u);
    expect(helper).not.toContain("login.keychain");
  });
  it("must find both existing legitimate S03 writer Keychain entries",()=>{
    expect(helper).toContain("com.radlina.remote-mcp.v3.s03-writer-token");
    expect(helper).toContain("com.radlina.remote-mcp.v3.s03-writer-hmac-base64");
    expect(helper).toContain('required existing V3 writer item absent');
    expect(helper).not.toContain("SecRandomCopyBytes");
    expect(helper).not.toContain("randomUUID");
  });
  it("writes only physically isolated 0600 S03 credential files",()=>{
    expect(helper).toContain('s03-writer-token.secret');
    expect(helper).toContain('s03-writer-hmac.b64');
    expect(helper).toContain('O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW');
    expect(helper).toContain("mode_t(0o600)");
    expect(helper).toContain("fsync(fd)");
    expect(helper).toContain("0o077");
    expect(helper).toContain("unlink(tokenFile.path)");
  });
  it("does not expose secrets through command arguments, stdout, or service environment",()=>{
    expect(shell).toContain('/usr/bin/swift "$HELPER" --stage');
    expect(shell).not.toContain('TOKEN_VALUE=');
    expect(shell).not.toContain('HMAC_VALUE=');
    expect(helper).not.toContain('print(token)');
    expect(helper).not.toContain('print(hmac)');
    expect(helper).not.toContain('Process.run');
    expect(helper).not.toContain('ProcessInfo.processInfo.arguments');
  });
  it("rejects overwrite and is constrained to real host and Mac owner",()=>{
    expect(shell).toContain("refuse overwrite");
    expect(helper).toContain("amirs-MacBook-Pro.local");
    expect(helper).toContain("amirsheikhzadeh");
    expect(helper).toContain("existing staged writer files require explicit reconciliation");
  });
  it("does not stage mock acceptance evidence or modify separate V2",()=>{
    expect(helper).not.toContain("gateAccepted");
    expect(helper).not.toContain("RadlinaRemoteMCP");
    expect(helper).not.toContain("v2-");
    expect(shell).not.toContain("launchctl bootstrap");
    expect(shell).not.toContain("systemctl");
  });
});
