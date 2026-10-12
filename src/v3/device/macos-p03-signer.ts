/**
 * P03 Mac identity is reused, never rotated or silently reprovisioned.
 * V3-only Keychain access: signature scope is restricted to device-local
 * target approvals, exact signed receipts, F01 receipts and poll sessions.
 */
import { execFile as execFileCallback } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { canonicalJson } from "../../utils/json.js";
import { MacOSKeychainSecretProtector } from "./macos-agent.js";
import { MacOSDeviceIdentityStore, type MacOSDeviceIdentity } from "./macos-identity.js";
import { ed25519PublicKeyFingerprint } from "./owner-pinned-enrollment.js";

const run = promisify(execFileCallback);
const P03_MAC_KEY = "f2c2e93ff120fbc5122cbb6b5a0b461a072f54bd8d226368c858fd0bd17037ea";
const allowedSchemas = new Set([
  "radlina.v3.i01.recipient-approval/v1",
  "radlina.v3.i01.signed-device-response/v1",
  "radlina.v3.i01.signed-agent-poll/v1",
  "radlina.v3.i01.device-session/v1",
  "radlina.v3.p03.signed-heartbeat/v1",
  "radlina.v3.i01.signed-agent-result/v1",
  "radlina.v3.f01.signed-fleet-reply/v1",
  "radlina.v3.f01.recipient-release-consent/v1",
]);
const trustedRoot = path.join(os.homedir(), ".local", "share", "radlina", "v3-beta", "macbook-main-runner");

async function privateRegularFile(file: string): Promise<void> {
  const info = await stat(file);
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error("Mac P03 private regular file with 0600 required");
  }
}
async function privateDirectory(file: string): Promise<void> {
  const info = await stat(file);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) {
    throw new Error("Mac P03 private directory with 0700 required");
  }
}
async function security(args: string[]): Promise<string> {
  try {
    const { stdout } = await run("/usr/bin/security", args, {
      timeout: 15000, maxBuffer: 64 * 1024,
    });
    return stdout.trim();
  } catch {
    throw new Error("existing P03 macOS Keychain access denied");
  }
}

export class ExistingPhysicalMacP03Signer {
  private constructor(private readonly identity: MacOSDeviceIdentity) {}
  static async open(): Promise<ExistingPhysicalMacP03Signer> {
    if (process.platform !== "darwin" || process.arch !== "x64" ||
      os.hostname() !== "amirs-MacBook-Pro.local") {
      throw new Error("signed Mac P03 port requires physical enrolled macOS x64");
    }
    await privateDirectory(trustedRoot);
    const keychainFile = path.join(trustedRoot, "v3-device.keychain-db");
    const passwordFile = path.join(trustedRoot, "keychain-password.local");
    const stateFile = path.join(trustedRoot, "runner-device-identity.json");
    for (const f of [keychainFile, passwordFile, stateFile]) await privateRegularFile(f);
    const password = (await readFile(passwordFile, "utf8")).trim();
    if (password.length < 40 || password.length > 200) {
      throw new Error("existing dedicated macOS P03 Keychain metadata invalid");
    }
    await security(["unlock-keychain", "-p", password, keychainFile]);
    const keychain = new MacOSKeychainSecretProtector(
      "com.radlina.remote-mcp.v3.runner.identity",
      async (args) => await security([...args, keychainFile]),
    );
    // A missing stateFile above fails; ensure() therefore does not provision or rotate keys.
    const identity = await new MacOSDeviceIdentityStore(stateFile, keychain)
      .ensure("macbook-main", "3.0.0-alpha.1");
    if (identity.state.publicKeyFingerprint !== P03_MAC_KEY) {
      throw new Error("existing Mac Keychain signer not equal to registered physical P03 identity");
    }
    return new ExistingPhysicalMacP03Signer(identity);
  }
  publicIdentity() {
    const {agentInstanceId,deviceId,publicKeyPem,publicKeyFingerprint,agentVersion} = this.identity.state;
    return {agentInstanceId,deviceId,publicKeyPem,publicKeyFingerprint,agentVersion};
  }
  signCanonical(payload: string): string {
    if (Buffer.byteLength(payload, "utf8") > 256 * 1024) {
      throw new Error("bounded V3 macOS P03 signed operation required");
    }
    let value: unknown;
    try { value = JSON.parse(payload); }
    catch { throw new Error("canonical V3 signing payload must be JSON"); }
    if (!value || typeof value !== "object") throw new Error("structured Mac device receipt required");
    const record = value as Record<string, unknown>;
    const consent=record["schema"]==="1.0.0"&&record["action"]==="consent.decision"&&
      record["targetDeviceId"]==="macbook-main"&&
      record["decision"]!==undefined&&
      ["approve","deny"].includes(String(record["decision"]))&&
      record["duration"]==="once";
    if (typeof record["schema"] !== "string" || (!allowedSchemas.has(record["schema"])&&!consent) ||
      canonicalJson(value) !== payload) {
      throw new Error("P03 device may sign only canonical, named V3 local receipts");
    }
    if (record["targetDeviceId"] !== undefined && record["targetDeviceId"] !== "macbook-main") {
      throw new Error("Mac P03 cannot sign a different execution target");
    }
    if (record["deviceId"] !== undefined && record["deviceId"] !== "macbook-main") {
      throw new Error("Mac P03 cannot sign a different device identity");
    }
    const proof = this.identity.signCanonical(value);
    if (!verify(null, Buffer.from(payload, "utf8"), createPublicKey(this.identity.state.publicKeyPem),
      Buffer.from(proof, "base64")) ||
      ed25519PublicKeyFingerprint(this.identity.state.publicKeyPem) !== P03_MAC_KEY) {
      throw new Error("Mac P03 signing self-verification failed");
    }
    return proof;
  }
}
