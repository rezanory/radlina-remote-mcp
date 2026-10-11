import { execFile as execFileCallback } from "node:child_process";
import { createHash, createPublicKey, randomBytes, randomUUID, verify } from "node:crypto";
import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { canonicalJson } from "../../src/utils/json.js";
import { MacOSKeychainSecretProtector } from "../../src/v3/device/macos-agent.js";
import { MacOSDeviceIdentityStore } from "../../src/v3/device/macos-identity.js";

const execFile = promisify(execFileCallback);
const deviceId = "macbook-main";
const version = "3.0.0-alpha.1";
const state = path.join(
  os.homedir(),
  ".local",
  "share",
  "radlina",
  "v3-beta",
  "macbook-main-runner",
);
const keychainFile = path.join(state, "v3-device.keychain-db");
const passwordFile = path.join(state, "keychain-password.local");
const identityFile = path.join(state, "runner-device-identity.json");

type TailnetStatus = {
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Self?: { ID?: string; Online?: boolean; DNSName?: string };
};

async function security(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFile("/usr/bin/security", args, {
      timeout: 15_000,
      maxBuffer: 1024 * 1024,
    });
    return stdout.trim();
  } catch {
    throw new Error("dedicated noninteractive macOS Keychain operation failed (secret redacted)");
  }
}

async function liveTailnet(): Promise<TailnetStatus> {
  for (const binary of [
    "/usr/local/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
  ]) {
    try {
      const { stdout } = await execFile(binary, ["status", "--json"], {
        timeout: 15_000,
        maxBuffer: 4 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout) as TailnetStatus;
      if (
        parsed.BackendState === "Running" &&
        parsed.CurrentTailnet?.Name === "rezanory.github" &&
        parsed.Self?.Online &&
        parsed.Self.ID
      ) {
        return parsed;
      }
    } catch {
      // Try the existing alternate installation without changing Tailscale.
    }
  }
  throw new Error("real Mac Tailnet identity is unavailable");
}

async function isPrivateFile(file: string): Promise<boolean> {
  const info = await stat(file);
  return info.isFile() && (info.mode & 0o077) === 0;
}

async function keychainProtector(): Promise<MacOSKeychainSecretProtector> {
  process.umask(0o077);
  await mkdir(state, { recursive: true, mode: 0o700 });
  if (((await stat(state)).mode & 0o077) !== 0) throw new Error("state directory ACL must be 0700");
  const keychainExists = await stat(keychainFile).then(
    () => true,
    () => false,
  );
  let password: string;
  if (!keychainExists) {
    if (
      await stat(passwordFile).then(
        () => true,
        () => false,
      )
    ) {
      throw new Error("existing Keychain password without Keychain: refuse identity reset");
    }
    password = randomBytes(36).toString("hex");
    await writeFile(passwordFile, password, { flag: "wx", mode: 0o600 });
    await security(["create-keychain", "-p", password, keychainFile]);
    await chmod(keychainFile, 0o600);
  } else {
    if (!(await isPrivateFile(passwordFile))) throw new Error("Keychain credential ACL invalid");
    password = (await readFile(passwordFile, "utf8")).trim();
  }
  if (!(await isPrivateFile(keychainFile)) || password.length < 40) {
    throw new Error("durable macOS Keychain requires private local metadata");
  }
  await security(["unlock-keychain", "-p", password, keychainFile]);
  return new MacOSKeychainSecretProtector(
    "com.radlina.remote-mcp.v3.runner.identity",
    async (args) => await security([...args, keychainFile]),
  );
}

async function exclusiveJson(file: string, value: unknown): Promise<void> {
  const temporary = file + "." + randomUUID() + ".tmp";
  const exists = await stat(file).then(
    () => true,
    () => false,
  );
  if (exists) throw new Error("signed output already exists; use a fresh receipt directory");
  await writeFile(temporary, canonicalJson(value) + "\n", { flag: "wx", mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, file);
}

async function main(): Promise<void> {
  if (process.platform !== "darwin" || !["x64", "arm64"].includes(process.arch)) {
    throw new Error("physical macOS is required");
  }
  const tailnet = await liveTailnet();
  const tailnetHash = createHash("sha256").update(tailnet.Self!.ID!).digest("hex");
  const identity = await new MacOSDeviceIdentityStore(
    identityFile,
    await keychainProtector(),
  ).ensure(deviceId, version);
  const publicKey = createPublicKey(identity.state.publicKeyPem);
  const signPayload = (value: unknown): string => {
    const proof = identity.signCanonical(value);
    if (!verify(null, Buffer.from(canonicalJson(value)), publicKey, Buffer.from(proof, "base64"))) {
      throw new Error("physical Keychain signature self-check failed");
    }
    return proof;
  };
  const receiptDirectory = process.env["RADLINA_MAC_P03_RECEIPT_DIRECTORY"];
  if (!receiptDirectory || !path.isAbsolute(receiptDirectory)) {
    throw new Error("absolute isolated receipt directory required");
  }
  await mkdir(receiptDirectory, { recursive: true, mode: 0o700 });
  if (((await stat(receiptDirectory)).mode & 0o077) !== 0) {
    throw new Error("receipt directory must be private");
  }
  const action = process.env["RADLINA_MAC_P03_ACTION"] ?? "ensure";
  if (action === "ensure") {
    const request = {
      schema: "radlina.v3.p03.macos-enrollment-request/v1",
      deviceId,
      hostname: os.hostname(),
      platform: "macos",
      architecture: process.arch,
      agentVersion: version,
      agentInstanceId: identity.state.agentInstanceId,
      devicePublicKeyPem: identity.state.publicKeyPem,
      deviceKeyFingerprint: identity.state.publicKeyFingerprint,
      selfClaimedTailnetNodeHash: tailnetHash,
      tailnet: tailnet.CurrentTailnet!.Name,
      tailscaleDnsName: tailnet.Self!.DNSName ?? null,
      requestedAt: new Date().toISOString(),
      requestedTrustState: "pending",
    } as const;
    await exclusiveJson(path.join(receiptDirectory, "p03-device-request.json"), {
      request,
      deviceSignatureBase64: signPayload(request),
    });
  } else if (action === "sign-challenge") {
    const value = process.env["RADLINA_MAC_P03_CHALLENGE_BASE64"] ?? "";
    if (value.length === 0 || value.length > 8192)
      throw new Error("bounded signed enrollment challenge required");
    const ch = JSON.parse(Buffer.from(value, "base64").toString("utf8")) as {
      schema: string;
      purpose: string;
      challengeId: string;
      deviceId: string;
      hostname: string;
      platform: string;
      architecture: string;
      agentVersion: string;
      agentInstanceId: string;
      deviceKeyFingerprint: string;
      expectedTailnetNodeHash: string;
      issuedAtMs: number;
      expiresAtMs: number;
    };
    const now = Date.now();
    if (
      ch.schema !== "1.0.0" ||
      ch.purpose !== "p03.owner-approved-enrollment" ||
      ch.deviceId !== deviceId ||
      ch.hostname !== os.hostname() ||
      ch.platform !== "macos" ||
      ch.architecture !== process.arch ||
      ch.agentVersion !== version ||
      ch.agentInstanceId !== identity.state.agentInstanceId ||
      ch.deviceKeyFingerprint !== identity.state.publicKeyFingerprint ||
      ch.expectedTailnetNodeHash !== tailnetHash ||
      !Number.isSafeInteger(ch.issuedAtMs) ||
      !Number.isSafeInteger(ch.expiresAtMs) ||
      now < ch.issuedAtMs ||
      now >= ch.expiresAtMs ||
      ch.expiresAtMs - ch.issuedAtMs > 600_000 ||
      !/^[0-9a-f-]{36}$/u.test(ch.challengeId)
    ) {
      throw new Error("P03 challenge does not match real Mac, Tailnet, signing key and TTL");
    }
    await exclusiveJson(path.join(receiptDirectory, "p03-device-proof.json"), {
      schema: "radlina.v3.p03.device-proof/v1",
      challengeId: ch.challengeId,
      deviceId,
      challengeSha256: createHash("sha256").update(canonicalJson(ch)).digest("hex"),
      deviceSignatureBase64: signPayload(ch),
    });
  } else if (action === "heartbeat") {
    const heartbeat = {
      schema: "radlina.v3.p03.signed-heartbeat/v1",
      deviceId,
      agentInstanceId: identity.state.agentInstanceId,
      signedAtMs: Date.now(),
      nonce: randomUUID(),
      agentVersion: version,
      status: "online",
      health: "healthy",
      capabilities: ["device.health"],
    } as const;
    await exclusiveJson(path.join(receiptDirectory, "p03-signed-heartbeat.json"), {
      schema: "radlina.v3.p03.heartbeat-evidence/v1",
      heartbeat,
      deviceSignatureBase64: signPayload(heartbeat),
    });
  } else {
    throw new Error("unsupported isolated P03 action");
  }
  process.stdout.write(
    JSON.stringify({
      deviceId,
      action,
      deviceKeyFingerprint: identity.state.publicKeyFingerprint,
      liveTailnetFingerprint: tailnetHash,
      signatureSelfVerified: true,
      keychain: "dedicated durable runner Keychain; login Keychain untouched",
      trustState: "pending until verified Windows authority admission",
      v2Modified: false,
    }) + "\n",
  );
}

try {
  await main();
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      acceptance: "BLOCKED_FAIL_CLOSED",
      error: error instanceof Error ? error.message : "macOS signing failure",
    }) + "\n",
  );
  process.exitCode = 1;
}
