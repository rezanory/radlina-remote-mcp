import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import * as z from "zod/v4";

import { canonicalJson } from "../../src/utils/json.js";
import { MacOSKeychainSecretProtector } from "../../src/v3/device/macos-agent.js";
import { MacOSDeviceIdentityStore } from "../../src/v3/device/macos-identity.js";

const execFile = promisify(execFileCallback);
const challengeSchema = z.object({
  schema: z.literal("1.0.0"),
  purpose: z.literal("p03.owner-approved-enrollment"),
  challengeId: z.string().uuid(),
  deviceId: z.literal("macbook-main"),
  hostname: z.string().min(1),
  platform: z.literal("macos"),
  architecture: z.enum(["x64", "arm64", "unknown"]),
  agentVersion: z.string().min(1),
  agentInstanceId: z.string().uuid(),
  deviceKeyFingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  expectedTailnetNodeHash: z.string().regex(/^[0-9a-f]{64}$/u),
  issuedAtMs: z.number().int().positive(),
  expiresAtMs: z.number().int().positive(),
});

async function tailscaleStatus(): Promise<{
  BackendState?: string;
  CurrentTailnet?: { Name?: string };
  Self?: { ID?: string; Online?: boolean; DNSName?: string };
}> {
  for (const executable of [
    "/usr/local/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
  ]) {
    try {
      const { stdout } = await execFile(executable, ["status", "--json"], {
        timeout: 20_000,
        maxBuffer: 4 * 1024 * 1024,
      });
      return JSON.parse(stdout) as Awaited<ReturnType<typeof tailscaleStatus>>;
    } catch {
      // Try the next fixed application path.
    }
  }
  throw new Error("Tailscale status is unavailable on this Mac");
}

async function atomicPrivateJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, canonicalJson(value) + "\n", { flag: "wx", mode: 0o600 });
  await rename(temporary, file);
  await chmod(file, 0o600);
}

async function main(): Promise<void> {
  if (process.platform !== "darwin") throw new Error("physical macOS is required");
  if (process.arch !== "x64" && process.arch !== "arm64") {
    throw new Error("supported physical Mac architecture is required");
  }

  const stateDirectory =
    process.env["RADLINA_V3_MAC_STATE_DIRECTORY"] ??
    path.join(os.homedir(), ".local", "share", "radlina", "v3-beta", "macbook-main");
  if (!path.isAbsolute(stateDirectory) || stateDirectory.toLowerCase().includes("v2")) {
    throw new Error("absolute isolated V3 Mac state directory required");
  }
  const identityFile = path.join(stateDirectory, "device-identity.json");
  const keychain = new MacOSKeychainSecretProtector("com.radlina.remote-mcp.v3.device-identity");
  const identity = await new MacOSDeviceIdentityStore(identityFile, keychain).ensure(
    "macbook-main",
    "3.0.0-alpha.1",
  );
  const action = process.env["RADLINA_V3_MAC_IDENTITY_ACTION"] ?? "ensure";

  if (action === "sign-challenge") {
    const challengeFile = process.env["RADLINA_V3_P03_CHALLENGE_FILE"];
    if (!challengeFile || !path.isAbsolute(challengeFile)) {
      throw new Error("absolute RADLINA_V3_P03_CHALLENGE_FILE is required");
    }
    const challenge = challengeSchema.parse(JSON.parse(await readFile(challengeFile, "utf8")));
    if (
      challenge.hostname !== os.hostname() ||
      challenge.architecture !== process.arch ||
      challenge.agentVersion !== identity.state.agentVersion ||
      challenge.agentInstanceId !== identity.state.agentInstanceId ||
      challenge.deviceKeyFingerprint !== identity.state.publicKeyFingerprint
    ) {
      throw new Error("P03 challenge does not match this physical Mac identity");
    }
    const outputFile = path.join(
      stateDirectory,
      `challenge-${challenge.challengeId}.device-proof.json`,
    );
    await atomicPrivateJson(outputFile, {
      schema: "radlina.v3.p03.device-proof/v1",
      challengeId: challenge.challengeId,
      deviceId: challenge.deviceId,
      challengeSha256: createHash("sha256").update(canonicalJson(challenge)).digest("hex"),
      deviceSignatureBase64: identity.signCanonical(challenge),
    });
    process.stdout.write(
      JSON.stringify({
        action,
        deviceId: challenge.deviceId,
        trustState: "pending",
        deviceProofFile: outputFile,
        ownerSignatureStillRequired: true,
        productionAcceptance: "NOT_GRANTED",
      }) + "\n",
    );
    return;
  }
  if (action !== "ensure") throw new Error("unsupported identity action");

  const tailscale = await tailscaleStatus();
  if (
    tailscale.BackendState !== "Running" ||
    tailscale.CurrentTailnet?.Name !== "rezanory.github" ||
    !tailscale.Self?.Online ||
    !tailscale.Self.ID
  ) {
    throw new Error("live expected Tailnet identity is required");
  }
  const request = {
    schema: "radlina.v3.p03.macos-enrollment-request/v1",
    deviceId: identity.state.deviceId,
    hostname: os.hostname(),
    platform: "macos",
    architecture: process.arch,
    agentVersion: identity.state.agentVersion,
    agentInstanceId: identity.state.agentInstanceId,
    devicePublicKeyPem: identity.state.publicKeyPem,
    deviceKeyFingerprint: identity.state.publicKeyFingerprint,
    selfClaimedTailnetNodeHash: createHash("sha256").update(tailscale.Self.ID).digest("hex"),
    tailnet: tailscale.CurrentTailnet.Name,
    tailscaleDnsName: tailscale.Self.DNSName ?? null,
    requestedAt: new Date().toISOString(),
    requestedTrustState: "pending",
  } as const;
  const requestFile = path.join(stateDirectory, "p03-enrollment-request.json");
  await atomicPrivateJson(requestFile, {
    request,
    deviceSignatureBase64: identity.signCanonical(request),
  });
  process.stdout.write(
    JSON.stringify({
      action,
      deviceId: request.deviceId,
      trustState: "pending",
      keyStorage: "macOS Keychain",
      identityStateFile: identityFile,
      enrollmentRequestFile: requestFile,
      independentOwnerApprovalRequired: true,
      independentWindowsTailnetObservationRequired: true,
      p06Routable: false,
      productionAcceptance: "NOT_GRANTED",
    }) + "\n",
  );
}

try {
  await main();
} catch (error) {
  process.stdout.write(
    JSON.stringify({
      readiness: "BLOCKED",
      productionAcceptance: "NOT_GRANTED",
      error: error instanceof Error ? error.message : "unknown macOS identity error",
    }) + "\n",
  );
  process.exitCode = 1;
}
