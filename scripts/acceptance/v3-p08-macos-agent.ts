import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { promisify } from "node:util";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../src/v3/capability/runtime.js";
import {
  MacOSDeviceAgent,
  MacOSKeychainSecretProtector,
  createMacOSPlatformAdapter,
} from "../../src/v3/device/macos-agent.js";
import {
  createMacOSNativePorts,
  type MacOSNativePorts,
} from "../../src/v3/device/macos-native-ports.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
import { testConfig } from "../../tests/helpers/config.js";

if (process.platform !== "darwin") {
  process.stdout.write(
    JSON.stringify({
      acceptance: "BLOCKED_REAL_MACOS_REQUIRED",
      platform: process.platform,
    }),
  );
  process.exit(2);
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-p08-"));
const isolatedKeychainFile = path.join(root, "acceptance-only.keychain-db");
const execFile = promisify(execFileCallback);

// macOS self-hosted CI has no interactive login Keychain; never unlock the
// user's personal Keychain or change the default Keychain search list.
async function scopedSecurity(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFile("security", args, {
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
    });
    return stdout.trim();
  } catch {
    // No exception may expose a synthetic Keychain password in public CI logs.
    throw new Error(`isolated macOS Keychain command ${args[0] ?? "unknown"} failed`);
  }
}
let nativePorts: MacOSNativePorts | undefined;

try {
  nativePorts = await createMacOSNativePorts({
    roots: [root],
    executableAllowlist: ["/bin/sh"],
    environmentAllowlist: ["PATH"],
    ripgrepExecutable: process.env["RADLINA_RG_EXECUTABLE"] ?? "/usr/local/bin/rg",
    maxProcessRuntimeMs: 5_000,
    maxSearchRuntimeMs: 5_000,
  });

  const fixturePassword = randomBytes(36).toString("hex");
  await scopedSecurity(["create-keychain", "-p", fixturePassword, isolatedKeychainFile]);
  await scopedSecurity(["unlock-keychain", "-p", fixturePassword, isolatedKeychainFile]);
  // Scope every CRUD command to the freshly created test Keychain only.
  // Never mutate the default login Keychain or its trusted-app ACLs.
  const keychain = new MacOSKeychainSecretProtector(
    `com.radlina.remote-mcp.p08.${process.pid}`,
    (args) => scopedSecurity([...args, isolatedKeychainFile]),
  );
  const adapter = createMacOSPlatformAdapter({
    filesystem: nativePorts.filesystem,
    process: nativePorts.process,
    search: nativePorts.search,
    secrets: keychain,
    agentVersion: "3.0.0-alpha.1",
    readiness: async () => ({ ready: true, detail: "p08-acceptance" }),
    scheduleRestart: async () => undefined,
  });

  const secret = Buffer.from("radlina-p08-keychain");
  const secretRef = await adapter.secrets.protect(secret);
  const restored = await adapter.secrets.unprotect(secretRef);
  const keychainRoundTrip =
    Buffer.from(restored).equals(secret) && !Buffer.from(secretRef).equals(secret);

  const markerFile = path.join(root, "radlina-p08-marker.txt");
  await adapter.filesystem.writeFile(markerFile, Buffer.from("p08"), true);
  const fileInfo = await adapter.filesystem.getFileInfo(markerFile);
  const entries = await adapter.filesystem.listDirectory(root);

  const processHandle = await adapter.process.start({
    executable: "/bin/sh",
    args: ["-lc", "exit 0"],
    cwd: root,
    timeoutMs: 5_000,
  });
  let processState = await adapter.process.read(processHandle.sessionId);
  for (let attempt = 0; attempt < 100 && processState.status === "running"; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    processState = await adapter.process.read(processHandle.sessionId);
  }

  const searchHandle = await adapter.search.start({
    root,
    pattern: "radlina-p08-marker",
    mode: "files",
    caseSensitive: true,
    literal: true,
    maxResults: 10,
  });
  let searchState = await adapter.search.status(searchHandle.searchId);
  for (let attempt = 0; attempt < 100 && searchState.status === "running"; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    searchState = await adapter.search.status(searchHandle.searchId);
  }
  const found = await adapter.search.results(searchHandle.searchId);

  const registry = new CapabilityRegistry();
  registry.register({
    id: "radlina.device",
    version: "3.0.0",
    description: "P08 real macOS acceptance",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async () => ({
          status: "healthy",
          host: (await adapter.deviceInfo.getDeviceInfo()).hostname,
        }),
      },
    ],
  });

  const policy = new V3ExecutionPolicyGuard(
    new PolicyEngine(testConfig("C:\\workspace"), {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    }),
  );
  const runtime = new V3CapabilityRuntime(
    registry,
    policy,
    { record: async (input) => sha256(canonicalJson(input)) },
    new HmacDistributedAuditSigner(Buffer.alloc(32, 29)),
  );

  const agent = new MacOSDeviceAgent(adapter, registry, runtime, {
    deviceId: "macbook-main",
    tags: ["primary", "apple", "p08-accepted"],
    trustState: "trusted",
    identity: {
      deviceId: "macbook-main",
      agentInstanceId: "127d6964-20af-4414-9fbb-b7b4b0d75d84",
      agentVersion: "3.0.0-alpha.1",
      publicKeyFingerprint: "a".repeat(64),
      enrolledAt: new Date().toISOString(),
    },
  });

  const hello = await agent.hello();
  const auth: AuthInfo = {
    token: "p08-token",
    clientId: "p08-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  const input = {};
  const execution = await agent.execute(
    {
      requestId: randomUUID(),
      workflowExecutionId: "wf-p08",
      nodeId: "health",
      attempt: 1,
      targetDeviceId: "macbook-main",
      capability: "device.health",
      input,
      inputSha256: sha256(canonicalJson(input)),
      timeoutMs: 5_000,
      globalCorrelationId: "corr-p08",
      traceId: "trace-p08",
    },
    {
      auth,
      subject: "owner",
      profile: "test",
      isCancelled: () => false,
    },
  );

  await keychain.delete(secretRef);

  const info = await adapter.deviceInfo.getDeviceInfo();
  const acceptance =
    info.platform === "macos" &&
    keychainRoundTrip &&
    fileInfo.kind === "file" &&
    entries.includes("radlina-p08-marker.txt") &&
    processState.status === "complete" &&
    processState.exitCode === 0 &&
    searchState.status === "complete" &&
    found.length === 1 &&
    hello.descriptor.deviceId === "macbook-main" &&
    execution.ok &&
    execution.receipt.resolvedDeviceId === "macbook-main" &&
    execution.receipt.terminalState === "completed";

  process.stdout.write(
    JSON.stringify({
      input: {
        deviceId: "macbook-main",
        markerFile,
        process: "/bin/sh",
      },
      runtime: {
        agent: "MacOSDeviceAgent",
        keychain: "macOS security isolated test Keychain (not login Keychain)",
        process: "policy-bounded macOS native child_process",
        filesystem: "policy-bounded macOS native fs/promises",
        search: "policy-bounded real ripgrep",
      },
      execution: {
        hostname: info.hostname,
        architecture: info.architecture,
        keychainRoundTrip,
        fileKind: fileInfo.kind,
        processStatus: processState.status,
        processExitCode: processState.exitCode,
        searchResultCount: found.length,
        helloDeviceId: hello.descriptor.deviceId,
      },
      output: {
        resolvedDeviceId: execution.receipt.resolvedDeviceId,
        terminalState: execution.receipt.terminalState,
        localAuditReceiptHash: execution.receipt.localAuditReceiptHash,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await nativePorts?.close();
  try {
    await scopedSecurity(["delete-keychain", isolatedKeychainFile]);
  } catch {
    // Never touch the user login Keychain; only the acceptance temp directory.
  }
  await rm(root, { recursive: true, force: true });
}
