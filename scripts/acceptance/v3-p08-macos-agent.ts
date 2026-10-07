import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";

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
import type { FilesystemPort, ProcessPort, SearchPort } from "../../src/v3/platform/contracts.js";
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
const processSessions = new Map<
  string,
  { status: "running" | "complete" | "failed" | "terminated"; exitCode: number | null }
>();

try {
  const filesystem: FilesystemPort = {
    getFileInfo: async (target) => {
      const info = await stat(target);
      return {
        path: target,
        kind: info.isDirectory() ? "directory" : info.isFile() ? "file" : "other",
        size: info.size,
        modifiedAt: info.mtime.toISOString(),
      };
    },
    readFile: async (target, offset, length) => {
      const bytes = await readFile(target);
      return bytes.subarray(offset, offset + length);
    },
    writeFile: async (target, value, overwrite) => {
      await writeFile(target, value, { flag: overwrite ? "w" : "wx" });
    },
    listDirectory: async (target) => (await readdir(target)).sort(),
  };

  const processPort: ProcessPort = {
    start: async (request) => {
      const sessionId = randomUUID();
      const child = spawn(request.executable, request.args, {
        cwd: request.cwd,
        env: { ...process.env, ...(request.env ?? {}) },
        stdio: ["pipe", "ignore", "ignore"],
      });
      processSessions.set(sessionId, { status: "running", exitCode: null });
      child.once("exit", (code) => {
        processSessions.set(sessionId, {
          status: code === 0 ? "complete" : "failed",
          exitCode: code,
        });
      });
      return { sessionId, pid: child.pid ?? null };
    },
    read: async (sessionId) => ({
      sessionId,
      ...(processSessions.get(sessionId) ?? { status: "failed" as const, exitCode: null }),
    }),
    interact: async () => undefined,
    terminate: async (sessionId) => {
      processSessions.set(sessionId, { status: "terminated", exitCode: null });
    },
  };

  let searchResults: unknown[] = [];
  const search: SearchPort = {
    start: async (request) => {
      const entries = await readdir(request.root);
      searchResults = entries
        .filter((name) =>
          request.caseSensitive
            ? name.includes(request.pattern)
            : name.toLowerCase().includes(request.pattern.toLowerCase()),
        )
        .slice(0, request.maxResults)
        .map((name) => ({ path: path.join(request.root, name) }));
      return { searchId: "p08-search" };
    },
    status: async (searchId) => ({
      searchId,
      status: "complete",
      resultCount: searchResults.length,
    }),
    results: async () => [...searchResults],
    cancel: async () => undefined,
  };

  const keychain = new MacOSKeychainSecretProtector(`com.radlina.remote-mcp.p08.${process.pid}`);
  const adapter = createMacOSPlatformAdapter({
    filesystem,
    process: processPort,
    search,
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
  const searchState = await adapter.search.status(searchHandle.searchId);
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
        keychain: "macOS security generic-password",
        process: "native child_process",
        filesystem: "native fs/promises",
        search: "native directory search",
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
  await rm(root, { recursive: true, force: true });
}
