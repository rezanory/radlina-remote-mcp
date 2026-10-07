import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { FilesystemService } from "../../src/tools/filesystem/service.js";
import { ProcessManager } from "../../src/tools/process/manager.js";
import { SearchManager } from "../../src/tools/search/manager.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../src/v3/capability/runtime.js";
import {
  WindowsDeviceAgent,
  createWindowsPlatformAdapter,
} from "../../src/v3/device/windows-agent.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
import { testConfig } from "../../tests/helpers/config.js";

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-p07-"));
const workspace = path.join(root, "workspace");
const state = path.join(root, "state");

try {
  const config = testConfig(workspace);
  config.storage.directory = state;
  config.audit.directory = path.join(state, "audit");
  config.dependencies.ripgrepExecutable =
    "C:\\radlina-remote-mcp\\.runtime\\ripgrep-15.2.0-x86_64-pc-windows-msvc\\rg.exe";
  config.profiles.test!.roots = [workspace];
  config.profiles.test!.allowShell = true;
  config.profiles.test!.envAllowlist = [
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "COMSPEC",
    "WINDIR",
  ];

  await import("node:fs/promises").then(({ mkdir }) => mkdir(workspace, { recursive: true }));

  const store = new Store(state);
  const policyEngine = new PolicyEngine(config, {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  const filesystem = new FilesystemService(
    [workspace],
    config.policy.maxFileBytes,
    path.join(root, "trash"),
    false,
  );
  const processes = new ProcessManager(config, store, policyEngine);
  const searches = new SearchManager(config, store);

  const adapter = createWindowsPlatformAdapter({
    subject: "owner",
    profileName: "test",
    profile: config.profiles.test!,
    filesystem,
    processes,
    searches,
    agentVersion: "3.0.0-alpha.1",
    readiness: async () => ({ ready: true, detail: "p07-acceptance" }),
    scheduleRestart: async () => undefined,
  });

  const secret = Buffer.from("radlina-p07-dpapi");
  const protectedSecret = await adapter.secrets.protect(secret);
  const restoredSecret = await adapter.secrets.unprotect(protectedSecret);
  const dpapiRoundTrip =
    Buffer.from(restoredSecret).equals(secret) && !Buffer.from(protectedSecret).equals(secret);

  const filePath = path.join(workspace, "acceptance.txt");
  await adapter.filesystem.writeFile(
    filePath,
    Buffer.from("radlina-p07-search-marker\n", "utf8"),
    true,
  );
  const fileInfo = await adapter.filesystem.getFileInfo(filePath);
  const fileBytes = await adapter.filesystem.readFile(filePath, 0, 4096);
  const directoryEntries = await adapter.filesystem.listDirectory(workspace);

  const processHandle = await adapter.process.start({
    executable: "cmd.exe",
    args: ["/d", "/s", "/c", "echo radlina-p07-process"],
    cwd: workspace,
    timeoutMs: 10_000,
  });
  let processSnapshot = await adapter.process.read(processHandle.sessionId);
  for (let attempt = 0; attempt < 100 && processSnapshot.status === "running"; attempt += 1) {
    await delay(50);
    processSnapshot = await adapter.process.read(
      processHandle.sessionId,
      processSnapshot.outputCursor,
    );
  }

  const searchHandle = await adapter.search.start({
    root: workspace,
    pattern: "radlina-p07-search-marker",
    mode: "content",
    caseSensitive: true,
    literal: true,
    maxResults: 20,
  });
  let searchSnapshot = await adapter.search.status(searchHandle.searchId);
  for (let attempt = 0; attempt < 100 && searchSnapshot.status === "running"; attempt += 1) {
    await delay(50);
    searchSnapshot = await adapter.search.status(searchHandle.searchId);
  }
  const searchResults = await adapter.search.results(searchHandle.searchId);

  const registry = new CapabilityRegistry();
  registry.register({
    id: "radlina.device",
    version: "3.0.0",
    description: "P07 real Windows agent acceptance",
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

  const capabilityRuntime = new V3CapabilityRuntime(
    registry,
    new V3ExecutionPolicyGuard(policyEngine),
    {
      record: async (input) => sha256(canonicalJson(input)),
    },
    new HmacDistributedAuditSigner(Buffer.alloc(32, 23)),
  );

  const agent = new WindowsDeviceAgent(adapter, registry, capabilityRuntime, {
    deviceId: "windows-main",
    tags: ["primary", "p07-accepted"],
    trustState: "trusted",
    identity: {
      deviceId: "windows-main",
      agentInstanceId: "e8fe5d2a-a9e2-4c11-a9ea-7ab4d29557ad",
      agentVersion: "3.0.0-alpha.1",
      publicKeyFingerprint: "a".repeat(64),
      enrolledAt: "2026-10-07T22:00:00+03:00",
    },
  });
  const hello = await agent.hello();

  const auth: AuthInfo = {
    token: "p07-token",
    clientId: "p07-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  const input = {};
  const execution = await agent.execute(
    {
      requestId: "4bc54b5e-041b-4b1f-84d4-7eed90ebf234",
      workflowExecutionId: "wf-p07",
      nodeId: "health",
      attempt: 1,
      targetDeviceId: "windows-main",
      capability: "device.health",
      input,
      inputSha256: sha256(canonicalJson(input)),
      timeoutMs: 5_000,
      globalCorrelationId: "corr-p07",
      traceId: "trace-p07",
    },
    {
      auth,
      subject: "owner",
      profile: "test",
      isCancelled: () => false,
    },
  );

  const deviceInfo = await adapter.deviceInfo.getDeviceInfo();
  const acceptance =
    process.platform === "win32" &&
    deviceInfo.platform === "windows" &&
    deviceInfo.hostname.toLowerCase() === "laptop-13qineif" &&
    dpapiRoundTrip &&
    fileInfo.kind === "file" &&
    Buffer.from(fileBytes).toString("utf8").includes("radlina-p07-search-marker") &&
    directoryEntries.includes("acceptance.txt") &&
    processSnapshot.status === "complete" &&
    processSnapshot.exitCode === 0 &&
    searchSnapshot.status === "complete" &&
    searchResults.some((entry) => JSON.stringify(entry).includes("radlina-p07-search-marker")) &&
    hello.descriptor.deviceId === "windows-main" &&
    hello.descriptor.platform === "windows" &&
    execution.ok &&
    execution.receipt.resolvedDeviceId === "windows-main" &&
    execution.receipt.terminalState === "completed";

  await searches.shutdown();
  await processes.shutdown();
  store.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        deviceId: "windows-main",
        filePath,
        process: "cmd.exe",
        searchPattern: "radlina-p07-search-marker",
      },
      runtime: {
        adapter: "createWindowsPlatformAdapter",
        filesystem: "FilesystemService",
        process: "ProcessManager",
        search: "SearchManager+ripgrep",
        secrets: "Windows DPAPI LocalMachine",
        agent: "WindowsDeviceAgent+V3CapabilityRuntime",
      },
      execution: {
        hostname: deviceInfo.hostname,
        dpapiRoundTrip,
        fileKind: fileInfo.kind,
        directoryEntries,
        processStatus: processSnapshot.status,
        processExitCode: processSnapshot.exitCode,
        searchStatus: searchSnapshot.status,
        searchResultCount: searchResults.length,
        helloDeviceId: hello.descriptor.deviceId,
        capabilityExecutionOk: execution.ok,
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
