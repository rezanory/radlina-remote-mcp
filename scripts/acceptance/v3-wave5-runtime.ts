import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { FilesystemArtifactBus } from "../../src/v3/artifact/bus.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { DeviceRouter } from "../../src/v3/device/router.js";
import { PluginRuntime, type PluginManifest } from "../../src/v3/plugin/runtime.js";
import {
  ProcessIsolatedPluginHostFactory,
  type PluginSourceResolver,
} from "../../src/v3/plugin/process-host.js";
import type { WorkflowDefinition } from "../../src/v3/workflow/contracts.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { WorkflowRecoveryEngine } from "../../src/v3/workflow/recovery.js";
import { WorkflowTriggerRuntime } from "../../src/v3/workflow/triggers.js";
import { WorktreeRuntime, type GitWorktreePort } from "../../src/v3/worktrees/runtime.js";

const execFileAsync = promisify(execFile);

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }

  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

async function git(args: string[], cwd?: string): Promise<string> {
  const result = await execFileAsync("git", args, {
    cwd,
    windowsHide: true,
    timeout: 30_000,
  });
  return result.stdout.trim();
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-wave5-"));

try {
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 13));
  const artifacts = new FilesystemArtifactBus(path.join(root, "artifacts"));

  const recoveryDefinition: WorkflowDefinition = {
    workflowId: "wave5.recovery",
    definitionVersion: "1.0.0",
    title: "Wave5 recovery acceptance",
    nodes: [
      {
        id: "recoverable",
        capability: "device.health",
        input: { probe: true },
        dependsOn: [],
        target: { deviceId: "windows-main" },
        maxAttempts: 2,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "device.health/v1",
          artifactMode: "inline",
          maxBytes: 4_096,
        },
      },
    ],
  };

  const workflowStore = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  await workflowStore.create("wf-recovery", "owner", "idem-recovery", recoveryDefinition);
  workflowStore.transitionWorkflow("wf-recovery", "running");
  workflowStore.transitionNode("wf-recovery", "recoverable", "ready");
  workflowStore.transitionNode("wf-recovery", "recoverable", "running");

  const recovery = new WorkflowRecoveryEngine(
    workflowStore,
    { lookup: async () => undefined },
    { isIdempotent: () => true },
  );
  const recoveryActions = await recovery.reconcileRunning("wf-recovery", [
    { nodeId: "recoverable", attempt: 1 },
  ]);
  const interruptedStatus = workflowStore.snapshot("wf-recovery").nodes[0]?.status ?? null;
  await recovery.resumeNode("wf-recovery", "recoverable", 1);
  const resumedStatus = workflowStore.snapshot("wf-recovery").nodes[0]?.status ?? null;

  const nonIdempotentStore = new WorkflowSqliteStore(
    path.join(root, "workflow-non-idempotent.sqlite3"),
    new Codec(),
  );
  await nonIdempotentStore.create("wf-unsafe", "owner", "idem-unsafe", recoveryDefinition);
  nonIdempotentStore.transitionWorkflow("wf-unsafe", "running");
  nonIdempotentStore.transitionNode("wf-unsafe", "recoverable", "ready");
  nonIdempotentStore.transitionNode("wf-unsafe", "recoverable", "running");
  const unsafeRecovery = new WorkflowRecoveryEngine(
    nonIdempotentStore,
    { lookup: async () => undefined },
    { isIdempotent: () => false },
  );
  await unsafeRecovery.reconcileRunning("wf-unsafe", [{ nodeId: "recoverable", attempt: 1 }]);
  let unsafeRetryBlocked = false;
  try {
    await unsafeRecovery.resumeNode("wf-unsafe", "recoverable", 1);
  } catch {
    unsafeRetryBlocked = true;
  }

  let triggerSubmitCount = 0;
  const triggerStore = new WorkflowSqliteStore(
    path.join(root, "trigger-workflows.sqlite3"),
    new Codec(),
  );
  const triggers = new WorkflowTriggerRuntime(path.join(root, "triggers.sqlite3"), {
    submit: async ({ subject, idempotencyKey, workflow }) => {
      triggerSubmitCount += 1;
      const executionId = "wf-triggered";
      await triggerStore.create(executionId, subject, idempotencyKey, workflow);
      return executionId;
    },
  });
  const triggerInput = {
    source: "acceptance",
    eventId: "event-wave5",
    subject: "owner",
    workflow: recoveryDefinition,
    payload: { accepted: true },
  };
  const firstTrigger = await triggers.accept(triggerInput);
  const replayTrigger = await triggers.accept(triggerInput);

  const devices = [
    parseDeviceDescriptor({
      deviceId: "windows-main",
      hostname: "LAPTOP-13QINEIF",
      platform: "windows",
      architecture: "x64",
      agentVersion: "3.0.0-alpha.1",
      status: "online",
      lastSeen: "2026-10-07T18:00:00+03:00",
      capabilities: ["device.health"],
      tags: ["primary"],
      trustState: "trusted",
      health: "healthy",
    }),
    parseDeviceDescriptor({
      deviceId: "macbook-main",
      hostname: "MacBook",
      platform: "macos",
      architecture: "arm64",
      agentVersion: "3.0.0-alpha.1",
      status: "online",
      lastSeen: "2026-10-07T18:00:00+03:00",
      capabilities: ["device.health"],
      tags: ["primary", "apple"],
      trustState: "trusted",
      health: "healthy",
    }),
  ];
  const router = new DeviceRouter({
    get: (deviceId) => devices.find((device) => device.deviceId === deviceId),
    list: () => [...devices],
  });
  const macRoute = router.route({ platform: "macos" }, "device.health");
  let exactFailoverBlocked = false;
  const unavailableExact = new DeviceRouter({
    get: (deviceId) =>
      deviceId === "windows-main"
        ? parseDeviceDescriptor({ ...devices[0]!, status: "offline" })
        : devices.find((device) => device.deviceId === deviceId),
    list: () => [...devices],
  });
  try {
    unavailableExact.route({ deviceId: "windows-main" }, "device.health");
  } catch {
    exactFailoverBlocked = true;
  }

  const repo = path.join(root, "repo");
  const workspaceRoot = path.join(root, "workspaces");
  await git(["init", repo]);
  await git(["-C", repo, "config", "user.email", "acceptance@radlina.local"]);
  await git(["-C", repo, "config", "user.name", "Radlina Acceptance"]);
  await writeFile(path.join(repo, "README.md"), "wave5\n", "utf8");
  await git(["-C", repo, "add", "README.md"]);
  await git(["-C", repo, "commit", "-m", "seed"]);
  const baseRef = await git(["-C", repo, "rev-parse", "HEAD"]);

  const gitPort: GitWorktreePort = {
    create: async ({ repositoryPath, targetPath, branchName, baseRef: base }) => {
      await git(["-C", repositoryPath, "worktree", "add", "-b", branchName, targetPath, base]);
    },
    release: async (repositoryPath, targetPath) => {
      await git(["-C", repositoryPath, "worktree", "remove", targetPath]);
    },
    status: async (targetPath) => ({
      clean: (await git(["-C", targetPath, "status", "--porcelain"])) === "",
      head: await git(["-C", targetPath, "rev-parse", "HEAD"]),
    }),
  };

  const worktrees = new WorktreeRuntime(
    workspaceRoot,
    gitPort,
    {
      authorize: () => ({ allowed: true, reason: "acceptance" }),
    },
    artifacts,
    signer,
    () => "2026-10-07T18:00:00+03:00",
  );
  const worktreeResult = await worktrees.create({
    workspaceId: "wf-wave5-node-worktree",
    workflowExecutionId: "wf-wave5",
    nodeId: "worktree",
    deviceId: "windows-main",
    repositoryPath: repo,
    branchName: "acceptance/wave5",
    baseRef,
    globalCorrelationId: "corr-worktree",
    traceId: "trace-worktree",
  });
  const worktreeHead = await git(["-C", worktreeResult.targetPath, "rev-parse", "HEAD"]);
  const worktreeReceiptValid = worktrees.verifyReceipt(worktreeResult.receipt);
  await worktrees.release({
    workspaceId: "wf-wave5-node-worktree",
    workflowExecutionId: "wf-wave5",
    nodeId: "worktree",
    deviceId: "windows-main",
    repositoryPath: repo,
  });

  const registry = new CapabilityRegistry();
  const pluginManifest: PluginManifest = {
    pluginId: "echo-plugin",
    version: "1.0.0",
    description: "Wave5 isolated echo plugin",
    capabilities: [
      {
        id: "echo-plugin.echo",
        version: "1.0.0",
        description: "Echo",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
      },
    ],
  };
  const pluginSource =
    "async ({ payload, context }) => ({ payload, subject: context.subject, childPid: process.pid, fsReadAllowed: process.permission?.has('fs.read') ?? null })";
  const resolver: PluginSourceResolver = {
    resolve: async () => pluginSource,
  };
  const plugins = new PluginRuntime(
    registry,
    new ProcessIsolatedPluginHostFactory(process.execPath, resolver, 5_000),
    artifacts,
    signer,
    () => "2026-10-07T18:00:01+03:00",
  );
  const loadedPlugin = await plugins.load(pluginManifest);
  const pluginProvider = registry.resolve("echo-plugin.echo");
  const pluginResult = (await pluginProvider.execute(
    {
      subject: "owner",
      profile: "test",
      auth: undefined,
      isCancelled: () => false,
    },
    { value: 5 },
  )) as {
    payload: { value: number };
    subject: string;
    childPid: number;
    fsReadAllowed: boolean | null;
  };
  const pluginReceiptValid = plugins.verifyLoadReceipt(loadedPlugin.receipt);
  await plugins.unload("echo-plugin");

  const acceptance =
    recoveryActions[0]?.action === "interrupted-unknown-outcome" &&
    interruptedStatus === "interrupted" &&
    resumedStatus === "ready" &&
    unsafeRetryBlocked &&
    firstTrigger.executionId === "wf-triggered" &&
    firstTrigger.replayed === false &&
    replayTrigger.replayed === true &&
    triggerSubmitCount === 1 &&
    macRoute.device.deviceId === "macbook-main" &&
    exactFailoverBlocked &&
    worktreeHead === baseRef &&
    worktreeReceiptValid &&
    pluginResult.payload.value === 5 &&
    pluginResult.subject === "owner" &&
    pluginResult.childPid !== process.pid &&
    pluginResult.fsReadAllowed === false &&
    pluginReceiptValid &&
    plugins.list().length === 0;

  workflowStore.close();
  nonIdempotentStore.close();
  triggerStore.close();
  triggers.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        recoveryExecutionId: "wf-recovery",
        triggerEventId: "event-wave5",
        routeSelector: { platform: "macos" },
        workspaceId: "wf-wave5-node-worktree",
        pluginId: "echo-plugin",
      },
      runtime: {
        recovery: "WorkflowRecoveryEngine",
        triggers: "WorkflowTriggerRuntime",
        router: "DeviceRouter",
        worktrees: "WorktreeRuntime+real git worktree",
        plugins: "PluginRuntime+ProcessIsolatedPluginHostFactory",
      },
      execution: {
        recoveryAction: recoveryActions[0]?.action,
        unsafeRetryBlocked,
        triggerSubmitCount,
        triggerReplay: replayTrigger.replayed,
        routedDeviceId: macRoute.device.deviceId,
        exactFailoverBlocked,
        worktreeHead,
        pluginChildPid: pluginResult.childPid,
        pluginFilesystemReadAllowed: pluginResult.fsReadAllowed,
      },
      output: {
        worktreeReceiptArtifactId: worktreeResult.receiptArtifact.artifactId,
        worktreeReceiptValid,
        pluginLoadArtifactId: loadedPlugin.receiptArtifact.artifactId,
        pluginReceiptValid,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
