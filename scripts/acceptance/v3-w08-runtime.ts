import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../src/v3/capability/runtime.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { DeviceRouter } from "../../src/v3/device/router.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
import type { WorkflowDefinition } from "../../src/v3/workflow/contracts.js";
import { InMemoryWorkflowTelemetry } from "../../src/v3/workflow/observability.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { WorkflowRecoveryEngine } from "../../src/v3/workflow/recovery.js";
import {
  CanonicalWorkflowRuntime,
  type ExecutionDispatchPort,
} from "../../src/v3/workflow/runtime.js";
import { WorkflowScheduler } from "../../src/v3/workflow/scheduler.js";
import { testConfig } from "../../tests/helpers/config.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }

  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-w08-"));

try {
  const device = parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "LAPTOP-13QINEIF",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: new Date().toISOString(),
    capabilities: ["device.health"],
    tags: ["primary"],
    trustState: "trusted",
    health: "healthy",
  });

  const router = new DeviceRouter({
    get: (deviceId) => (deviceId === device.deviceId ? device : undefined),
    list: () => [device],
  });

  const capabilities = new CapabilityRegistry();
  capabilities.register({
    id: "radlina.device",
    version: "3.0.0",
    description: "W08 acceptance device",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "Return acceptance health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async (_context, input) => ({
          status: "healthy",
          input,
          executedOn: "windows-main",
        }),
      },
    ],
  });

  const auth: AuthInfo = {
    token: "w08-token",
    clientId: "w08-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };

  const config = testConfig(root);
  const policy = new V3ExecutionPolicyGuard(
    new PolicyEngine(config, {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    }),
  );
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 17));
  const capabilityRuntime = new V3CapabilityRuntime(
    capabilities,
    policy,
    {
      record: async (input) => sha256(canonicalJson(input)),
    },
    signer,
  );

  const dispatch: ExecutionDispatchPort = {
    execute: async ({ workflowExecutionId, subject, node, attempt }) => {
      const route = router.route(node.target, node.capability);
      const outcome = await capabilityRuntime.execute(
        {
          requestId: crypto.randomUUID(),
          workflowExecutionId,
          nodeId: node.id,
          attempt,
          targetDeviceId: route.device.deviceId,
          capability: node.capability,
          input: node.input,
          inputSha256: sha256(canonicalJson(node.input)),
          timeoutMs: node.timeoutMs,
          globalCorrelationId: `corr-${node.id}-${attempt}`,
          traceId: `trace-${node.id}-${attempt}`,
        },
        {
          auth,
          subject,
          profile: "test",
          device: route.device,
          agentInstanceId: "4e8a58e7-2c13-42c9-8848-1d99d290e90f",
          isCancelled: () => false,
        },
      );
      return outcome.ok
        ? { receipt: outcome.receipt, output: outcome.result }
        : { receipt: outcome.receipt, output: outcome.error };
    },
    cancel: async () => undefined,
  };

  const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  const scheduler = new WorkflowScheduler(store);
  const recovery = new WorkflowRecoveryEngine(
    store,
    {
      lookup: async (workflowExecutionId, nodeId, attempt) =>
        store.attemptReceipt(workflowExecutionId, nodeId, attempt),
    },
    {
      isIdempotent: (capability) => capabilities.resolve(capability).idempotent,
    },
  );
  const telemetry = new InMemoryWorkflowTelemetry();
  const runtime = new CanonicalWorkflowRuntime(
    store,
    scheduler,
    recovery,
    telemetry,
    dispatch,
    () => Date.now(),
    () => "wf-w08",
  );

  const node = (id: string, dependsOn: string[] = []) => ({
    id,
    capability: "device.health",
    input: { id },
    dependsOn,
    target: { deviceId: "windows-main" as const },
    maxAttempts: 2,
    timeoutMs: 5_000,
    executionPolicy: {
      failureMode: "fail-workflow" as const,
      allowDynamicReroute: false,
      unknownOutcome: "manual-resume" as const,
    },
    expectedOutput: {
      contractId: "device.health/v1",
      artifactMode: "inline" as const,
      maxBytes: 16_384,
    },
  });

  const definition: WorkflowDefinition = {
    workflowId: "w08.acceptance",
    definitionVersion: "1.0.0",
    title: "W08 canonical runtime acceptance",
    nodes: [node("health-a"), node("health-b"), node("join", ["health-a", "health-b"])],
  };

  const submitted = await runtime.submit({
    executionId: "wf-w08",
    subject: "owner",
    idempotencyKey: "w08-idempotency",
    definition,
  });
  const replay = await runtime.submit({
    subject: "owner",
    idempotencyKey: "w08-idempotency",
    definition,
  });
  const result = await runtime.runUntilIdle(submitted.executionId);
  const receipts = result.snapshot.nodes.map((item) =>
    store.attemptReceipt(result.executionId, item.id, item.attempts),
  );
  const events = store.events(result.executionId) as Array<{ kind: string }>;
  const metrics = telemetry.snapshot();

  const acceptance =
    submitted.replayed === false &&
    replay.replayed === true &&
    replay.executionId === "wf-w08" &&
    result.snapshot.status === "completed" &&
    result.dispatchedNodes === 3 &&
    result.snapshot.nodes.every((item) => item.status === "completed" && item.attempts === 1) &&
    receipts.every(
      (receipt) =>
        receipt?.terminalState === "completed" && receipt.resolvedDeviceId === "windows-main",
    ) &&
    events.filter((event) => event.kind === "node.receipt").length === 3 &&
    metrics.counters["node.dispatched"] === 3 &&
    metrics.counters["node.completed"] === 3 &&
    metrics.counters["workflow.completed"] === 1;

  store.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        workflowExecutionId: "wf-w08",
        nodes: ["health-a", "health-b", "join"],
      },
      runtime: {
        workflow: "CanonicalWorkflowRuntime",
        scheduler: "WorkflowScheduler",
        dispatch: "DeviceRouter+V3CapabilityRuntime",
        persistence: "WorkflowSqliteStore",
      },
      execution: {
        dispatchedNodes: result.dispatchedNodes,
        cycles: result.cycles,
        workflowStatus: result.snapshot.status,
        nodeStates: result.snapshot.nodes.map((item) => [item.id, item.status, item.attempts]),
      },
      output: {
        durableReceipts: receipts.length,
        durableReceiptEvents: events.filter((event) => event.kind === "node.receipt").length,
        telemetry: metrics.counters,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
