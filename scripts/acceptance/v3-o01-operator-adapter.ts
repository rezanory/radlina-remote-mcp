import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { V3CapabilityRuntime } from "../../src/v3/capability/runtime.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { DeviceRouter } from "../../src/v3/device/router.js";
import { SmartOperatorAdapter } from "../../src/v3/operator/adapter.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
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

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-o01-"));
const bindingDb = new DatabaseSync(":memory:");

try {
  const device = parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "O01-Windows",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: new Date().toISOString(),
    capabilities: ["device.health", "process.exec"],
    tags: ["primary"],
    trustState: "trusted",
    health: "healthy",
  });

  const capabilities = new CapabilityRegistry();
  capabilities.register({
    id: "radlina.o01-acceptance",
    version: "1.0.0",
    description: "O01 acceptance capabilities",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async (_context, input) => ({
          status: "healthy",
          input,
        }),
      },
      {
        id: "process.exec",
        version: "1.0.0",
        description: "bounded acceptance execution",
        requiredScope: "process:execute",
        risk: "high",
        readOnly: false,
        idempotent: false,
        execute: async (_context, input) => ({
          status: "complete",
          input,
        }),
      },
    ],
  });

  const config = testConfig(root);
  const policyEngine = new PolicyEngine(config, {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  const executionPolicy = new V3ExecutionPolicyGuard(policyEngine);
  const capabilityRuntime = new V3CapabilityRuntime(
    capabilities,
    executionPolicy,
    { record: async (input) => sha256(canonicalJson(input)) },
    new HmacDistributedAuditSigner(Buffer.alloc(32, 31)),
  );
  const router = new DeviceRouter({
    get: (deviceId) => (deviceId === "windows-main" ? device : undefined),
    list: () => [device],
  });

  const auth: AuthInfo = {
    token: "o01-acceptance-token",
    clientId: "o01-client",
    scopes: ["device:read", "process:execute"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };

  const dispatch: ExecutionDispatchPort = {
    execute: async ({ workflowExecutionId, subject, node, attempt }) => {
      const route = router.route(node.target, node.capability);
      const result = await capabilityRuntime.execute(
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
          agentInstanceId: "d2679fe7-98de-4428-b3ad-599e4e27530a",
          isCancelled: () => false,
        },
      );
      return result.ok
        ? { receipt: result.receipt, output: result.result }
        : { receipt: result.receipt, output: result.error };
    },
    cancel: async () => undefined,
  };

  const workflowStore = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  const scheduler = new WorkflowScheduler(workflowStore);
  const recovery = new WorkflowRecoveryEngine(
    workflowStore,
    {
      lookup: async (executionId, nodeId, attempt) =>
        workflowStore.attemptReceipt(executionId, nodeId, attempt),
    },
    {
      isIdempotent: (capability) => capabilities.resolve(capability).idempotent,
    },
  );
  const telemetry = new InMemoryWorkflowTelemetry();
  const workflow = new CanonicalWorkflowRuntime(
    workflowStore,
    scheduler,
    recovery,
    telemetry,
    dispatch,
  );

  const operator = new SmartOperatorAdapter(
    bindingDb,
    policyEngine,
    capabilities,
    workflow,
    workflowStore,
    { deviceId: "windows-main" },
  );

  const plan = {
    title: "O01 acceptance plan",
    steps: [
      {
        id: "health",
        capability: "device.health",
        input: { marker: "secret-input-marker" },
        maxAttempts: 1,
      },
      {
        id: "exec",
        capability: "process.exec",
        input: { marker: "execution-marker" },
        maxAttempts: 1,
      },
    ],
  };

  const submitted = await operator.submit(auth, "owner", "test", plan, "o01-idempotency");
  const replay = await operator.submit(auth, "owner", "test", plan, "o01-idempotency");

  const run = await workflow.runUntilIdle(submitted.jobId);
  const projected = operator.status("owner", submitted.jobId);
  const recent = operator.recent("owner", 10);
  const bound = operator.context("owner", submitted.jobId);
  const rawBinding = bindingDb
    .prepare("SELECT * FROM v3_operator_bindings WHERE job_id=?")
    .get(submitted.jobId) as Record<string, unknown>;
  const encodedBinding = JSON.stringify(rawBinding);

  const acceptance =
    submitted.replayed === false &&
    replay.replayed === true &&
    replay.jobId === submitted.jobId &&
    run.snapshot.status === "completed" &&
    run.dispatchedNodes === 2 &&
    projected.status === "completed" &&
    projected.steps.length === 2 &&
    projected.steps.every(
      (step) =>
        step.status === "completed" &&
        step.attempts === 1 &&
        step.receipt?.resolvedDeviceId === "windows-main",
    ) &&
    recent.length === 1 &&
    bound.profile === "test" &&
    bound.clientId === "o01-client" &&
    bound.scopes.join(",") === "device:read,process:execute" &&
    !encodedBinding.includes("secret-input-marker") &&
    !encodedBinding.includes("o01-acceptance-token");

  workflowStore.close();
  bindingDb.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        title: plan.title,
        legacySteps: plan.steps.map((step) => step.id),
        idempotencyKey: "o01-idempotency",
      },
      runtime: {
        adapter: "SmartOperatorAdapter",
        workflow: "CanonicalWorkflowRuntime",
        scheduler: "WorkflowScheduler",
        dispatch: "DeviceRouter+V3CapabilityRuntime",
      },
      execution: {
        jobId: submitted.jobId,
        replayed: replay.replayed,
        dispatchedNodes: run.dispatchedNodes,
        workflowStatus: run.snapshot.status,
      },
      output: {
        projectedStatus: projected.status,
        projectedSteps: projected.steps.map((step) => [
          step.id,
          step.status,
          step.attempts,
          step.receipt?.resolvedDeviceId ?? null,
        ]),
        durableBindingContainsInputPlaintext: encodedBinding.includes("secret-input-marker"),
        durableBindingContainsToken: encodedBinding.includes("o01-acceptance-token"),
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
