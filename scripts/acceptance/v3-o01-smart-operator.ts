import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { SmartOperatorAdapter } from "../../src/v3/operator/adapter.js";
import type { DispatchReceipt } from "../../src/v3/workflow/contracts.js";
import { InMemoryWorkflowTelemetry } from "../../src/v3/workflow/observability.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { WorkflowRecoveryEngine } from "../../src/v3/workflow/recovery.js";
import {
  CanonicalWorkflowRuntime,
  type WorkflowDispatchInput,
} from "../../src/v3/workflow/runtime.js";
import { WorkflowScheduler } from "../../src/v3/workflow/scheduler.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value, "utf8").toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-o01-"));
try {
  const store = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  const scheduler = new WorkflowScheduler(store);
  const recovery = new WorkflowRecoveryEngine(
    store,
    { lookup: async () => undefined },
    { isIdempotent: () => true },
  );
  const telemetry = new InMemoryWorkflowTelemetry();
  const dispatchOrder: string[] = [];

  const workflow = new CanonicalWorkflowRuntime(store, scheduler, recovery, telemetry, {
    execute: async (input: WorkflowDispatchInput) => {
      dispatchOrder.push(input.node.id);
      const receipt: DispatchReceipt = {
        workflowExecutionId: input.workflowExecutionId,
        nodeId: input.node.id,
        attempt: input.attempt,
        resolvedDeviceId: "windows-main",
        capability: input.node.capability,
        inputSha256: sha256(canonicalJson(input.node.input)),
        startedAt: new Date().toISOString(),
        terminalState: "completed",
        outputSha256: sha256(canonicalJson({ ok: true, nodeId: input.node.id })),
        localAuditReceiptHash: "a".repeat(64),
        globalCorrelationId: "corr-o01",
        traceId: "trace-o01",
      };
      return { receipt, output: { ok: true } };
    },
  });

  const launched: Array<Promise<unknown>> = [];
  const adapter = new SmartOperatorAdapter(
    workflow,
    {
      launch: (executionId) => {
        launched.push(workflow.runUntilIdle(executionId));
      },
    },
    { isIdempotent: () => true },
    { defaultTarget: { deviceId: "windows-main" } },
    () => "wf-o01",
  );

  const submitted = await adapter.submit(undefined, "owner", "radlina", {
    title: "O01 real acceptance",
    steps: [
      { id: "health-a", capability: "device.health", input: { sequence: 1 }, maxAttempts: 2 },
      { id: "health-b", capability: "device.health", input: { sequence: 2 }, maxAttempts: 1 },
    ],
  });
  await Promise.all(launched);
  const status = await adapter.status("owner", submitted.jobId);

  const acceptance =
    submitted.jobId === "wf-o01" &&
    submitted.status === "queued" &&
    status.status === "completed" &&
    status.steps.every((step) => step.status === "completed") &&
    dispatchOrder.join(",") === "health-a,health-b";

  store.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        legacyPlanSteps: ["health-a", "health-b"],
        defaultDeviceId: "windows-main",
      },
      runtime: {
        adapter: "SmartOperatorAdapter",
        workflowAuthority: "CanonicalWorkflowRuntime",
        scheduler: "WorkflowScheduler",
        persistence: "WorkflowSqliteStore",
      },
      execution: {
        jobId: submitted.jobId,
        dispatchOrder,
        finalStatus: status.status,
        stepStates: status.steps.map((step) => [step.id, step.status]),
      },
      output: {
        jobIdIsCanonicalExecutionId: submitted.jobId === "wf-o01",
        workflowCompleted: status.status === "completed",
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
