import type { AuthInfo } from "@modelcontextprotocol/server";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import { CapabilityRegistry } from "../../../src/components/registry.js";
import { PolicyEngine } from "../../../src/policy/engine.js";
import { SmartOperatorAdapter, type OperatorWorkflowPort } from "../../../src/v3/operator/adapter.js";
import type {
  DispatchReceipt,
  WorkflowDefinition,
  WorkflowSnapshot,
} from "../../../src/v3/workflow/contracts.js";
import { testConfig } from "../../helpers/config.js";

const jobId = "11111111-1111-4111-8111-111111111111";
const hash = "a".repeat(64);

const auth: AuthInfo = {
  token: "never-persist-this-token",
  clientId: "operator-client",
  scopes: ["device:read", "process:execute"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

class FakeWorkflow implements OperatorWorkflowPort {
  readonly submissions: WorkflowDefinition[] = [];
  private seen = false;
  snapshot: WorkflowSnapshot = {
    executionId: jobId,
    subject: "owner",
    status: "queued",
    definitionSha256: hash,
    nodes: [
      { id: "health", status: "pending", attempts: 0, maxAttempts: 1 },
      { id: "exec", status: "pending", attempts: 0, maxAttempts: 1 },
    ],
  };

  async submit(input: {
    executionId?: string;
    subject: string;
    idempotencyKey: string;
    definition: WorkflowDefinition;
  }) {
    this.submissions.push(input.definition);
    const replayed = this.seen;
    this.seen = true;
    return { executionId: jobId, replayed };
  }

  status() {
    return this.snapshot;
  }

  async resumeNode(_executionId: string, nodeId: string) {
    this.snapshot = {
      ...this.snapshot,
      status: "queued",
      nodes: this.snapshot.nodes.map((node) =>
        node.id === nodeId ? { ...node, status: "ready" } : node,
      ),
    };
    return this.snapshot;
  }

  async cancel() {
    this.snapshot = {
      ...this.snapshot,
      status: "cancelled",
      nodes: this.snapshot.nodes.map((node) =>
        node.status === "completed" ? node : { ...node, status: "cancelled" },
      ),
    };
    return this.snapshot;
  }
}

function registry() {
  const value = new CapabilityRegistry();
  value.register({
    id: "radlina.operator-test",
    version: "1.0.0",
    description: "test",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async () => ({ ok: true }),
      },
      {
        id: "process.exec",
        version: "1.0.0",
        description: "exec",
        requiredScope: "process:execute",
        risk: "high",
        readOnly: false,
        idempotent: false,
        execute: async () => ({ ok: true }),
      },
    ],
  });
  return value;
}

function adapter(receipt?: DispatchReceipt) {
  const db = new DatabaseSync(":memory:");
  const workflow = new FakeWorkflow();
  const capabilities = registry();
  const policy = new PolicyEngine(testConfig("C:\\workspace"), {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  return {
    db,
    workflow,
    adapter: new SmartOperatorAdapter(
      db,
      policy,
      capabilities,
      workflow,
      { attemptReceipt: () => receipt },
      { deviceId: "windows-main" },
    ),
  };
}

function plan() {
  return {
    title: "Legacy operator plan",
    steps: [
      {
        id: "health",
        capability: "device.health",
        input: { secret: "secret-value" },
        maxAttempts: 1,
      },
      {
        id: "exec",
        capability: "process.exec",
        input: { executable: "cmd.exe" },
        maxAttempts: 1,
      },
    ],
  };
}

describe("V3 SmartOperatorAdapter", () => {
  it("translates a legacy ordered plan into the canonical sequential DAG", () => {
    const value = adapter();
    const definition = value.adapter.translate(plan());
    expect(definition.nodes.map((node) => [node.id, node.dependsOn])).toEqual([
      ["health", []],
      ["exec", ["health"]],
    ]);
    expect(definition.nodes.every((node) => node.target.deviceId === "windows-main")).toBe(true);
    value.db.close();
  });

  it("submits to the canonical runtime and persists only compatibility metadata", async () => {
    const value = adapter();
    await expect(
      value.adapter.submit(auth, "owner", "test", plan(), "idem-1"),
    ).resolves.toEqual({
      jobId,
      status: "queued",
      steps: 2,
      replayed: false,
    });

    const row = value.db
      .prepare("SELECT * FROM v3_operator_bindings WHERE job_id=?")
      .get(jobId) as Record<string, unknown>;
    const encoded = JSON.stringify(row);
    expect(encoded).not.toContain("secret-value");
    expect(encoded).not.toContain("never-persist-this-token");
    expect(row["client_id"]).toBe("operator-client");
    expect(JSON.parse(String(row["scopes_json"]))).toEqual(["device:read", "process:execute"]);
    value.db.close();
  });

  it("replays the same binding but rejects a profile change under the same idempotency key", async () => {
    const value = adapter();
    await value.adapter.submit(auth, "owner", "test", plan(), "idem-1");
    await expect(
      value.adapter.submit(auth, "owner", "test", plan(), "idem-1"),
    ).resolves.toMatchObject({ jobId, replayed: true });
    await expect(
      value.adapter.submit(auth, "owner", "other", plan(), "idem-1"),
    ).rejects.toThrow(/different profile/u);
    value.db.close();
  });

  it("rejects retry configuration for a non-idempotent legacy capability", async () => {
    const value = adapter();
    const unsafe = plan();
    unsafe.steps[1]!.maxAttempts = 2;
    await expect(
      value.adapter.submit(auth, "owner", "test", unsafe, "idem-unsafe"),
    ).rejects.toThrow(/must use maxAttempts=1/u);
    expect(value.workflow.submissions).toHaveLength(0);
    value.db.close();
  });

  it("projects canonical states and durable receipts into the legacy status shape", async () => {
    const receipt: DispatchReceipt = {
      workflowExecutionId: jobId,
      nodeId: "health",
      attempt: 1,
      resolvedDeviceId: "windows-main",
      capability: "device.health",
      inputSha256: hash,
      startedAt: "2026-10-08T00:00:00Z",
      terminalState: "completed",
      outputSha256: hash,
      localAuditReceiptHash: hash,
      globalCorrelationId: "corr",
      traceId: "trace",
    };
    const value = adapter(receipt);
    await value.adapter.submit(auth, "owner", "test", plan(), "idem-1");
    value.workflow.snapshot = {
      ...value.workflow.snapshot,
      status: "running",
      nodes: [
        { id: "health", status: "completed", attempts: 1, maxAttempts: 1 },
        { id: "exec", status: "ready", attempts: 0, maxAttempts: 1 },
      ],
    };

    const status = value.adapter.status("owner", jobId);
    expect(status.status).toBe("running");
    expect(status.steps).toEqual([
      expect.objectContaining({ id: "health", status: "completed", receipt }),
      expect.objectContaining({ id: "exec", status: "pending", receipt: null }),
    ]);
    expect(value.adapter.recent("owner", 10)).toHaveLength(1);
    expect(() => value.adapter.status("other", jobId)).toThrow(/not found/u);
    value.db.close();
  });

  it("binds resume/cancel to the original client scopes without owning execution", async () => {
    const value = adapter();
    await value.adapter.submit(auth, "owner", "test", plan(), "idem-1");
    value.workflow.snapshot = {
      ...value.workflow.snapshot,
      status: "interrupted",
      nodes: [
        { id: "health", status: "interrupted", attempts: 1, maxAttempts: 1 },
        { id: "exec", status: "blocked", attempts: 0, maxAttempts: 1 },
      ],
    };

    await expect(value.adapter.resume(auth, "owner", jobId)).resolves.toEqual({
      jobId,
      status: "queued",
    });
    await expect(
      value.adapter.cancel({ ...auth, clientId: "other-client" }, "owner", jobId),
    ).rejects.toThrow(/different OAuth client/u);
    await expect(value.adapter.cancel(auth, "owner", jobId)).resolves.toEqual({
      jobId,
      status: "cancelled",
      requested: true,
    });
    value.db.close();
  });
});
