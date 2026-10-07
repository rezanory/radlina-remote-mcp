import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { CapabilityRegistry } from "../../src/components/registry.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import {
  HmacDistributedAuditSigner,
  verifyDistributedAuditRecord,
} from "../../src/v3/audit/distributed.js";
import { FilesystemArtifactBus } from "../../src/v3/artifact/bus.js";
import { artifactReference } from "../../src/v3/artifact/contracts.js";
import { V3CapabilityRuntime } from "../../src/v3/capability/runtime.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
import type { WorkflowDefinition } from "../../src/v3/workflow/contracts.js";
import {
  InMemoryWorkflowTelemetry,
  WorkflowTraceTimer,
} from "../../src/v3/workflow/observability.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { WorkflowScheduler } from "../../src/v3/workflow/scheduler.js";
import { testConfig } from "../../tests/helpers/config.js";

class Codec implements WorkflowPayloadCodec {
  async encode(value: string): Promise<string> {
    return Buffer.from(value).toString("base64");
  }
  async decode(value: string): Promise<string> {
    return Buffer.from(value, "base64").toString("utf8");
  }
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-wave4-"));
try {
  const definition: WorkflowDefinition = {
    workflowId: "wave4.acceptance",
    definitionVersion: "1.0.0",
    title: "Wave4 execution acceptance",
    nodes: [
      {
        id: "health-a",
        capability: "device.health",
        input: { probe: "a" },
        dependsOn: [],
        target: { deviceId: "windows-main" },
        maxAttempts: 1,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "device.health/v1",
          artifactMode: "either",
          maxBytes: 65_536,
        },
      },
      {
        id: "health-b",
        capability: "device.health",
        input: { probe: "b" },
        dependsOn: [],
        target: { deviceId: "windows-main" },
        maxAttempts: 1,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "device.health/v1",
          artifactMode: "either",
          maxBytes: 65_536,
        },
      },
      {
        id: "join",
        capability: "device.health",
        input: { probe: "join" },
        dependsOn: ["health-a", "health-b"],
        target: { deviceId: "windows-main" },
        maxAttempts: 1,
        timeoutMs: 5_000,
        executionPolicy: {
          failureMode: "fail-workflow",
          allowDynamicReroute: false,
          unknownOutcome: "manual-resume",
        },
        expectedOutput: {
          contractId: "device.health/v1",
          artifactMode: "artifact",
          maxBytes: 65_536,
        },
      },
    ],
  };

  const workflowStore = new WorkflowSqliteStore(path.join(root, "workflow.sqlite3"), new Codec());
  await workflowStore.create("wf-wave4", "owner", "idem-wave4", definition);
  workflowStore.transitionWorkflow("wf-wave4", "running");
  const scheduler = new WorkflowScheduler(workflowStore);
  const firstDecision = await scheduler.reconcile("wf-wave4");

  const registry = new CapabilityRegistry();
  registry.register({
    id: "radlina.device",
    version: "3.0.0",
    description: "wave4 acceptance",
    capabilities: [
      {
        id: "device.health",
        version: "1.0.0",
        description: "health",
        requiredScope: "device:read",
        risk: "low",
        readOnly: true,
        idempotent: true,
        execute: async (_context, input) => ({ status: "healthy", input }),
      },
    ],
  });

  const device = parseDeviceDescriptor({
    deviceId: "windows-main",
    hostname: "LAPTOP-13QINEIF",
    platform: "windows",
    architecture: "x64",
    agentVersion: "3.0.0-alpha.1",
    status: "online",
    lastSeen: "2026-10-07T15:00:00+03:00",
    capabilities: ["device.health"],
    tags: ["primary"],
    trustState: "trusted",
    health: "healthy",
  });
  const auth: AuthInfo = {
    token: "wave4-token",
    clientId: "wave4-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 11));
  const capabilityRuntime = new V3CapabilityRuntime(
    registry,
    new V3ExecutionPolicyGuard(
      new PolicyEngine(testConfig(root), {
        killSwitch: () => false,
        emergencyReadOnly: () => false,
      }),
    ),
    {
      record: async (value) => sha256(canonicalJson(value)),
    },
    signer,
  );

  const telemetry = new InMemoryWorkflowTelemetry();
  const timer = new WorkflowTraceTimer(() => Date.now(), telemetry);
  const workflowDuration = timer.startWorkflow("wf-wave4");
  const outcomes = [];

  async function executeNode(nodeId: string) {
    const node = definition.nodes.find((candidate) => candidate.id === nodeId)!;
    workflowStore.transitionNode("wf-wave4", nodeId, "running");
    const nodeTimer = timer.startNode("wf-wave4", nodeId, "windows-main");
    const outcome = await capabilityRuntime.execute(
      {
        requestId: crypto.randomUUID(),
        workflowExecutionId: "wf-wave4",
        nodeId,
        attempt: 1,
        targetDeviceId: "windows-main",
        capability: node.capability,
        input: node.input,
        inputSha256: sha256(canonicalJson(node.input)),
        timeoutMs: node.timeoutMs,
        globalCorrelationId: `corr-${nodeId}`,
        traceId: `trace-${nodeId}`,
      },
      {
        auth,
        subject: "owner",
        profile: "test",
        device,
        agentInstanceId: "4c564052-c9d5-4d36-a991-d387b973c068",
        isCancelled: () => false,
      },
    );
    if (!outcome.ok) throw new Error(`capability execution failed: ${outcome.error.message}`);
    nodeTimer.complete();
    workflowStore.transitionNode("wf-wave4", nodeId, "completed");
    outcomes.push(outcome);
  }

  await Promise.all(firstDecision.ready.map(executeNode));
  const joinDecision = await scheduler.reconcile("wf-wave4");
  await executeNode("join");
  workflowStore.transitionWorkflow("wf-wave4", "completed");
  telemetry.emit({
    type: "workflow.completed",
    workflowExecutionId: "wf-wave4",
    at: Date.now(),
    durationMs: workflowDuration(),
  });

  const artifactBus = new FilesystemArtifactBus(path.join(root, "artifacts"));
  const finalOutcome = outcomes.at(-1)!;
  const artifact = await artifactBus.publish(Buffer.from(canonicalJson(finalOutcome.result)), {
    mediaType: "application/json",
    workflowExecutionId: "wf-wave4",
    nodeId: "join",
    deviceId: "windows-main",
    createdAt: "2026-10-07T15:00:02+03:00",
  });
  const fetched = await artifactBus.fetch(artifactReference(artifact));
  const transfer = artifactBus.createTransferReceipt(
    artifact,
    {
      globalCorrelationId: "corr-transfer",
      traceId: "trace-transfer",
      sourceDeviceId: "windows-main",
      targetDeviceId: "macbook-main",
      verifiedAt: "2026-10-07T15:00:03+03:00",
    },
    signer,
  );

  const snapshot = workflowStore.snapshot("wf-wave4");
  const metrics = telemetry.snapshot();
  const auditsValid = outcomes.every((outcome) =>
    verifyDistributedAuditRecord(outcome.audit, signer),
  );
  const acceptance =
    firstDecision.ready.join(",") === "health-a,health-b" &&
    joinDecision.ready.join(",") === "join" &&
    snapshot.status === "completed" &&
    snapshot.nodes.every((node) => node.status === "completed") &&
    outcomes.length === 3 &&
    auditsValid &&
    fetched.toString() === canonicalJson(finalOutcome.result) &&
    artifactBus.verifyTransferReceipt(transfer, signer) &&
    metrics.counters["node.dispatched"] === 3 &&
    metrics.counters["node.completed"] === 3;

  workflowStore.close();

  process.stdout.write(
    JSON.stringify({
      input: {
        workflowExecutionId: "wf-wave4",
        roots: firstDecision.ready,
        join: joinDecision.ready,
      },
      runtime: {
        scheduler: "WorkflowScheduler",
        capabilityRuntime: "V3CapabilityRuntime",
        observability: "InMemoryWorkflowTelemetry",
        artifactBus: "FilesystemArtifactBus",
      },
      execution: {
        nodeExecutions: outcomes.length,
        workflowStatus: snapshot.status,
        nodeStatuses: snapshot.nodes.map((node) => [node.id, node.status]),
        distributedAuditsValid: auditsValid,
      },
      output: {
        artifactId: artifact.artifactId,
        transferReceiptHash: transfer.recordHash,
        telemetry: metrics.counters,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
