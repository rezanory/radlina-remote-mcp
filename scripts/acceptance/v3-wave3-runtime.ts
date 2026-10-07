import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { PolicyEngine } from "../../src/policy/engine.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import {
  createDistributedAuditRecord,
  HmacDistributedAuditSigner,
  verifyDistributedAuditRecord,
} from "../../src/v3/audit/distributed.js";
import {
  assertAgentHello,
  assertExecuteRequestForDevice,
  parseAgentExecuteRequest,
} from "../../src/v3/device/agent-protocol.js";
import { parseDeviceDescriptor } from "../../src/v3/device/identity.js";
import { SqliteDeviceRegistry } from "../../src/v3/device/registry.js";
import { V3ExecutionPolicyGuard } from "../../src/v3/security/policy.js";
import type { WorkflowDefinition } from "../../src/v3/workflow/contracts.js";
import {
  WorkflowSqliteStore,
  type WorkflowPayloadCodec,
} from "../../src/v3/workflow/persistence.js";
import { testConfig } from "../../tests/helpers/config.js";

class Base64Codec implements WorkflowPayloadCodec {
  async encode(plaintext: string): Promise<string> {
    return Buffer.from(plaintext, "utf8").toString("base64");
  }
  async decode(encoded: string): Promise<string> {
    return Buffer.from(encoded, "base64").toString("utf8");
  }
}

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-wave3-"));
try {
  const workflowDefinition: WorkflowDefinition = {
    workflowId: "runtime.acceptance",
    definitionVersion: "1.0.0",
    title: "Wave3 runtime acceptance",
    nodes: [
      {
        id: "health",
        capability: "device.health",
        input: { probe: true },
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
          artifactMode: "inline",
          maxBytes: 65_536,
        },
      },
    ],
  };

  const workflowStore = new WorkflowSqliteStore(
    path.join(root, "workflow.sqlite3"),
    new Base64Codec(),
  );
  const created = await workflowStore.create(
    "wf-real-1",
    "owner",
    "idem-real-1",
    workflowDefinition,
  );
  workflowStore.transitionWorkflow("wf-real-1", "running");
  workflowStore.transitionNode("wf-real-1", "health", "ready");
  workflowStore.transitionNode("wf-real-1", "health", "running");
  workflowStore.transitionNode("wf-real-1", "health", "completed");
  workflowStore.transitionWorkflow("wf-real-1", "completed");
  const workflowSnapshot = workflowStore.snapshot("wf-real-1");
  const workflowEvents = workflowStore.events("wf-real-1");
  workflowStore.close();

  const registry = new SqliteDeviceRegistry(path.join(root, "devices.sqlite3"));
  registry.register(
    parseDeviceDescriptor({
      deviceId: "windows-main",
      hostname: "LAPTOP-13QINEIF",
      platform: "windows",
      architecture: "x64",
      agentVersion: "3.0.0-alpha.1",
      status: "online",
      lastSeen: "2026-10-07T13:00:00+03:00",
      capabilities: ["device.health"],
      tags: ["primary"],
      trustState: "pending",
      health: "healthy",
    }),
  );
  const heartbeat = registry.heartbeat("windows-main", {
    lastSeen: "2026-10-07T13:00:01+03:00",
    status: "online",
    health: "healthy",
    agentVersion: "3.0.0-alpha.1",
    capabilities: ["device.health"],
  });
  registry.close();

  const trustedDevice = parseDeviceDescriptor({ ...heartbeat, trustState: "trusted" });
  const identity = {
    deviceId: "windows-main",
    agentInstanceId: "ed5c4a30-1c28-43a9-8b4a-e87cd9f38966",
    agentVersion: "3.0.0-alpha.1",
    publicKeyFingerprint: "a".repeat(64),
    enrolledAt: "2026-10-07T13:00:00+03:00",
  };
  assertAgentHello({ protocolVersion: "1.0.0", descriptor: trustedDevice, identity });

  const executionInput = { probe: true };
  const executeRequest = parseAgentExecuteRequest({
    requestId: "53923e93-f290-457b-8375-98c3ac86d8a7",
    workflowExecutionId: "wf-real-1",
    nodeId: "health",
    attempt: 1,
    targetDeviceId: "windows-main",
    capability: "device.health",
    input: executionInput,
    inputSha256: sha256(canonicalJson(executionInput)),
    timeoutMs: 5_000,
    globalCorrelationId: "corr-real-1",
    traceId: "trace-real-1",
  });
  assertExecuteRequestForDevice(executeRequest, trustedDevice);

  const auth: AuthInfo = {
    token: "acceptance-token",
    clientId: "acceptance-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  const policy = new V3ExecutionPolicyGuard(
    new PolicyEngine(testConfig(root), {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    }),
  ).authorize({
    auth,
    profile: "test",
    tool: "operator_submit",
    requiredScope: "device:read",
    risk: "low",
    capability: "device.health",
    target: { deviceId: "windows-main" },
    device: trustedDevice,
  });

  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 7));
  const audit = createDistributedAuditRecord(
    {
      globalCorrelationId: "corr-real-1",
      traceId: "trace-real-1",
      subject: "owner",
      profile: "test",
      workflowExecutionId: "wf-real-1",
      nodeId: "health",
      attempt: 1,
      resolvedDeviceId: "windows-main",
      capability: "device.health",
      policyDecision: {
        allowed: policy.allowed,
        reason: policy.reason,
        requiredScope: "device:read",
        risk: "low",
      },
      inputSha256: executeRequest.inputSha256,
      outputSha256: "b".repeat(64),
      localAuditReceiptHash: "c".repeat(64),
      requestedAt: "2026-10-07T13:00:00+03:00",
      endedAt: "2026-10-07T13:00:01+03:00",
      terminalState: "completed",
    },
    signer,
  );

  const acceptance =
    created.replayed === false &&
    workflowSnapshot.status === "completed" &&
    workflowSnapshot.nodes[0]?.status === "completed" &&
    workflowEvents.length === 6 &&
    heartbeat.deviceId === "windows-main" &&
    policy.allowed &&
    verifyDistributedAuditRecord(audit, signer);

  process.stdout.write(
    JSON.stringify({
      input: {
        workflowExecutionId: "wf-real-1",
        deviceId: "windows-main",
        capability: "device.health",
      },
      runtime: {
        workflowPersistence: "WorkflowSqliteStore",
        deviceRegistry: "SqliteDeviceRegistry",
        policy: "PolicyEngine+V3ExecutionPolicyGuard",
        agentProtocol: "V3 device agent protocol",
        distributedAudit: "HMAC-SHA256",
      },
      execution: {
        workflowEvents: workflowEvents.length,
        workflowStatus: workflowSnapshot.status,
        nodeStatus: workflowSnapshot.nodes[0]?.status,
        heartbeatStatus: heartbeat.status,
        policyAllowed: policy.allowed,
      },
      output: {
        distributedAuditHash: audit.recordHash,
        resolvedDeviceId: audit.resolvedDeviceId,
        terminalState: audit.terminalState,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
