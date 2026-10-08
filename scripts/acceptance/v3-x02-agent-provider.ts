import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";

import { PolicyEngine } from "../../src/policy/engine.js";
import {
  AgentProviderRuntime,
  PolicyEngineAgentProviderPolicy,
  type AgentProvider,
} from "../../src/v3/agent-provider/runtime.js";
import { HmacDistributedAuditSigner } from "../../src/v3/audit/distributed.js";
import { testConfig } from "../../tests/helpers/config.js";

const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-x02-"));
try {
  const policy = new PolicyEngineAgentProviderPolicy(
    new PolicyEngine(testConfig(root), {
      killSwitch: () => false,
      emergencyReadOnly: () => false,
    }),
  );
  const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 31));
  const runtime = new AgentProviderRuntime(policy, signer);
  let cancelCalls = 0;

  const provider: AgentProvider = {
    descriptor: {
      id: "openai-agent",
      version: "1.0.0",
      description: "X02 acceptance provider",
      requiredScope: "device:read",
      risk: "low",
    },
    invoke: async (payload, context) => {
      if (
        payload &&
        typeof payload === "object" &&
        (payload as { mode?: string }).mode === "wait"
      ) {
        await new Promise<void>((resolve, reject) => {
          if (context.signal.aborted) {
            reject(new Error("cancelled"));
            return;
          }
          context.signal.addEventListener("abort", () => reject(new Error("cancelled")), {
            once: true,
          });
        });
      }
      return { provider: "openai-agent", payload };
    },
    cancel: async () => {
      cancelCalls += 1;
    },
  };
  runtime.register(provider);

  const auth: AuthInfo = {
    token: "x02-token",
    clientId: "x02-client",
    scopes: ["device:read"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };

  const completed = await runtime.invoke({
    invocationId: "e365e356-18e5-4a28-82d1-f6ff655d9e67",
    auth,
    subject: "owner",
    profile: "test",
    workflowExecutionId: "wf-x02",
    nodeId: "agent-a",
    attempt: 1,
    providerId: "openai-agent",
    payload: { prompt: "ping" },
    globalCorrelationId: "corr-x02-a",
    traceId: "trace-x02-a",
  });

  const pending = runtime.invoke({
    invocationId: "63a4b3a8-8560-4e8d-9d4a-774d1961c031",
    auth,
    subject: "owner",
    profile: "test",
    workflowExecutionId: "wf-x02",
    nodeId: "agent-b",
    attempt: 1,
    providerId: "openai-agent",
    payload: { mode: "wait" },
    globalCorrelationId: "corr-x02-b",
    traceId: "trace-x02-b",
  });

  await new Promise((resolve) => setTimeout(resolve, 20));
  const cancelRequested = await runtime.cancel("63a4b3a8-8560-4e8d-9d4a-774d1961c031");
  const cancelled = await pending;

  const completedReceiptValid = completed.ok && runtime.verifyReceipt(completed.receipt);
  const cancelledReceiptValid =
    !cancelled.ok &&
    cancelled.receipt.terminalState === "cancelled" &&
    runtime.verifyReceipt(cancelled.receipt);

  const acceptance =
    completedReceiptValid &&
    cancelRequested &&
    cancelledReceiptValid &&
    cancelCalls === 1 &&
    runtime.list().length === 1;

  process.stdout.write(
    JSON.stringify({
      input: {
        providerId: "openai-agent",
        workflowExecutionId: "wf-x02",
        completedInvocation: "e365e356-18e5-4a28-82d1-f6ff655d9e67",
        cancelledInvocation: "63a4b3a8-8560-4e8d-9d4a-774d1961c031",
      },
      runtime: {
        providerRuntime: "AgentProviderRuntime",
        policy: "PolicyEngineAgentProviderPolicy",
        audit: "HmacDistributedAuditSigner",
      },
      execution: {
        completed: completed.ok,
        completedTerminalState: completed.receipt.terminalState,
        cancelRequested,
        cancelledTerminalState: cancelled.receipt.terminalState,
        providerCancelCalls: cancelCalls,
      },
      output: {
        completedReceiptValid,
        cancelledReceiptValid,
        providerCount: runtime.list().length,
      },
      acceptance: acceptance ? "PASS" : "FAIL",
    }),
  );
  if (!acceptance) process.exitCode = 1;
} finally {
  await rm(root, { recursive: true, force: true });
}
