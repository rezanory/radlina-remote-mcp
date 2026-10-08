import { readFile } from "node:fs/promises";

import type { AuthInfo } from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";

import { PolicyEngine } from "../../../src/policy/engine.js";
import {
  AgentProviderRuntime,
  AgentProviderRuntimeError,
  PolicyEngineAgentProviderPolicy,
  type AgentProvider,
  type AgentProviderPolicyPort,
} from "../../../src/v3/agent-provider/runtime.js";
import { HmacDistributedAuditSigner } from "../../../src/v3/audit/distributed.js";
import { testConfig } from "../../helpers/config.js";

const auth: AuthInfo = {
  token: "token",
  clientId: "client",
  scopes: ["device:read"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

function provider(
  invoke: AgentProvider["invoke"] = async (payload) => ({ echoed: payload }),
): AgentProvider {
  return {
    descriptor: {
      id: "openai-agent",
      version: "1.0.0",
      description: "Provider",
      requiredScope: "device:read",
      risk: "low",
    },
    invoke,
  };
}

function allowPolicy(): AgentProviderPolicyPort {
  return {
    authorize: () => ({ allowed: true, reason: "allowed" }),
  };
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    invocationId: "3b1b6cd2-d05f-4c68-9d63-6a69d8a7e752",
    auth,
    subject: "owner",
    profile: "test",
    workflowExecutionId: "wf-1",
    nodeId: "agent",
    attempt: 1,
    providerId: "openai-agent",
    payload: { value: 1 },
    globalCorrelationId: "corr-1",
    traceId: "trace-1",
    ...overrides,
  };
}

describe("V3 AgentProviderRuntime", () => {
  it("registers provider descriptors deterministically and rejects duplicates", () => {
    const runtime = new AgentProviderRuntime(
      allowPolicy(),
      new HmacDistributedAuditSigner(Buffer.alloc(32, 4)),
    );
    runtime.register(provider());
    expect(runtime.list()).toEqual([
      {
        id: "openai-agent",
        version: "1.0.0",
        description: "Provider",
        requiredScope: "device:read",
        risk: "low",
      },
    ]);
    expect(() => runtime.register(provider())).toThrow(/already registered/u);
  });

  it("invokes only after policy authorization and returns a signed correlated receipt", async () => {
    const signer = new HmacDistributedAuditSigner(Buffer.alloc(32, 4));
    const invoke = vi.fn(async (payload: unknown) => ({ result: payload }));
    const runtime = new AgentProviderRuntime(
      allowPolicy(),
      signer,
      (() => {
        const values = ["2026-10-08T03:00:00+03:00", "2026-10-08T03:00:01+03:00"];
        return () => values.shift()!;
      })(),
    );
    runtime.register(provider(invoke));

    const outcome = await runtime.invoke(request());
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("expected success");
    expect(outcome.output).toEqual({ result: { value: 1 } });
    expect(outcome.receipt).toMatchObject({
      invocationId: "3b1b6cd2-d05f-4c68-9d63-6a69d8a7e752",
      providerId: "openai-agent",
      workflowExecutionId: "wf-1",
      nodeId: "agent",
      attempt: 1,
      terminalState: "completed",
      policyReason: "allowed",
    });
    expect(runtime.verifyReceipt(outcome.receipt)).toBe(true);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("fails before provider execution when policy denies", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    const runtime = new AgentProviderRuntime(
      { authorize: () => ({ allowed: false, reason: "denied" }) },
      new HmacDistributedAuditSigner(Buffer.alloc(32, 4)),
    );
    runtime.register(provider(invoke));

    await expect(runtime.invoke(request())).rejects.toThrow(/policy denied/u);
    expect(invoke).not.toHaveBeenCalled();
  });

  it("normalizes provider failures into signed failed receipts", async () => {
    const runtime = new AgentProviderRuntime(
      allowPolicy(),
      new HmacDistributedAuditSigner(Buffer.alloc(32, 4)),
    );
    runtime.register(
      provider(async () => {
        throw new Error("provider outage");
      }),
    );

    const outcome = await runtime.invoke(request());
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("expected failure");
    expect(outcome.error.message).toBe("provider outage");
    expect(outcome.receipt.terminalState).toBe("failed");
    expect(outcome.receipt.outputSha256).toBeNull();
    expect(runtime.verifyReceipt(outcome.receipt)).toBe(true);
  });

  it("cancels an active provider invocation through AbortSignal and provider cancel", async () => {
    let started!: () => void;
    const startedPromise = new Promise<void>((resolve) => {
      started = resolve;
    });
    const cancel = vi.fn(async () => undefined);
    const deferred: AgentProvider = {
      ...provider(),
      cancel,
      invoke: async (_payload, context) => {
        started();
        await new Promise<void>((resolve, reject) => {
          context.signal.addEventListener("abort", () => reject(new Error("aborted by runtime")), {
            once: true,
          });
        });
        return { impossible: true };
      },
    };
    const runtime = new AgentProviderRuntime(
      allowPolicy(),
      new HmacDistributedAuditSigner(Buffer.alloc(32, 4)),
    );
    runtime.register(deferred);

    const pending = runtime.invoke(request());
    await startedPromise;
    await expect(runtime.cancel("3b1b6cd2-d05f-4c68-9d63-6a69d8a7e752")).resolves.toBe(true);
    const outcome = await pending;
    expect(outcome.ok).toBe(false);
    expect(outcome.receipt.terminalState).toBe("cancelled");
    expect(cancel).toHaveBeenCalledWith("3b1b6cd2-d05f-4c68-9d63-6a69d8a7e752");
  });

  it("uses the existing PolicyEngine fail-closed scope and emergency controls", () => {
    const policy = new PolicyEngineAgentProviderPolicy(
      new PolicyEngine(testConfig("C:\\workspace"), {
        killSwitch: () => false,
        emergencyReadOnly: () => false,
      }),
    );
    expect(
      policy.authorize({
        auth,
        profile: "test",
        providerId: "openai-agent",
        requiredScope: "device:read",
        risk: "low",
      }).allowed,
    ).toBe(true);
    expect(
      policy.authorize({
        auth: { ...auth, scopes: [] },
        profile: "test",
        providerId: "openai-agent",
        requiredScope: "device:read",
        risk: "low",
      }).allowed,
    ).toBe(false);
  });

  it("has no workflow scheduler, state-store, or direct persistence authority", async () => {
    const source = await readFile(
      new URL("../../../src/v3/agent-provider/runtime.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("WorkflowSqliteStore");
    expect(source).not.toContain("WorkflowScheduler");
    expect(source).not.toContain("node:sqlite");
    expect(source).not.toContain("transitionWorkflow");
    expect(source).not.toContain("transitionNode");
  });

  it("rejects unregister while an invocation is active", async () => {
    let release!: () => void;
    const blocker = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started!: () => void;
    const startedPromise = new Promise<void>((resolve) => {
      started = resolve;
    });
    const runtime = new AgentProviderRuntime(
      allowPolicy(),
      new HmacDistributedAuditSigner(Buffer.alloc(32, 4)),
    );
    runtime.register(
      provider(async () => {
        started();
        await blocker;
        return { ok: true };
      }),
    );

    const pending = runtime.invoke(request());
    await startedPromise;
    expect(() => runtime.unregister("openai-agent")).toThrow(AgentProviderRuntimeError);
    release();
    await pending;
    expect(runtime.unregister("openai-agent")).toBe(true);
  });
});
