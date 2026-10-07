import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { WorkflowDefinition } from "../../../src/v3/workflow/contracts.js";
import {
  WorkflowTriggerConflict,
  WorkflowTriggerRuntime,
  type TriggerWorkflowSubmitPort,
} from "../../../src/v3/workflow/triggers.js";

const roots: string[] = [];

function workflow(title = "Trigger acceptance"): WorkflowDefinition {
  return {
    workflowId: "trigger.acceptance",
    definitionVersion: "1.0.0",
    title,
    nodes: [
      {
        id: "health",
        capability: "device.health",
        input: {},
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
          contractId: "health/v1",
          artifactMode: "inline",
          maxBytes: 1024,
        },
      },
    ],
  };
}

function submitMock() {
  return vi.fn<TriggerWorkflowSubmitPort["submit"]>(async () => "wf-trigger-1");
}

async function runtime(submit = submitMock()) {
  const root = await mkdtemp(path.join(tmpdir(), "radlina-v3-trigger-"));
  roots.push(root);
  return {
    submit,
    runtime: new WorkflowTriggerRuntime(path.join(root, "triggers.sqlite3"), { submit }),
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("V3 workflow triggers", () => {
  it("accepts an event and submits one workflow with a deterministic idempotency key", async () => {
    const { runtime: trigger, submit } = await runtime();
    await expect(
      trigger.accept({
        source: "webhook",
        eventId: "event-1",
        subject: "owner",
        workflow: workflow(),
        payload: { value: 1 },
      }),
    ).resolves.toEqual({ executionId: "wf-trigger-1", replayed: false });

    expect(submit).toHaveBeenCalledTimes(1);
    expect(submit.mock.calls[0]?.[0].idempotencyKey).toMatch(/^trigger:[0-9a-f]{64}$/u);
    expect(trigger.status("webhook", "event-1")).toMatchObject({
      status: "submitted",
      execution_id: "wf-trigger-1",
    });
    trigger.close();
  });

  it("deduplicates an identical replay without resubmitting", async () => {
    const { runtime: trigger, submit } = await runtime();
    const input = {
      source: "webhook",
      eventId: "event-1",
      subject: "owner",
      workflow: workflow(),
      payload: { value: 1 },
    };
    await trigger.accept(input);
    await expect(trigger.accept(input)).resolves.toEqual({
      executionId: "wf-trigger-1",
      replayed: true,
    });
    expect(submit).toHaveBeenCalledTimes(1);
    trigger.close();
  });

  it("rejects event-id reuse with different workflow or payload content", async () => {
    const { runtime: trigger } = await runtime();
    await trigger.accept({
      source: "webhook",
      eventId: "event-1",
      subject: "owner",
      workflow: workflow(),
      payload: { value: 1 },
    });
    await expect(
      trigger.accept({
        source: "webhook",
        eventId: "event-1",
        subject: "owner",
        workflow: workflow("Different"),
        payload: { value: 1 },
      }),
    ).rejects.toThrow(WorkflowTriggerConflict);
    trigger.close();
  });

  it("persists a failed submission and safely retries with the same idempotency key", async () => {
    const submit = vi
      .fn<TriggerWorkflowSubmitPort["submit"]>()
      .mockRejectedValueOnce(new Error("temporary outage"))
      .mockResolvedValueOnce("wf-trigger-2");
    const runtimeResult = await runtime(submit);
    const input = {
      source: "schedule",
      eventId: "event-2",
      subject: "owner",
      workflow: workflow(),
      payload: { tick: 1 },
    };

    await expect(runtimeResult.runtime.accept(input)).rejects.toThrow(/temporary outage/u);
    expect(runtimeResult.runtime.status("schedule", "event-2")?.status).toBe("failed");
    await expect(runtimeResult.runtime.accept(input)).resolves.toEqual({
      executionId: "wf-trigger-2",
      replayed: true,
    });
    expect(submit.mock.calls[0]?.[0].idempotencyKey).toBe(submit.mock.calls[1]?.[0].idempotencyKey);
    runtimeResult.runtime.close();
  });
});
