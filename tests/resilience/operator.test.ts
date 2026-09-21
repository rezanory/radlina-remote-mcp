import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import { protectBytes } from "../../src/auth/dpapi.js";

import type { CapabilityProvider } from "../../src/components/contracts.js";
import { CapabilityRegistry } from "../../src/components/registry.js";
import { OperatorManager } from "../../src/operator/manager.js";
import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { sha256 } from "../../src/utils/json.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];
const admin: AuthInfo = {
  token: "operator-test",
  clientId: "operator-test",
  scopes: ["admin"],
  expiresAt: Math.floor(Date.now() / 1000) + 60,
};

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function setup(providers: CapabilityProvider[]) {
  const root = await mkdtemp(path.join(os.tmpdir(), "radlina-operator-"));
  cleanup.push(root);
  const config = testConfig(root);
  const store = new Store(config.storage.directory);
  const policy = new PolicyEngine(config, {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  const registry = new CapabilityRegistry();
  registry.register({
    id: "test.operator",
    version: "1.0.0",
    description: "test providers",
    capabilities: providers,
  });
  return { root, store, registry, manager: new OperatorManager(store, policy, registry) };
}

function provider(
  id: string,
  options: {
    idempotent?: boolean;
    execute?: CapabilityProvider["execute"];
  } = {},
): CapabilityProvider {
  return {
    id,
    version: "1.0.0",
    description: id,
    requiredScope: "device:read",
    risk: "low",
    readOnly: options.idempotent ?? true,
    idempotent: options.idempotent ?? true,
    execute: options.execute ?? (async (_context, input) => ({ input })),
  };
}

async function waitForTerminal(
  manager: OperatorManager,
  jobId: string,
): Promise<{ status: string; steps: Array<{ status: string; attempts: number }> }> {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    const status = (await manager.status("subject", jobId)) as {
      status: string;
      steps: Array<{ status: string; attempts: number }>;
    };
    if (!["queued", "running"].includes(status.status)) return status;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("operator job did not reach a terminal state");
}

describe("OperatorManager", () => {
  it("executes ordered component capabilities and persists completion receipts", async () => {
    const calls: string[] = [];
    const first = provider("test.first", {
      execute: async () => {
        calls.push("first");
        return { ok: 1 };
      },
    });
    const second = provider("test.second", {
      execute: async () => {
        calls.push("second");
        return { ok: 2 };
      },
    });
    const { store, manager } = await setup([first, second]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "ordered plan",
        steps: [
          { id: "one", capability: "test.first", input: {}, maxAttempts: 1 },
          { id: "two", capability: "test.second", input: {}, maxAttempts: 1 },
        ],
      });
      const result = await waitForTerminal(manager, submitted.jobId);
      expect(result.status).toBe("completed");
      expect(result.steps.map((step) => step.status)).toEqual(["completed", "completed"]);
      expect(calls).toEqual(["first", "second"]);
    } finally {
      store.close();
    }
  });

  it("retries only an idempotent capability within its explicit retry budget", async () => {
    let calls = 0;
    const flaky = provider("test.flaky", {
      idempotent: true,
      execute: async () => {
        calls += 1;
        if (calls === 1) throw new Error("temporary failure");
        return { recovered: true };
      },
    });
    const { store, manager } = await setup([flaky]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "retry plan",
        steps: [{ id: "retry", capability: "test.flaky", input: {}, maxAttempts: 2 }],
      });
      const result = await waitForTerminal(manager, submitted.jobId);
      expect(result.status).toBe("completed");
      expect(result.steps[0]?.attempts).toBe(2);
      expect(calls).toBe(2);
    } finally {
      store.close();
    }
  });

  it("rejects automatic retries for non-idempotent capabilities before side effects", async () => {
    let calls = 0;
    const write = provider("test.write", {
      idempotent: false,
      execute: async () => {
        calls += 1;
        return { written: true };
      },
    });
    const { store, manager } = await setup([write]);
    try {
      await expect(
        manager.submit(admin, "subject", "test", {
          title: "unsafe retry",
          steps: [{ id: "write", capability: "test.write", input: {}, maxAttempts: 2 }],
        }),
      ).rejects.toThrow(/non-idempotent/u);
      expect(calls).toBe(0);
      const row = store.db.prepare("SELECT COUNT(*) AS count FROM operator_jobs").get() as {
        count: number;
      };
      expect(row.count).toBe(0);
    } finally {
      store.close();
    }
  });

  it("marks in-flight work interrupted on restart and refuses unsafe replay", async () => {
    const write = provider("test.write", { idempotent: false });
    const { store, manager } = await setup([write]);
    try {
      const now = Date.now();
      store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at,started_at) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run("job", "subject", "test", "restart", "running", 0, now, now, now);
      store.db
        .prepare(
          "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts,started_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run("job", "write", 0, "test.write", "protected", "hash", "running", 1, 1, now);

      expect(manager.reconcile()).toEqual({ interruptedJobs: 1, interruptedSteps: 1 });
      const status = (await manager.status("subject", "job")) as {
        status: string;
        steps: Array<{ status: string }>;
      };
      expect(status.status).toBe("interrupted");
      expect(status.steps[0]?.status).toBe("interrupted");
      expect(() => manager.resume(admin, "subject", "job")).toThrow(/non-idempotent/u);
    } finally {
      store.close();
    }
  });

  it("keeps sensitive operator input and result payloads protected at rest", async () => {
    const secret = "RADLINA_OPERATOR_SECRET_9f7f44b1";
    const echo = provider("test.secret", {
      execute: async (_context, input) => ({
        echoed: (input as { secret?: string }).secret,
      }),
    });
    const { store, manager } = await setup([echo]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "protected persistence",
        steps: [{ id: "secret", capability: "test.secret", input: { secret }, maxAttempts: 1 }],
      });
      const result = (await waitForTerminal(manager, submitted.jobId)) as {
        status: string;
        steps: Array<{ result?: { echoed?: string } | null }>;
      };
      expect(result.status).toBe("completed");
      expect(result.steps[0]?.result?.echoed).toBe(secret);
      const row = store.db
        .prepare(
          "SELECT input_protected,input_sha256,result_protected,error_protected FROM operator_steps WHERE job_id=?",
        )
        .get(submitted.jobId) as Record<string, unknown>;
      expect(JSON.stringify(row)).not.toContain(secret);
      expect(typeof row["input_sha256"]).toBe("string");
    } finally {
      store.close();
    }
  });

  it("cancels queued work before execution", async () => {
    const { store, manager } = await setup([provider("test.read")]);
    try {
      const now = Date.now();
      const inputText = "{}";
      const inputProtected = await protectBytes(Buffer.from(inputText, "utf8"));
      store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run("queued-job", "subject", "test", "queued cancellation", "queued", 0, now, now);
      store.db
        .prepare(
          "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "queued-job",
          "read",
          0,
          "test.read",
          inputProtected,
          sha256(inputText),
          "pending",
          0,
          1,
        );

      expect(manager.cancel("subject", "queued-job")).toEqual({
        jobId: "queued-job",
        status: "cancelled",
        requested: true,
      });
      const status = (await manager.status("subject", "queued-job")) as {
        status: string;
        steps: Array<{ status: string }>;
      };
      expect(status.status).toBe("cancelled");
      expect(status.steps[0]?.status).toBe("cancelled");
    } finally {
      store.close();
    }
  });

  it("honors cancellation requested while a capability is running", async () => {
    const cancellable = provider("test.cancellable", {
      execute: async (context) => {
        for (let attempt = 0; attempt < 200; attempt += 1) {
          if (context.isCancelled()) return { cancellationObserved: true };
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        return { cancellationObserved: false };
      },
    });
    const { store, manager } = await setup([cancellable]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "running cancellation",
        steps: [{ id: "run", capability: "test.cancellable", input: {}, maxAttempts: 1 }],
      });
      for (let attempt = 0; attempt < 200; attempt += 1) {
        const snapshot = (await manager.status("subject", submitted.jobId)) as { status: string };
        if (snapshot.status === "running") break;
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      expect(manager.cancel("subject", submitted.jobId).requested).toBe(true);
      const result = await waitForTerminal(manager, submitted.jobId);
      expect(result.status).toBe("cancelled");
      expect(result.steps[0]?.status).toBe("cancelled");
    } finally {
      store.close();
    }
  });

  it("isolates jobs by authenticated subject", async () => {
    const { store, manager } = await setup([provider("test.read")]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "subject isolation",
        steps: [{ id: "read", capability: "test.read", input: {}, maxAttempts: 1 }],
      });
      await waitForTerminal(manager, submitted.jobId);
      await expect(manager.status("other-subject", submitted.jobId)).rejects.toThrow(/not found/u);
      expect(() => manager.cancel("other-subject", submitted.jobId)).toThrow(/not found/u);
      await expect(manager.recent("other-subject")).resolves.toEqual([]);
    } finally {
      store.close();
    }
  });

  it("rejects malformed, oversized, and overlong plans before persistence", async () => {
    const { store, manager } = await setup([provider("test.read")]);
    try {
      await expect(
        manager.submit(admin, "subject", "test", {
          title: "duplicate ids",
          steps: [
            { id: "same", capability: "test.read", input: {}, maxAttempts: 1 },
            { id: "same", capability: "test.read", input: {}, maxAttempts: 1 },
          ],
        }),
      ).rejects.toThrow(/unique/u);

      await expect(
        manager.submit(admin, "subject", "test", {
          title: "too many steps",
          steps: Array.from({ length: 17 }, (_, index) => ({
            id: `step-${index}`,
            capability: "test.read",
            input: {},
            maxAttempts: 1,
          })),
        }),
      ).rejects.toThrow(/1-16/u);

      await expect(
        manager.submit(admin, "subject", "test", {
          title: "oversized",
          steps: [
            {
              id: "large",
              capability: "test.read",
              input: { payload: "x".repeat(70 * 1024) },
              maxAttempts: 1,
            },
          ],
        }),
      ).rejects.toThrow(/size limit/u);

      const row = store.db.prepare("SELECT COUNT(*) AS count FROM operator_jobs").get() as {
        count: number;
      };
      expect(row.count).toBe(0);
    } finally {
      store.close();
    }
  });

  it("resumes interrupted idempotent work only after the protected input integrity check", async () => {
    let calls = 0;
    const { store, manager } = await setup([
      provider("test.read", {
        execute: async () => {
          calls += 1;
          return { resumed: true };
        },
      }),
    ]);
    try {
      const now = Date.now();
      const inputText = "{}";
      const inputProtected = await protectBytes(Buffer.from(inputText, "utf8"));
      store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at,started_at) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run("resume-job", "subject", "test", "resume", "running", 0, now, now, now);
      store.db
        .prepare(
          "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts,started_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "resume-job",
          "read",
          0,
          "test.read",
          inputProtected,
          sha256(inputText),
          "running",
          1,
          2,
          now,
        );

      expect(manager.reconcile()).toEqual({ interruptedJobs: 1, interruptedSteps: 1 });
      expect(manager.resume(admin, "subject", "resume-job")).toEqual({
        jobId: "resume-job",
        status: "queued",
      });
      const result = await waitForTerminal(manager, "resume-job");
      expect(result.status).toBe("completed");
      expect(result.steps[0]?.attempts).toBe(2);
      expect(calls).toBe(1);
    } finally {
      store.close();
    }
  });

  it("refuses resume after an idempotent step exhausts its retry budget", async () => {
    const alwaysFails = provider("test.always-fails", {
      execute: async () => {
        throw new Error("persistent failure");
      },
    });
    const { store, manager } = await setup([alwaysFails]);
    try {
      const submitted = await manager.submit(admin, "subject", "test", {
        title: "exhaust retry budget",
        steps: [{ id: "fail", capability: "test.always-fails", input: {}, maxAttempts: 1 }],
      });
      const result = await waitForTerminal(manager, submitted.jobId);
      expect(result.status).toBe("failed");
      expect(() => manager.resume(admin, "subject", submitted.jobId)).toThrow(/exhausted/u);
    } finally {
      store.close();
    }
  });

  it("fails closed when a capability becomes unavailable before restart recovery", async () => {
    const { store, registry, manager } = await setup([provider("test.read")]);
    try {
      const now = Date.now();
      const inputText = "{}";
      const inputProtected = await protectBytes(Buffer.from(inputText, "utf8"));
      store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at,started_at) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "missing-capability",
          "subject",
          "test",
          "missing capability",
          "running",
          0,
          now,
          now,
          now,
        );
      store.db
        .prepare(
          "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts,started_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "missing-capability",
          "read",
          0,
          "test.read",
          inputProtected,
          sha256(inputText),
          "running",
          1,
          2,
          now,
        );

      manager.reconcile();
      expect(registry.unregister("test.operator")).toBe(true);
      expect(() => manager.resume(admin, "subject", "missing-capability")).toThrow(
        /not available/u,
      );
    } finally {
      store.close();
    }
  });

  it("fails closed instead of executing when a protected input payload is corrupted", async () => {
    let calls = 0;
    const { store, manager } = await setup([
      provider("test.read", {
        execute: async () => {
          calls += 1;
          return { shouldNotRun: true };
        },
      }),
    ]);
    try {
      const now = Date.now();
      store.db
        .prepare(
          "INSERT INTO operator_jobs(id,subject,profile,title,status,cancel_requested,created_at,updated_at,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "corrupt-payload",
          "subject",
          "test",
          "corrupt payload",
          "interrupted",
          0,
          now,
          now,
          now,
          now,
        );
      store.db
        .prepare(
          "INSERT INTO operator_steps(job_id,step_id,ordinal,capability,input_protected,input_sha256,status,attempts,max_attempts,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "corrupt-payload",
          "read",
          0,
          "test.read",
          "definitely-not-a-dpapi-payload",
          sha256("{}"),
          "interrupted",
          0,
          1,
          now,
          now,
        );

      expect(manager.resume(admin, "subject", "corrupt-payload").status).toBe("queued");
      const result = await waitForTerminal(manager, "corrupt-payload");
      expect(result.status).toBe("failed");
      expect(result.steps[0]?.status).toBe("failed");
      expect(calls).toBe(0);
    } finally {
      store.close();
    }
  });

  it("fails closed when the caller lacks authorization", async () => {
    const { store, manager } = await setup([provider("test.read")]);
    try {
      await expect(
        manager.submit(undefined, "subject", "test", {
          title: "unauthorized",
          steps: [{ id: "read", capability: "test.read", input: {}, maxAttempts: 1 }],
        }),
      ).rejects.toThrow(/authenticated identity/u);
    } finally {
      store.close();
    }
  });
});
