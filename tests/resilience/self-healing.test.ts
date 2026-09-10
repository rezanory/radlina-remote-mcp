import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { stringify as stringifyYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";

import { closeRuntime, createRuntime } from "../../src/runtime.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function runtimeFixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "radlina-reliability-"));
  cleanup.push(root);
  const config = testConfig(root);
  config.reliability.probeIntervalMs = 300_000;
  config.reliability.auditVerifyIntervalMs = 300_000;
  const configFile = path.join(root, "config.yaml");
  await writeFile(configFile, stringifyYaml(config), "utf8");
  return { root, runtime: await createRuntime(configFile) };
}

describe("self-healing reliability supervisor", () => {
  it("reconciles stale sessions and expired OAuth state without disturbing healthy readiness", async () => {
    const { root, runtime } = await runtimeFixture();
    try {
      expect(runtime.reliability.snapshot().status).toBe("healthy");
      expect(runtime.reliability.snapshot().ready).toBe(true);

      const expiredApproval = randomUUID();
      runtime.store.db
        .prepare(
          "INSERT INTO oauth_approvals(id,client_id,redirect_uri,challenge,scope,resource,state,approved,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run(
          expiredApproval,
          "stale-client",
          "http://127.0.0.1/callback",
          "x".repeat(43),
          "device:read",
          runtime.auth.resourceUrl.href,
          null,
          0,
          Date.now() - 1,
        );

      const processId = randomUUID();
      runtime.store.db
        .prepare(
          "INSERT INTO process_sessions(id,subject,profile,pid,executable,args_json,output_path,status,started_at,start_identity) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          processId,
          "owner",
          "test",
          null,
          process.execPath,
          "{}",
          path.join(root, `${processId}.log`),
          "running",
          Date.now() - 1_000,
          "stale",
        );

      const searchId = randomUUID();
      runtime.store.db
        .prepare(
          "INSERT INTO search_sessions(id,subject,profile,pid,query_json,result_path,status,started_at) VALUES(?,?,?,?,?,?,?,?)",
        )
        .run(
          searchId,
          "owner",
          "test",
          null,
          "{}",
          path.join(root, `${searchId}.jsonl`),
          "running",
          Date.now() - 1_000,
        );

      const snapshot = await runtime.reliability.probe("resilience-test");
      expect(snapshot.status).toBe("healthy");
      expect(snapshot.ready).toBe(true);
      expect(snapshot.recoveryCount).toBeGreaterThanOrEqual(3);

      const processRow = runtime.store.db
        .prepare("SELECT status FROM process_sessions WHERE id=?")
        .get(processId) as { status: string };
      const searchRow = runtime.store.db
        .prepare("SELECT status FROM search_sessions WHERE id=?")
        .get(searchId) as { status: string };
      const approvalCount = runtime.store.db
        .prepare("SELECT COUNT(*) AS count FROM oauth_approvals WHERE id=?")
        .get(expiredApproval) as { count: number };

      expect(processRow.status).toBe("interrupted");
      expect(searchRow.status).toBe("interrupted");
      expect(approvalCount.count).toBe(0);
      expect(runtime.reliability.recentEvents(20)).toEqual(
        expect.arrayContaining([expect.objectContaining({ kind: "recovery", status: "applied" })]),
      );
    } finally {
      closeRuntime(runtime);
    }
  });

  it("fails closed on a dependency fault and returns to healthy after recovery", async () => {
    const { root, runtime } = await runtimeFixture();
    try {
      const originalRipgrep = runtime.config.dependencies.ripgrepExecutable;
      runtime.config.dependencies.ripgrepExecutable = path.join(root, "missing-rg.exe");

      const degraded = await runtime.reliability.probe("dependency-failure-1", false);
      expect(degraded.status).toBe("degraded");
      expect(degraded.ready).toBe(false);
      expect(degraded.checks.ripgrep?.ok).toBe(false);

      const unhealthy = await runtime.reliability.probe("dependency-failure-2", false);
      expect(unhealthy.status).toBe("unhealthy");
      expect(unhealthy.ready).toBe(false);
      expect(unhealthy.consecutiveFailures).toBe(2);

      runtime.config.dependencies.ripgrepExecutable = originalRipgrep;
      const recovered = await runtime.reliability.probe("dependency-restored", false);
      expect(recovered.status).toBe("healthy");
      expect(recovered.ready).toBe(true);
      expect(recovered.consecutiveFailures).toBe(0);
      expect(runtime.reliability.recentEvents(20)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "health-transition", status: "unhealthy" }),
          expect.objectContaining({ kind: "health-transition", status: "healthy" }),
        ]),
      );
    } finally {
      closeRuntime(runtime);
    }
  });
  it("fails closed instead of rejecting when the supervisor itself cannot access persistence", async () => {
    const { runtime } = await runtimeFixture();
    runtime.reliability.stop();
    runtime.store.close();
    const snapshot = await runtime.reliability.probe("closed-store-supervisor-failure");
    expect(snapshot.status).toBe("unhealthy");
    expect(snapshot.ready).toBe(false);
    expect(snapshot.checks.supervisor).toMatchObject({ ok: false });
    closeRuntime(runtime);
  });
});
