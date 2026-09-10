import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { AuthInfo } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, it } from "vitest";

import { AuditChain } from "../../src/audit/chain.js";
import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { ToolRuntime } from "../../src/policy/runtime.js";
import { canonicalJson, sha256 } from "../../src/utils/json.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function setup() {
  const root = await mkdtemp(path.join(os.tmpdir(), "radlina-runtime-"));
  cleanup.push(root);
  const config = testConfig(root);
  const store = new Store(config.storage.directory);
  const audit = new AuditChain(config, store);
  await audit.initialize();
  const policy = new PolicyEngine(config, {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  const auth: AuthInfo = {
    token: "test",
    clientId: "client",
    scopes: ["filesystem:write"],
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  return { root, store, audit, policy, auth };
}

describe("audit and idempotency", () => {
  it("serializes concurrent audit events into a verifiable chain", async () => {
    const { audit, store } = await setup();
    await Promise.all(
      Array.from({ length: 25 }, (_, index) =>
        audit.append({
          correlationId: crypto.randomUUID(),
          subject: "test",
          deviceId: "device",
          tool: `tool-${index}`,
          args: { index },
          decision: "allow",
          durationMs: index,
          exitState: "success",
        }),
      ),
    );
    await expect(audit.verify(await audit.files())).resolves.toEqual({ valid: true, records: 25 });
    store.close();
  });

  it("keeps audit records verifiable when optional args are undefined", async () => {
    const { audit, store } = await setup();
    await audit.append({
      correlationId: crypto.randomUUID(),
      subject: "test",
      deviceId: "device",
      tool: "get_file_info",
      args: { path: "C:\\workspace\\fixture.txt", profile: undefined },
      decision: "allow",
      durationMs: 1,
      exitState: "success",
    });
    await expect(audit.verify(await audit.files())).resolves.toEqual({ valid: true, records: 1 });
    store.close();
  });

  it("detects tampering", async () => {
    const { audit, store } = await setup();
    await audit.append({
      correlationId: crypto.randomUUID(),
      subject: "test",
      deviceId: "device",
      tool: "read_file",
      args: {},
      decision: "allow",
      durationMs: 1,
      exitState: "success",
    });
    const active = (await audit.files()).at(-1);
    if (!active) throw new Error("active audit file missing");
    const content = await readFile(active, "utf8");
    await writeFile(active, content.replace("read_file", "write_file"), "utf8");
    await expect(audit.verify(await audit.files())).resolves.toMatchObject({ valid: false });
    store.close();
  });

  it("coalesces concurrent requests with the same idempotency key", async () => {
    const { audit, store, policy, auth } = await setup();
    const runtime = new ToolRuntime(policy, audit, store);
    let executions = 0;
    const invoke = () =>
      runtime.run({
        auth,
        tool: "write_file",
        scope: "filesystem:write",
        args: { path: "a" },
        idempotencyKey: "76db737a-b8bd-4b3a-9121-afafefee042f",
        handler: async () => {
          executions += 1;
          await new Promise((resolve) => setTimeout(resolve, 20));
          return { ok: true };
        },
      });
    const [first, second] = await Promise.all([invoke(), invoke()]);
    expect(executions).toBe(1);
    expect(first.structuredContent).toMatchObject({ replayed: false });
    expect(second.structuredContent).toMatchObject({ replayed: true });
    store.close();
  });

  it("fails closed on a durable idempotency claim with an unknown crash outcome", async () => {
    const { audit, store, policy, auth } = await setup();
    const key = "21477d6a-b652-485a-bb67-2c96e00e43a0";
    const args = { path: "a" };
    const argsHash = sha256(canonicalJson(args));
    expect(store.claimIdempotency(key, "client", "write_file", argsHash)).toBe(true);

    const restartedRuntime = new ToolRuntime(policy, audit, store);
    let executions = 0;
    const result = await restartedRuntime.run({
      auth,
      tool: "write_file",
      scope: "filesystem:write",
      args,
      idempotencyKey: key,
      handler: async () => {
        executions += 1;
        return { ok: true };
      },
    });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ code: "CONFLICT" });
    expect(executions).toBe(0);
    expect(store.clearIdempotencyClaim(key)).toBe(true);
    store.close();
  });
});
