import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Store } from "../../src/persistence/store.js";
import { isValidationCommand, ProcessRepeatGuard } from "../../src/policy/repeat-guard.js";
import type { SafePathResolver } from "../../src/tools/filesystem/safe-path.js";

describe("V3 original MCP pre-spawn validation no-repeat guard", () => {
  let root: string;
  let store: Store;
  let guard: ProcessRepeatGuard;
  let resolver: SafePathResolver;
  const evidence = {
    gate: "G012",
    operation: "monthly_settlement_test",
    errorCode: "W01_MISSING",
    candidateFiles: ["source.py"],
    stateFiles: ["runtime_state.json"],
  };

  beforeEach(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "radlina-v3-no-repeat-"));
    await mkdir(path.join(root, "db"));
    await writeFile(path.join(root, "source.py"), "print('first source')");
    await writeFile(path.join(root, "runtime_state.json"), '{"w01":false}');
    store = new Store(path.join(root, "db"));
    guard = new ProcessRepeatGuard(store);
    resolver = {
      resolve: async (input: string) => {
        const candidate = path.resolve(root, input);
        if (!candidate.startsWith(root + path.sep)) throw Error("INVALID_PATH");
        return candidate;
      },
    } as unknown as SafePathResolver;
  });

  afterEach(async () => {
    store.close();
    await rm(root, { recursive: true, force: true });
  });

  function claim(
    selected = evidence,
    subject = "authorized-owner",
    args: string[] = ["-m", "pytest", "-q"],
  ) {
    return guard.claim(subject, "owned-v3", "C:\\Python\\python.exe",
      args, root, undefined, selected, resolver);
  }

  it("claims once then blocks unchanged process regardless of a new MCP request key", async () => {
    await expect(claim()).resolves.toMatchObject({ claimed: true });
    await expect(claim()).rejects.toMatchObject({ code: "CONFLICT" });
    const rows = store.db.prepare("SELECT COUNT(*) AS n FROM process_repeat_claims").get() as { n: number };
    expect(rows.n).toBe(1);
  });

  it("ignores cosmetic renaming of operation and error code", async () => {
    await claim();
    await expect(claim({ ...evidence, operation: "another_name", errorCode: "DIFFERENT" }))
      .rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("rejects a renamed gate for an identical command and unchanged evidence", async () => {
    await claim();
    await expect(claim({ ...evidence, gate: "G015" }))
      .rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("permits one new run when the actual authoritative state file changes", async () => {
    await claim();
    await writeFile(path.join(root, "runtime_state.json"), '{"w01":true}');
    await expect(claim()).resolves.toMatchObject({ claimed: true });
    await expect(claim()).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("permits one new run after source candidate actually changes", async () => {
    await claim();
    await writeFile(path.join(root, "source.py"), "print('repaired')");
    await expect(claim()).resolves.toMatchObject({ claimed: true });
  });

  it("persists a denied repeat across Store restart", async () => {
    await claim();
    store.close();
    store = new Store(path.join(root, "db"));
    guard = new ProcessRepeatGuard(store);
    await expect(claim()).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("allows exactly one concurrent claim for the same command and state", async () => {
    const outcomes = await Promise.allSettled([claim(), claim(), claim()]);
    expect(outcomes.filter((x) => x.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((x) => x.status === "rejected")).toHaveLength(2);
    const rows = store.db.prepare("SELECT COUNT(*) AS n FROM process_repeat_claims").get() as { n: number };
    expect(rows.n).toBe(1);
  });

  it("isolates owner identities so no subject can claim another owner's receipt", async () => {
    await claim();
    await expect(claim(evidence, "independent-tenant")).resolves.toMatchObject({ claimed: true });
  });

  it("fails closed if state evidence is missing or malformed", async () => {
    await expect(claim({ ...evidence, stateFiles: [] }))
      .rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(claim({ ...evidence, stateFiles: ["missing.json"] })).rejects.toThrow();
  });

  it("narrowly identifies test commands without blocking normal process operations", () => {
    expect(isValidationCommand("python.exe", ["-m", "pytest", "-q"])).toBe(true);
    expect(isValidationCommand("docker.exe", ["exec", "backend", "python", "-m", "unittest"])).toBe(true);
    expect(isValidationCommand("npm.cmd", ["test"])).toBe(true);
    expect(isValidationCommand("go.exe", ["test", "./..."])).toBe(true);
    expect(isValidationCommand("python.exe", ["manage.py", "migrate"])).toBe(false);
    expect(isValidationCommand("docker.exe", ["ps", "--format", "table"])).toBe(false);
  });
});
