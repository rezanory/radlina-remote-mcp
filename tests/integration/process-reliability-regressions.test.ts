import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { Store } from "../../src/persistence/store.js";
import { PolicyEngine } from "../../src/policy/engine.js";
import { FilesystemService } from "../../src/tools/filesystem/service.js";
import { ProcessManager } from "../../src/tools/process/manager.js";
import { testConfig } from "../helpers/config.js";

const cleanup: string[] = [];
const windowsTest = process.platform === "win32" ? it : it.skip;

afterEach(async () => {
  for (const directory of cleanup.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(prefix: string) {
  const root = await mkdtemp(path.join(os.tmpdir(), prefix));
  cleanup.push(root);
  const config = testConfig(root);
  config.policy.maxSessions = 16;
  const profile = config.profiles["test"]!;
  profile.roots = ["C:\\"];
  profile.commands = [];
  profile.allowShell = true;
  profile.envAllowlist = ["PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC"];
  const store = new Store(config.storage.directory);
  const policy = new PolicyEngine(config, {
    killSwitch: () => false,
    emergencyReadOnly: () => false,
  });
  const processes = new ProcessManager(config, store, policy);
  const files = new FilesystemService(profile.roots, 1024 * 1024, path.join(root, ".trash"), false);
  return { root, profile, store, processes, files };
}

async function waitForExit(store: Store, id: string): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const row = store.db.prepare("SELECT status FROM process_sessions WHERE id=?").get(id) as {
      status: string;
    };
    if (row.status !== "running") return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("process session did not exit before timeout");
}

describe("ProcessManager production regressions", () => {
  windowsTest(
    "resolves git.exe and git through PATH instead of the service working directory",
    async () => {
      const { root, profile, store, processes, files } = await fixture("radlina-path-regression-");
      try {
        const git = execFileSync("where.exe", ["git.exe"], { encoding: "utf8", windowsHide: true })
          .split(/\r?\n/u)
          .find(Boolean);
        expect(git).toBeTruthy();

        for (const executable of ["git.exe", "git"]) {
          const started = (await processes.start("owner", "test", profile, files.resolver, {
            executable,
            args: ["--version"],
            cwd: root,
          })) as { sessionId: string };
          await waitForExit(store, started.sessionId);
          const result = (await processes.readOutput(started.sessionId, "owner")) as {
            output: string;
            exitCode: number | null;
          };
          expect(result.exitCode).toBe(0);
          expect(result.output).toContain("git version");
        }
      } finally {
        processes.shutdown();
        store.close();
      }
    },
  );

  windowsTest(
    "returns a typed NOT_FOUND error when a requested executable cannot be resolved",
    async () => {
      const { root, profile, store, processes, files } = await fixture("radlina-missing-exe-");
      try {
        await expect(
          processes.start("owner", "test", profile, files.resolver, {
            executable: "radlina-definitely-not-installed-93f474.exe",
            args: [],
            cwd: root,
          }),
        ).rejects.toMatchObject({ code: "NOT_FOUND" });
      } finally {
        processes.shutdown();
        store.close();
      }
    },
  );

  windowsTest("quiesces finalizers before Store shutdown while a child is still live", async () => {
    const { root, profile, store, processes, files } = await fixture("radlina-shutdown-race-");
    await processes.start("owner", "test", profile, files.resolver, {
      executable: process.execPath,
      args: ["-e", "setTimeout(() => {}, 250)"],
      cwd: root,
    });
    processes.shutdown();
    store.close();
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(store.isOpen()).toBe(false);
    await expect(
      processes.start("owner", "test", profile, files.resolver, {
        executable: process.execPath,
        args: ["--version"],
        cwd: root,
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  windowsTest("treats taskkill TOCTOU exit as an idempotent successful termination", async () => {
    const { store, processes } = await fixture("radlina-terminate-race-");
    try {
      const pid = 2_147_483_000;
      store.db
        .prepare(
          "INSERT INTO process_sessions(id,subject,profile,pid,executable,args_json,output_path,status,started_at,start_identity) VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "11111111-1111-4111-8111-111111111111",
          "owner",
          "test",
          pid,
          process.execPath,
          "{}",
          "NUL",
          "running",
          Date.now(),
          "verified-before-race",
        );

      const internals = processes as unknown as {
        processIdentity: (selectedPid: number) => Promise<string | undefined>;
        processExists: (selectedPid: number) => Promise<boolean>;
      };
      let identityCalls = 0;
      internals.processIdentity = async () => {
        identityCalls += 1;
        return identityCalls === 1 ? "verified-before-race" : undefined;
      };
      internals.processExists = async () => false;

      const result = (await processes.terminate(
        "11111111-1111-4111-8111-111111111111",
        "owner",
        false,
      )) as { terminated: boolean; alreadyExited: boolean };
      expect(result).toMatchObject({ terminated: true, alreadyExited: true });
      const row = store.db
        .prepare("SELECT status FROM process_sessions WHERE id=?")
        .get("11111111-1111-4111-8111-111111111111") as { status: string };
      expect(row.status).toBe("terminated");
    } finally {
      processes.shutdown();
      store.close();
    }
  });
});
